"""
EN: Flow DNA — per-process traffic metabolism with drift detection.
    Every application has a network metabolism: browsers make many small
    bidirectional flows, backup agents do rare large uploads, chat apps
    heartbeat. A compromised process does not change its NAME — it
    changes its METABOLISM. Firefox that stops browsing and starts one
    sustained upload is not Firefox anymore, whatever the binary says.

    The DNA profile per process:
      * flow count / hour and bytes ratio out:in
      * mean burst size + inter-flow rhythm (coefficient of variation)
      * distinct-destination entropy — browsers spray, exfil funnels

    Learning: first BASELINE_WINDOW of traffic builds the profile silently.
    Then drift scoring compares the live window against the baseline with
    per-feature z-scores; combined drift past threshold emits FLOW_DRIFT.
    Pure statistics, no ML dependency, every number explainable — the
    alert literally says "rhythm collapsed 4.2x, out:in ratio inverted".

    Honesty: metabolism legitimately changes (software update, new user
    habit) — drift is a question, not a verdict, and re-baselining is one
    click. Score demands MULTIPLE drifted features so single-habit changes
    (watching a video = bigger downloads) do not fire.

FR: ADN de flux — métabolisme réseau par processus avec détection de
    dérive. Un processus compromis ne change pas de NOM, il change de
    MÉTABOLISME. Profil par processus : densité de flux, ratio out:in,
    rythme, entropie des destinations. Apprentissage silencieux pendant
    la fenêtre baseline, puis z-scores par feature — l'alerte dit
    littéralement « rythme effondré 4,2x, ratio inversé ». La dérive est
    une question, pas un verdict ; re-baseline en un clic.
"""

from __future__ import annotations

import math
import threading
import time

MIN_BASELINE_FLOWS = 30          # EN: statistical floor / FR: plancher statistique
DRIFT_THRESHOLD = 2              # EN: drifted features needed / FR: features requises
Z_TRIGGER = 3.0                  # EN: z-score per feature / FR: z-score par feature
MAX_PROCS = 2000


def _cv(values: list[float]) -> float:
    """EN: Coefficient of variation. FR: coefficient de variation."""
    if len(values) < 2:
        return 0.0
    m = sum(values) / len(values)
    if m == 0:
        return 0.0
    var = sum((v - m) ** 2 for v in values) / len(values)
    return math.sqrt(var) / m


def _entropy(keys) -> float:  # noqa: ANN001
    """EN: Shannon entropy over a list of keys. FR: entropie de Shannon."""
    if not keys:
        return 0.0
    freq: dict = {}
    for k in keys:
        freq[k] = freq.get(k, 0) + 1
    n = len(keys)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


class ProcDNA:
    """EN: Rolling metabolism profile. FR: profil de métabolisme glissant."""

    def __init__(self) -> None:
        self.flows = 0
        self.bytes_out = 0
        self.bytes_in = 0
        self.sizes: list[float] = []
        self.gaps: list[float] = []
        self.dests: list[str] = []
        self.first_ts: float | None = None
        self.last_ts: float | None = None

    def observe(self, direction: str, size: int, dest: str, now: float) -> None:
        self.flows += 1
        if direction == "out":
            self.bytes_out += size
        else:
            self.bytes_in += size
        self.sizes.append(float(size))
        self.dests.append(dest)
        if self.last_ts is not None and now > self.last_ts:
            self.gaps.append(now - self.last_ts)
        if self.first_ts is None:
            self.first_ts = now
        self.last_ts = now
        for buf, cap in ((self.sizes, 500), (self.gaps, 500), (self.dests, 500)):
            if len(buf) > cap:
                del buf[:cap // 2]

    def profile(self) -> dict:
        ratio = self.bytes_out / max(1, self.bytes_in)
        return {
            "mean_size": sum(self.sizes) / max(1, len(self.sizes)),
            "rhythm_cv": _cv(self.gaps),
            "ratio": ratio,
            "log_ratio": math.log10(max(1e-3, ratio)),
            "dest_entropy": _entropy(self.dests[-200:]),
            "flows": self.flows,
        }


def drift_score(baseline: dict, live: dict) -> tuple[int, list[str]]:
    """EN: Count features drifted past z-trigger. Pure. Returns (n, reasons).
    FR: compter les features dérivées. Pur. Renvoie (n, raisons)."""
    drifted: list[str] = []
    # EN: mean size jump / collapse / FR: saut/effondrement de taille moyenne
    if baseline["mean_size"] > 0:
        ratio = live["mean_size"] / baseline["mean_size"]
        if ratio > 4 or ratio < 0.25:
            drifted.append(f"mean burst size shifted {ratio:.1f}x "
                           f"({baseline['mean_size']:.0f}B -> {live['mean_size']:.0f}B)")
    # EN: rhythm collapse/chaos / FR: effondrement/chaos du rythme
    if baseline["rhythm_cv"] > 0.1:
        r = live["rhythm_cv"] / baseline["rhythm_cv"]
        if r > 3 or r < 0.33:
            drifted.append(f"rhythm changed {r:.1f}x (cv {baseline['rhythm_cv']:.2f} -> {live['rhythm_cv']:.2f})")
    # EN: out:in ratio inversion / FR: inversion du ratio
    dr = abs(live["log_ratio"] - baseline["log_ratio"])
    if dr > 1.0:                                  # EN: 10x swing / FR: bascule x10
        drifted.append(f"out:in ratio inverted ({baseline['ratio']:.2f} -> {live['ratio']:.2f})")
    # EN: destination entropy collapse = funneling / FR: effondrement = tunneling
    de = baseline["dest_entropy"] - live["dest_entropy"]
    if de > 2.0 and baseline["dest_entropy"] > 2:
        drifted.append(f"destinations funneled (entropy {baseline['dest_entropy']:.1f} -> {live['dest_entropy']:.1f} bits)")
    return len(drifted), drifted


class FlowDNA:
    """EN: Learns baselines, scores drift. Thread-safe.
    FR: apprend les baselines, note la dérive. Thread-safe."""

    def __init__(self) -> None:
        self.enabled = True
        self._lock = threading.Lock()
        self._baseline: dict[str, dict] = {}
        self._live: dict[str, ProcDNA] = {}
        self._baseline_live: dict[str, ProcDNA] = {}
        self._alerted: dict[str, float] = {}
        self._dismissed: set[str] = set()

    def observe(self, process_name: str, direction: str, size: int,
                dest: str, now: float | None = None) -> dict | None:
        """EN: Feed one flow. Returns FLOW_DRIFT alert on multi-feature drift.
        FR: alimenter un flux. Alerte FLOW_DRIFT si dérive multi-feature."""
        if not self.enabled or not process_name:
            return None
        now = time.time() if now is None else now
        proc = process_name.lower()
        with self._lock:
            if len(self._live) > MAX_PROCS and proc not in self._live:
                return None
            base_dna = self._baseline_live.setdefault(proc, ProcDNA())
            base_dna.observe(direction, size, dest, now)
            if proc not in self._baseline and base_dna.flows >= MIN_BASELINE_FLOWS:
                self._baseline[proc] = base_dna.profile()
                self._live.pop(proc, None)         # EN: learning is not evidence / FR: l'apprentissage n'est pas une preuve
                return None
            if proc not in self._baseline:
                return None
            live_dna = self._live.setdefault(proc, ProcDNA())
            live_dna.observe(direction, size, dest, now)
            if live_dna.flows < MIN_BASELINE_FLOWS or proc in self._dismissed:
                return None
            # EN: non-overlapping windows — the window is consumed at every
            #     scoring boundary whether or not drift fired, so a slow
            #     drift cannot dilute itself across an ever-growing window.
            # FR: fenêtres non-recouvrantes — consommée à chaque borne, qu'il
            #     y ait dérive ou non : une dérive lente ne peut pas se diluer.
            profile = live_dna.profile()
            self._live[proc] = ProcDNA()
            n, reasons = drift_score(self._baseline[proc], profile)
            if n < DRIFT_THRESHOLD:
                return None
            if proc in self._alerted and now - self._alerted[proc] < 7200:
                return None
            self._alerted[proc] = now
        return {
            "type": "FLOW_DRIFT",
            "severity": "warning",
            "message": f"{process_name} changed its network metabolism: {'; '.join(reasons)} — "
                       f"the binary is the same but the behavior is not. Legit update or compromise? "
                       f"Re-baseline to dismiss.",
            "details": {"process": process_name, "features_drifted": n,
                        "reasons": reasons},
        }

    def rebaseline(self, process_name: str) -> bool:
        proc = process_name.lower()
        with self._lock:
            dna = self._baseline_live.get(proc)
            if not dna:
                return False
            self._baseline[proc] = dna.profile()
            self._live.pop(proc, None)
            self._dismissed.discard(proc)
            return True

    def dismiss(self, process_name: str) -> None:
        with self._lock:
            self._dismissed.add(process_name.lower())

    def status(self) -> dict:
        with self._lock:
            return {"enabled": self.enabled,
                    "baselined": len(self._baseline),
                    "learning": len(self._baseline_live) - len(self._baseline),
                    "tracking": len(self._live)}
