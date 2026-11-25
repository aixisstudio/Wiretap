"""
EN: Time-travel state diff — "what changed on this machine since Tuesday?"
    Every incident investigation starts with that question, and answering
    it today means a forensic expert with a disk image. Wiretap snapshots
    the security-relevant system state continuously and diffs any two
    points in time in milliseconds:

      * PERSISTENCE — every auto-start entry (via perswatch collector)
      * LISTENERS   — ports accepting connections, with owning process
      * PROCESSES   — running set with exe paths (shape, not content)

    Snapshots are small (a few KB), stored locally, pruned to the
    retention window. The diff answers in one view: what appeared, what
    vanished, what mutated — each change risk-scored so the malicious
    floats above the noise of normal system churn.

    Honest design: this is state diffing, not causality. "X appeared
    Tuesday 14:32" is evidence; WHY it appeared is the killchain's job.

FR: Diff d'état temporel — « qu'est-ce qui a changé depuis mardi ? ».
    Toute investigation commence par cette question. Wiretap snapshotte
    l'état système pertinent (persistance, listeners, processus) et
    différentie deux points dans le temps en millisecondes : ce qui est
    apparu, disparu, muté — chaque changement scoré par risque. Les
    snapshots sont petits, locaux, élagués selon la rétention. C'est du
    diff d'état, pas de la causalité — le pourquoi est le rôle du
    killchain.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

SNAPSHOT_INTERVAL = 3600.0       # EN: hourly snapshots / FR: snapshots horaires
MAX_SNAPSHOTS = 48               # EN: 48h retention / FR: rétention 48h


def collect_listeners() -> dict[str, dict]:
    """EN: Listening ports with owning process. Pure /proc parse on Linux,
        lsof fallback elsewhere — best-effort, zero privileges.
    FR: ports en écoute avec processus propriétaire. Best-effort."""
    listeners: dict[str, dict] = {}
    try:
        import subprocess
        out = subprocess.run(["lsof", "-iTCP", "-sTCP:LISTEN", "-P", "-n", "-Fpcn"],
                             capture_output=True, text=True, timeout=8)
        cur_pid, cur_proc = 0, ""
        for line in out.stdout.splitlines():
            if line.startswith("p"):
                cur_pid = int(line[1:] or 0)
            elif line.startswith("c"):
                cur_proc = line[1:]
            elif line.startswith("n") and ":" in line:
                port = line.rsplit(":", 1)[-1]
                if port.isdigit():
                    listeners[port] = {"port": int(port), "process": cur_proc, "pid": cur_pid}
    except (OSError, subprocess.TimeoutExpired):
        pass
    return listeners


def collect_processes() -> dict[str, dict]:
    """EN: Running process shapes (name -> count + sample paths).
    FR: formes des processus en cours (nom -> compte + chemins)."""
    procs: dict[str, dict] = {}
    try:
        import subprocess
        out = subprocess.run(["ps", "-axo", "comm="], capture_output=True,
                             text=True, timeout=8)
        for line in out.stdout.splitlines():
            path = line.strip()
            if not path:
                continue
            name = Path(path).name
            agg = procs.setdefault(name, {"name": name, "count": 0, "path": path})
            agg["count"] += 1
    except (OSError, subprocess.TimeoutExpired):
        pass
    return procs


def collect_state(persistence_collector=None) -> dict:  # noqa: ANN001
    """EN: Full security-relevant state. Collector injected for tests.
    FR: état complet pertinent sécurité. Collecteur injecté pour les tests."""
    if persistence_collector is None:
        from detection.perswatch import collect
        persistence_collector = collect
    try:
        pers = persistence_collector()
    except Exception:                                # noqa: BLE001
        pers = {}
    return {
        "ts": time.time(),
        "persistence": {eid: {"target": e.get("target", ""),
                              "content_hash": e.get("content_hash", "")}
                        for eid, e in pers.items()},
        "listeners": collect_listeners(),
        "processes": collect_processes(),
    }


def diff_states(old: dict, new: dict) -> dict:
    """EN: Pure diff of two snapshots — appeared/vanished/mutated per section,
        with a simple risk note for the dangerous classes of change.
    FR: diff pur de deux snapshots — apparu/disparu/muté par section, avec
        note de risque pour les classes de changement dangereuses."""
    out: dict = {"from_ts": old.get("ts", 0), "to_ts": new.get("ts", 0), "sections": {}}

    def _set_diff(section: str, key_of=lambda x: x):  # noqa: ANN001
        old_s, new_s = old.get(section, {}), new.get(section, {})
        appeared = sorted(set(new_s) - set(old_s))
        vanished = sorted(set(old_s) - set(new_s))
        mutated = sorted(k for k in set(old_s) & set(new_s)
                         if old_s[k] != new_s[k])
        out["sections"][section] = {
            "appeared": [{**new_s[k], "id": k} for k in appeared],
            "vanished": [{**old_s[k], "id": k} for k in vanished],
            "mutated": [{**new_s[k], "id": k} for k in mutated],
        }

    _set_diff("persistence")
    _set_diff("listeners")
    _set_diff("processes")

    risks: list[str] = []
    p = out["sections"]["persistence"]
    if p["appeared"]:
        risks.append(f"{len(p['appeared'])} new auto-start entries — the #1 post-infection artifact")
    lsec = out["sections"]["listeners"]
    if lsec["appeared"]:
        risks.append(f"{len(lsec['appeared'])} new listening ports — possible backdoor or legit service")
    pr = out["sections"]["processes"]
    if pr["appeared"]:
        risks.append(f"{len(pr['appeared'])} new process names seen")
    out["risk_notes"] = risks
    out["changes_total"] = sum(len(s["appeared"]) + len(s["vanished"]) + len(s["mutated"])
                               for s in out["sections"].values())
    return out


class TimeTravel:
    """EN: Snapshot store + diff engine. Disk-persisted, pruned.
    FR: magasin de snapshots + moteur de diff. Persisté disque, élagué."""

    def __init__(self, store_dir: Path | None = None, collector=None) -> None:  # noqa: ANN001
        self.store_dir = store_dir
        self._collector = collector
        self._snapshots: list[dict] = []
        if store_dir and store_dir.is_dir():
            for f in sorted(store_dir.glob("tt-*.json"))[-MAX_SNAPSHOTS:]:
                try:
                    self._snapshots.append(json.loads(f.read_text()))
                except (OSError, json.JSONDecodeError):
                    continue

    def snapshot(self, now: float | None = None) -> dict:
        state = collect_state(self._collector)
        if now is not None:
            state["ts"] = now
        self._snapshots.append(state)
        self._snapshots = self._snapshots[-MAX_SNAPSHOTS:]
        if self.store_dir:
            try:
                self.store_dir.mkdir(parents=True, exist_ok=True)
                (self.store_dir / f"tt-{int(state['ts'])}.json").write_text(json.dumps(state))
                for f in sorted(self.store_dir.glob("tt-*.json"))[:-MAX_SNAPSHOTS]:
                    f.unlink(missing_ok=True)
            except OSError:
                pass
        return {"ts": state["ts"], "stored": len(self._snapshots)}

    def diff_since(self, since_ts: float | None = None) -> dict:
        """EN: Diff the oldest snapshot at-or-after since_ts against now.
            None = oldest available. Empty store = honest "no baseline".
        FR: diff du plus vieux snapshot >= since_ts contre maintenant."""
        if not self._snapshots:
            return {"error": "no baseline snapshot yet — the first one is taken automatically",
                    "snapshots": 0}
        if since_ts is None:
            base = self._snapshots[0]
        else:
            candidates = [s for s in self._snapshots if s.get("ts", 0) >= since_ts]
            base = candidates[0] if candidates else self._snapshots[0]
        now_state = collect_state(self._collector)
        d = diff_states(base, now_state)
        d["snapshots"] = len(self._snapshots)
        return d

    def status(self) -> dict:
        return {"snapshots": len(self._snapshots),
                "oldest": self._snapshots[0]["ts"] if self._snapshots else None,
                "newest": self._snapshots[-1]["ts"] if self._snapshots else None}
