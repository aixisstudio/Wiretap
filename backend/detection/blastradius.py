"""
EN: Blast radius — automated impact assessment at alert time.
    When a critical alert fires, the only question that matters is:
    "if this was malicious, what did it touch?" Today that answer takes
    a forensic expert hours. Wiretap computes it in milliseconds, at the
    moment the alert fires, and attaches it to the alert itself:

      * NETWORK FOOTPRINT — destinations this process contacted in the
        analysis window, bytes in/out per destination, first/last seen
      * AI EXPOSURE — which AI providers received traffic from it
      * SECRET ACCESS — count of secret shapes in its environment
        (shapes, never values — same discipline as secretwatch)
      * PERSISTENCE — does it appear on the auto-start surface?
      * LINEAGE — what spawned it, what it spawned
      * FILE FOOTPRINT — best-effort open-files snapshot (platform
        dependent, zero privileges: /proc on Linux, lsof fallback)

    The assessment is EVIDENCE, not verdict: it answers "what is the
    worst this could have done" so the user triages in seconds instead
    of hours. Every field is labeled with its confidence and source.

FR: Rayon de blast — évaluation d'impact automatisée à l'alerte. Quand
    une alerte critique tire, la seule question qui compte : « si
    c'était malveillant, qu'a-t-il touché ? » Aujourd'hui ça prend des
    heures d'expertise forensique. Wiretap le calcule en millisecondes
    au moment de l'alerte : empreinte réseau par destination, exposition
    IA, accès secrets (formes, jamais valeurs), persistance, lignée,
    fichiers ouverts best-effort. Chaque champ est labellé avec sa
    source et sa confiance. Évidence, pas verdict.
"""

from __future__ import annotations

import os
import platform
import subprocess
import time
from pathlib import Path

WINDOW_S = 3600.0              # EN: default analysis window / FR: fenêtre d'analyse


def open_files_for_pid(pid: int) -> dict:
    """EN: Best-effort open-files snapshot. /proc on Linux, lsof elsewhere.
        Returns {"files": [...], "source": "procfs|lsof|none", "confidence": ...}
    FR: snapshot best-effort des fichiers ouverts."""
    if pid <= 0:
        return {"files": [], "source": "none", "confidence": "none"}
    if platform.system() == "Linux":
        fd_dir = Path(f"/proc/{pid}/fd")
        try:
            files = sorted({os.readlink(fd_dir / fd) for fd in os.listdir(fd_dir)
                            if not os.readlink(fd_dir / fd).startswith(("socket", "pipe", "anon"))})
            return {"files": files[:100], "source": "procfs", "confidence": "high"}
        except (OSError, FileNotFoundError):
            return {"files": [], "source": "procfs", "confidence": "process-gone-or-denied"}
    try:
        out = subprocess.run(["lsof", "-p", str(pid), "-Fn"],
                             capture_output=True, text=True, timeout=5)
        files = [ln[1:] for ln in out.stdout.splitlines()
                 if ln.startswith("n") and ln[1:].startswith("/")]
        interesting = [f for f in files if not f.startswith(
            ("/System/", "/usr/lib", "/dev/", "/private/var/db"))]
        return {"files": sorted(set(interesting))[:100], "source": "lsof",
                "confidence": "medium" if files else "low"}
    except (OSError, subprocess.TimeoutExpired):
        return {"files": [], "source": "none", "confidence": "none"}


class BlastRadius:
    """EN: Computes impact assessments from live data sources. The data
        sources are injected (db queries, secretwatch, perswatch) so this
        stays pure and testable.
    FR: calcule les évaluations d'impact depuis des sources injectées —
        pur et testable."""

    def __init__(self) -> None:
        self._assessments: dict[str, dict] = {}      # EN: alert_id -> assessment / FR: alerte -> évaluation
        self._sources: dict = {}

    def register_sources(self, **sources) -> None:  # noqa: ANN003
        """EN: inject callables: network_footprint(process) -> list,
            ai_exposure(process) -> list, secret_count(process) -> int,
            persistence_hit(process_or_path) -> dict|None, lineage(pid) -> list
        FR: injecter les sources de données."""
        self._sources.update(sources)

    def assess(self, process_name: str, pid: int = 0,
               target_path: str = "", now: float | None = None) -> dict:
        """EN: Compute the worst-case footprint. Pure assembly of injected
            sources + filesystem probes. All failures degrade to labeled
            "unknown", never to silence.
        FR: calculer l'empreinte pire-cas. Tout échec devient « unknown »
            labellé, jamais du silence."""
        now = time.time() if now is None else now
        assessment: dict = {
            "process": process_name, "pid": pid, "computed_at": now,
            "window_s": WINDOW_S, "sections": {},
        }
        net = self._safe("network_footprint", process_name)
        assessment["sections"]["network"] = {
            "value": net if net is not None else "unknown",
            "destinations": len(net) if net else 0,
            "source": "flow-db", "confidence": "high" if net is not None else "unavailable",
        }
        ai = self._safe("ai_exposure", process_name)
        assessment["sections"]["ai_exposure"] = {
            "value": ai if ai is not None else "unknown",
            "providers": len(ai) if ai else 0,
            "source": "aiwatch", "confidence": "high" if ai is not None else "unavailable",
        }
        secrets = self._safe("secret_count", process_name, pid)
        assessment["sections"]["secret_access"] = {
            "count": secrets if secrets is not None else "unknown",
            "note": "shapes only — values never inspected",
            "source": "secretwatch", "confidence": "high" if secrets is not None else "unavailable",
        }
        pers = self._safe("persistence_hit", process_name, target_path)
        assessment["sections"]["persistence"] = {
            "auto_start": bool(pers), "entries": pers or [],
            "source": "perswatch", "confidence": "high",
        }
        lin = self._safe("lineage", pid)
        assessment["sections"]["lineage"] = {
            "chain": lin if lin is not None else "unknown",
            "source": "lineage", "confidence": "medium" if lin else "unavailable",
        }
        files = open_files_for_pid(pid) if pid else {"files": [], "source": "none", "confidence": "no-pid"}
        assessment["sections"]["file_footprint"] = {
            "files": files["files"], "count": len(files["files"]),
            "source": files["source"], "confidence": files["confidence"],
        }
        # EN: worst-case summary — the triage sentence / FR: phrase de triage
        worst = []
        if net:
            worst.append(f"talked to {len(net)} destinations")
        if ai:
            worst.append(f"reached AI providers: {', '.join(a['service'] if isinstance(a, dict) else str(a) for a in ai[:5])}")
        if secrets:
            worst.append(f"had {secrets} secret shape(s) in reach")
        if pers:
            worst.append("SURVIVES REBOOT via auto-start")
        if files["files"]:
            worst.append(f"held {len(files['files'])} files open")
        assessment["worst_case"] = ("; ".join(worst) if worst else
                                    "no measurable footprint — either benign or already cleaned up")
        return assessment

    def _safe(self, source: str, *args):  # noqa: ANN202
        fn = self._sources.get(source)
        if not fn:
            return None
        try:
            return fn(*args)
        except Exception:
            return None

    def attach(self, alert_id: str, assessment: dict) -> None:
        self._assessments[alert_id] = assessment
        if len(self._assessments) > 500:
            for k in list(self._assessments)[:-250]:
                del self._assessments[k]

    def get(self, alert_id: str) -> dict | None:
        return self._assessments.get(alert_id)
