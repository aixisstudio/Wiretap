"""
EN: Presence-correlated exfiltration detection — the signal nobody uses.
    Every security tool on earth asks "what left the machine?". None asks
    "was a human even there when it left?". Yet that single bit splits
    the world in two:

      * 5 MB to an AI provider WHILE you type     = you, using your tools
      * 5 MB to the same provider while you are in a meeting, screen
        locked, hands off for an hour                          = something
        else is acting in your name

    Malware, rogue agents and compromised extensions share one structural
    weakness: they do not need you. Legitimate interactive tools almost
    always fire within seconds of your input.

    This module reads OS input-idle time WITHOUT privileges:
      macOS   IOHIDSystem HIDIdleTime via ioreg (nanoseconds)
      Windows GetLastInputInfo via ctypes user32
      Linux   xprintidle when present, X11 idle otherwise undetectable
              (honest degradation: verdict becomes "unknown", never guessed)

    The correlator then grades outbound flows:
      idle < 30 s      -> "interactive"   (user-driven, baseline noise)
      idle 30-300 s    -> "ambient"       (weak signal)
      idle > 300 s     -> "unattended"    (strong exfil precondition)

    Design honesty: presence is evidence, not verdict — backup agents and
    cloud sync also fire unattended. The alert always says exactly why it
    fired and asks the user to confirm or dismiss.

FR: Détection d'exfiltration corrélée à la présence — le signal que
    personne n'utilise. Tous les outils demandent « qu'est-ce qui sort ? »,
    aucun ne demande « y avait-il un humain devant la machine ? ». Pourtant
    ce bit unique sépare le monde en deux : 5 Mo vers une API IA pendant
    que tu tapes = toi ; les mêmes 5 Mo pendant ta réunion = autre chose
    agit en ton nom. Malwares, agents voyous et extensions compromises
    partagent une faiblesse structurelle : ils n'ont pas besoin de toi.
    Lecture de l'idle time SANS privilèges (IOHID macOS, GetLastInputInfo
    Windows, xprintidle Linux), dégradation honnête = « unknown ».
"""

from __future__ import annotations

import ctypes
import re
import subprocess
import threading
import time

INTERACTIVE_S = 30.0
AMBIENT_S = 300.0


def _idle_macos() -> float | None:
    try:
        out = subprocess.run(
            ["ioreg", "-c", "IOHIDSystem"],
            capture_output=True, text=True, timeout=4).stdout
        m = re.search(r"HIDIdleTime\"\s*=\s*(\d+)", out)
        if m:
            return int(m.group(1)) / 1e9          # EN: nanoseconds / FR: nanosecondes
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def _idle_windows() -> float | None:
    try:
        class LASTINPUTINFO(ctypes.Structure):
            _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]
        lii = LASTINPUTINFO()
        lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
        if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii)):
            millis = ctypes.windll.kernel32.GetTickCount() - lii.dwTime
            return max(0.0, millis / 1000.0)
    except (OSError, AttributeError, ValueError):
        pass
    return None


def _idle_linux() -> float | None:
    try:
        out = subprocess.run(["xprintidle"], capture_output=True,
                             text=True, timeout=3).stdout.strip()
        if out.isdigit():
            return int(out) / 1000.0
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def idle_seconds(sysname: str) -> float | None:
    """EN: Seconds since the last human input, None when undetectable.
    FR: secondes depuis la dernière entrée humaine, None si indétectable."""
    if sysname == "Darwin":
        return _idle_macos()
    if sysname == "Windows":
        return _idle_windows()
    if sysname == "Linux":
        return _idle_linux()
    return None


def classify(idle: float | None) -> str:
    """EN: Presence class. FR: classe de présence."""
    if idle is None:
        return "unknown"
    if idle < INTERACTIVE_S:
        return "interactive"
    if idle < AMBIENT_S:
        return "ambient"
    return "unattended"


class PresenceWatch:
    """EN: Correlator — grades sensitive outbound events with presence
    evidence and emits UNATTENDED_EXFIL alerts (deduped per process).
    FR: corrélateur — note les événements sortants sensibles avec la preuve
    de présence et émet des alertes UNATTENDED_EXFIL dédupliquées."""

    def __init__(self, sysname: str, idle_probe=idle_seconds) -> None:
        self.sysname = sysname
        self._probe = idle_probe
        self.enabled = True
        self._lock = threading.Lock()
        self._alerted: dict[str, float] = {}
        self._stats = {"interactive": 0, "ambient": 0, "unattended": 0, "unknown": 0}

    def grade(self, process_name: str, dest_desc: str,
              bytes_out: int, now: float | None = None) -> dict | None:
        """EN: Grade one sensitive outbound event. Returns an alert dict
        when the machine is unattended, else None (but stats accumulate).
        FR: noter un événement sortant sensible. Alerte si machine
        inoccupée, sinon None (les stats s'accumulent quand même)."""
        if not self.enabled:
            return None
        now = time.time() if now is None else now
        idle = self._probe(self.sysname)
        cls = classify(idle)
        with self._lock:
            self._stats[cls] += 1
        if cls != "unattended":
            return None
        key = process_name.lower()
        with self._lock:
            if key in self._alerted and now - self._alerted[key] < 3600:
                return None
            self._alerted[key] = now
        mb = bytes_out / (1024 * 1024)
        idle_min = (idle or 0) / 60
        return {
            "type": "UNATTENDED_EXFIL",
            "severity": "critical" if mb >= 1 else "warning",
            "message": f"{process_name} sent {mb:.1f} MB to {dest_desc} while you were away "
                       f"({idle_min:.0f} min without input) — legitimate tools fire when you type, "
                       f"this did not. Presence is evidence, not verdict: confirm or dismiss.",
            "details": {"process": process_name, "dest": dest_desc,
                        "bytes_out": bytes_out, "idle_seconds": idle,
                        "presence": cls},
        }

    def status(self) -> dict:
        idle = self._probe(self.sysname)
        with self._lock:
            return {"enabled": self.enabled,
                    "current_idle_s": idle,
                    "presence": classify(idle),
                    "flow_classes": dict(self._stats)}
