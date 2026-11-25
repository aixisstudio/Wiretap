"""
EN: Ransomware canaries + honeyports — two cheap tripwires that catch what
    signatures miss.

    CANARIES: small files planted in high-value user directories
    (Documents/Desktop/Pictures...). Nothing legitimate ever touches a
    file named `.wiretap_canary_*` — a modification or deletion means a
    mass-encryption/ransomware pass is in progress. Detection is by
    content hash on a slow poll (30 s) — no filesystem events API needed,
    pure stdlib, cross-platform.

    HONEYPORTS: TCP listeners on ports nobody should ever connect to on a
    workstation (telnet 23, SMB 445, RDP 3389, VNC 5900, SSH 22 when the
    machine doesn't serve it). ANY connection = scanning or lateral
    movement inside the LAN. Listeners answer nothing and close — they
    exist only to be touched.

    Both are opt-in-ish but safe-by-default: read-only canaries + passive
    listeners, no mitigation side effects.

FR: Canaris anti-ransomware + honeyports — deux pièges simples qui
    attrapent ce que les signatures ratent. Les canaris (fichiers plantés,
    hash surveillé toutes les 30 s) détectent le chiffrement de masse ;
    les honeyports (écoutes passives sur 23/445/3389/5900/22) détectent
    scans et mouvements latéraux — toute connexion est suspecte par
    construction. Stdlib pur, cross-plateforme, sans effet de bord.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import threading
from pathlib import Path

logger = logging.getLogger("wiretap.canary")

CANARY_NAME = ".wiretap_canary_do_not_touch.txt"
CANARY_CONTENT = (
    "WIRETAP CANARY — this file detects ransomware. Do not modify or delete.\n"
    "Everything legitimate ignores it; encryption malware does not.\n"
)
CANARY_DIRS = ("Documents", "Desktop", "Pictures", "Downloads")
HONEY_PORTS = (23, 445, 3389, 5900)      # EN: 22/ssh optional (often real) / FR: 22 optionnel
POLL_S = 30.0


class CanaryWatch:
    """EN: Plants canaries and polls their hashes. Emits alert dicts via a
    callback set by main. / FR: plante les canaris et surveille leurs hash."""

    def __init__(self, home: Path | None = None) -> None:
        self.home = home or Path.home()
        self.enabled = True
        self._canaries: dict[Path, str] = {}      # EN: path -> sha256 / FR: chemin -> sha256
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.on_alert = None                       # EN: callable(dict) / FR: callback

    def _emit(self, alert: dict) -> None:
        if self.on_alert:
            try:
                self.on_alert(alert)
            except Exception as e:                # noqa: BLE001
                logger.debug("canary emit: %s", e)

    @staticmethod
    def _hash(path: Path) -> str | None:
        try:
            return hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            return None

    def plant(self) -> list[str]:
        """EN: Drop canaries where missing, refresh the hash table.
        FR: dépose les canaris manquants, rafraîchit la table de hash."""
        planted = []
        for d in CANARY_DIRS:
            target = self.home / d
            if not target.is_dir():
                continue
            c = target / CANARY_NAME
            try:
                if not c.exists():
                    c.write_text(CANARY_CONTENT)
                    planted.append(str(c))
                h = self._hash(c)
                if h:
                    self._canaries[c] = h
            except OSError:
                continue
        return planted

    def check_once(self) -> list[dict]:
        """EN: One verification pass — returns alerts for touched canaries.
        FR: une passe de vérification — alertes pour canaris touchés."""
        alerts = []
        for path, expected in list(self._canaries.items()):
            current = self._hash(path)
            if current is None:
                alerts.append({
                    "type": "RANSOMWARE_CANARY",
                    "severity": "critical",
                    "message": f"Canary file DELETED: {path.name} in {path.parent.name} — "
                               f"mass file destruction/encryption pattern, check for ransomware NOW",
                    "details": {"path": str(path), "event": "deleted"},
                })
                del self._canaries[path]
            elif current != expected:
                alerts.append({
                    "type": "RANSOMWARE_CANARY",
                    "severity": "critical",
                    "message": f"Canary file MODIFIED: {path.name} in {path.parent.name} — "
                               f"nothing legitimate ever writes to it, ransomware encryption likely in progress",
                    "details": {"path": str(path), "event": "modified"},
                })
                del self._canaries[path]           # EN: fire once per corruption / FR: une fois
        return alerts

    def _loop(self) -> None:
        while not self._stop.wait(POLL_S):
            for alert in self.check_once():
                self._emit(alert)

    def start(self) -> None:
        self.plant()
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="canary")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def status(self) -> dict:
        return {"enabled": self.enabled, "canaries": len(self._canaries),
                "running": bool(self._thread and self._thread.is_alive())}


class HoneyPorts:
    """EN: Asyncio listeners on attack-surface ports. Any inbound connection
    fires one alert per (port, source) pair. / FR: écoutes asyncio sur les
    ports attaqués. Toute connexion entrante tire une alerte par couple."""

    def __init__(self, ports: tuple = HONEY_PORTS) -> None:
        self.ports = ports
        self.enabled = False                        # EN: opt-in — bind can conflict / FR: opt-in
        self._servers: list[asyncio.AbstractServer] = []
        self._alerted: set[tuple] = set()
        self.on_alert = None
        self.errors: list[str] = []

    async def start(self) -> dict:
        bound = []
        for port in self.ports:
            try:
                srv = await asyncio.start_server(
                    lambda r, w, p=port: self._touch(r, w, p),
                    "0.0.0.0", port)
                self._servers.append(srv)
                bound.append(port)
            except OSError as e:
                self.errors.append(f"{port}: {e}")
        return {"bound": bound, "errors": list(self.errors)}

    async def _touch(self, reader, writer, port: int) -> None:
        peer = writer.get_extra_info("peername")
        src = peer[0] if peer else "?"
        try:
            writer.close()
        except Exception:                           # noqa: BLE001
            pass
        key = (port, src)
        if key in self._alerted or src.startswith("127."):
            return
        self._alerted.add(key)
        if self.on_alert:
            self.on_alert({
                "type": "HONEYPORT_TOUCH",
                "severity": "critical",
                "message": f"{src} connected to honeyport {port} — nothing legitimate "
                           f"ever does, LAN scan or lateral movement in progress",
                "details": {"port": port, "source": src},
            })

    async def stop(self) -> None:
        for srv in self._servers:
            srv.close()
            await srv.wait_closed()
        self._servers.clear()

    def status(self) -> dict:
        return {"enabled": self.enabled, "bound": [s.sockets[0].getsockname()[1]
                for s in self._servers if s.sockets], "touches": len(self._alerted)}
