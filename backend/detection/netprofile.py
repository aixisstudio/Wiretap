"""
EN: Network-aware automatic profile switching — the Little Snitch killer
    feature, cross-platform. The firewall already knows how to expand a
    named profile; this module answers "which network am I on?" and
    applies the profile the user assigned to it.

    Network identity (best first):
      * Wi-Fi SSID+BSSID — the network you joined (macOS ipconfig/
        wdutil, Windows netsh, Linux iwgetid/nmcli);
      * fallback: default-gateway MAC + interface subnet — works for
        ethernet/docked setups where there is no SSID at all.

    Privacy note: the fingerprint NEVER leaves the machine — it is a
    local lookup key into the user's own mapping, nothing is broadcast.
    Everything degrades honestly: commands missing on a platform just
    yield the next fallback, and an unmapped network changes nothing.

FR: Bascule automatique de profil selon le réseau — la killer feature de
    Little Snitch, en cross-plateforme. Le pare-feu sait déjà déplier un
    profil nommé ; ce module répond « sur quel réseau suis-je ? » et
    applique le profil assigné par l'utilisateur.

    Identité réseau (meilleur d'abord) :
      * SSID+BSSID Wi-Fi — le réseau rejoint (ipconfig/wdutil macOS,
        netsh Windows, iwgetid/nmcli Linux) ;
      * repli : MAC de la passerelle par défaut + sous-réseau — marche
        aussi en ethernet/dock sans SSID.

    Confidentialité : l'empreinte ne quitte JAMAIS la machine — c'est une
    clé de recherche locale dans le mapping de l'utilisateur. Dégradation
    honnête : commande absente → repli suivant ; réseau non mappé → rien.
"""

from __future__ import annotations

import logging
import re
import subprocess
import threading
import time

logger = logging.getLogger("wiretap.netprofile")

_POLL_INTERVAL = 15.0          # EN: seconds between checks / FR: secondes entre vérifs
_CMD_TIMEOUT = 4.0


def _run(cmd: list[str]) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=_CMD_TIMEOUT)
        return out.stdout or ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def wifi_ssid_bssid(sysname: str) -> tuple[str | None, str | None]:
    """EN: (SSID, BSSID) of the current Wi-Fi network, platform-specific.
    Returns (None, None) when not on Wi-Fi or undetectable.
    FR: (SSID, BSSID) du réseau Wi-Fi courant. (None, None) hors Wi-Fi."""
    if sysname == "Darwin":
        # EN: modern macOS — `ipconfig getsummary en0` still exposes SSID
        #     on most builds; wdutil needs sudo for info since 14.4.
        # FR: macOS moderne — ipconfig expose encore le SSID la plupart
        #     du temps ; wdutil exige sudo depuis 14.4.
        for iface in ("en0", "en1"):
            out = _run(["ipconfig", "getsummary", iface])
            m = re.search(r"^\s*SSID\s*:\s*(.+)$", out, re.M)
            if m:
                ssid = m.group(1).strip()
                mb = re.search(r"^\s*BSSID\s*:\s*([0-9a-fA-F:]{17})", out, re.M)
                return ssid, (mb.group(1).lower() if mb else None)
        return None, None
    if sysname == "Windows":
        out = _run(["netsh", "wlan", "show", "interfaces"])
        ms = re.search(r"^\s*SSID\s*:\s*(.+)$", out, re.M)
        mb = re.search(r"^\s*BSSID\s*:\s*([0-9A-Fa-f:]{17})", out, re.M)
        if ms:
            return ms.group(1).strip(), (mb.group(1).lower() if mb else None)
        return None, None
    # EN: Linux — iwgetid is instant when present, nmcli the fallback.
    # FR: Linux — iwgetid immédiat si présent, nmcli en repli.
    out = _run(["iwgetid", "-r"])
    ssid = out.strip() or None
    bssid = None
    if ssid:
        ap = _run(["iwgetid", "-a", "-r"]).strip()
        bssid = ap.lower() if re.fullmatch(r"[0-9a-fA-F:]{17}", ap) else None
        return ssid, bssid
    out = _run(["nmcli", "-t", "-f", "active,ssid,bssid", "dev", "wifi"])
    for line in out.splitlines():
        parts = line.split(":")
        if parts and parts[0] == "yes" and len(parts) >= 2 and parts[1]:
            raw_bssid = ":".join(parts[2:8]).replace("\\", "").lower() if len(parts) >= 8 else None
            return parts[1], raw_bssid or None
    return None, None


def gateway_fingerprint(sysname: str) -> str | None:
    """EN: Fallback fingerprint — default gateway MAC + local subnet,
    e.g. `gw:aa:bb:cc:dd:ee:ff/192.168.1`. Works on ethernet and Wi-Fi.
    FR: Empreinte de repli — MAC passerelle + sous-réseau local.
    Marche en ethernet comme en Wi-Fi."""
    gw_ip = None
    if sysname in ("Darwin", "Linux"):
        out = _run(["sh", "-c", "netstat -rn 2>/dev/null | grep '^default' | head -1"])
        parts = out.split()
        if len(parts) >= 2:
            gw_ip = parts[1]
    elif sysname == "Windows":
        out = _run(["powershell", "-NoProfile", "-Command",
                    "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).NextHop"])
        gw_ip = out.strip() or None
    if not gw_ip:
        return None
    # EN: ARP lookup for the gateway MAC — `arp -n` is universal enough.
    # FR: MAC de la passerelle via ARP — `arp -n` est assez universel.
    mac = None
    out = _run(["arp", "-n", gw_ip])
    m = re.search(r"([0-9a-fA-F]{1,2}[:\-]){5}[0-9a-fA-F]{1,2}", out)
    if m:
        mac = m.group(0).lower().replace("-", ":")
    elif sysname == "Windows":
        out = _run(["arp", "-a", gw_ip])
        m = re.search(r"([0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}", out)
        if m:
            mac = m.group(0).lower().replace("-", ":")
    subnet = ".".join(gw_ip.split(".")[:3]) if gw_ip.count(".") == 3 else gw_ip
    return f"gw:{mac or 'unknown'}/{subnet}"


def current_fingerprint(sysname: str) -> dict:
    """EN: Best available network identity. FR: meilleure identité réseau."""
    ssid, bssid = wifi_ssid_bssid(sysname)
    if ssid:
        return {"kind": "wifi", "ssid": ssid, "bssid": bssid,
                "fp": f"wifi:{ssid}" + (f"@{bssid}" if bssid else "")}
    gw = gateway_fingerprint(sysname)
    if gw:
        return {"kind": "gateway", "ssid": None, "bssid": None, "fp": gw}
    return {"kind": "unknown", "ssid": None, "bssid": None, "fp": "unknown"}


class NetworkProfiler:
    """EN: Background watcher — polls the network identity, and when it
    changes applies the firewall profile the user mapped to it. Silent
    no-op when disabled, unmapped, or when the fingerprint is unknown.
    FR: Veille en tâche de fond — surveille l'identité réseau et applique
    le profil pare-feu mappé au changement. No-op silencieux si désactivé,
    non mappé ou empreinte inconnue."""

    def __init__(self, fw, sysname: str) -> None:  # noqa: ANN001
        self.fw = fw
        self.sysname = sysname
        self.enabled = False
        self.mappings: dict[str, str] = {}       # EN: fp -> profile / FR: empreinte -> profil
        self.last_fp: str | None = None
        self.last_applied: str | None = None
        self.last_change_ts: float | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def configure(self, *, enabled: bool | None = None,
                  mappings: dict | None = None) -> dict:
        if mappings is not None:
            self.mappings = {str(k): str(v) for k, v in mappings.items()
                             if str(v).lower() in self.fw.PROFILES}
        if enabled is not None:
            self.enabled = bool(enabled)
            if self.enabled:
                self.start()
            else:
                self.stop()
        return self.status()

    def status(self) -> dict:
        cur = current_fingerprint(self.sysname) if self.enabled else {"fp": self.last_fp or "?", "kind": "?", "ssid": None, "bssid": None}
        return {
            "enabled": self.enabled,
            "current": cur,
            "mapped_profile": self.mappings.get(cur.get("fp", "")),
            "last_applied": self.last_applied,
            "mappings": dict(self.mappings),
            "profiles": sorted(self.fw.PROFILES),
        }

    def assign_current(self, profile: str) -> dict:
        """EN: Map the CURRENT network to a profile — the one-tap gesture
        of the UI. Pass "none" to unmap. FR: mapper le réseau COURANT à
        un profil — le geste en un tap. « none » pour démapper."""
        cur = current_fingerprint(self.sysname)
        fp = cur.get("fp", "unknown")
        if fp == "unknown":
            return {"ok": False, "error": "network identity unknown"}
        if profile.lower() in ("none", ""):
            self.mappings.pop(fp, None)
        elif profile.lower() in self.fw.PROFILES:
            self.mappings[fp] = profile.lower()
        else:
            return {"ok": False, "error": f"unknown profile: {profile}"}
        return {"ok": True, "fp": fp, "mappings": dict(self.mappings)}

    # ── watcher / veille ────────────────────────────────────────────────────

    def _loop(self) -> None:
        while not self._stop.wait(_POLL_INTERVAL):
            try:
                cur = current_fingerprint(self.sysname)
                fp = cur.get("fp", "unknown")
                if fp == self.last_fp or fp == "unknown":
                    continue
                self.last_fp = fp
                profile = self.mappings.get(fp)
                if profile:
                    self.fw.apply_profile(profile)
                    self.last_applied = profile
                    self.last_change_ts = time.time()
                    logger.info("network changed to %s — applied profile %s", fp, profile)
            except Exception as e:               # noqa: BLE001 — the watcher must survive
                logger.debug("netprofile loop: %s", e)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="netprofile")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
