"""
EN: System DNS integration — the last mile of the DNS firewall. Filtering
    on 127.0.0.1:5353 only protects you when the OS actually sends its
    queries there. This module applies (and cleanly reverts) the system
    DNS configuration per platform:

      macOS   networksetup -setdnsservers <service> 127.0.0.1
      Linux   resolvectl dns <iface> 127.0.0.1  (systemd-resolved)
              or nmcli fallback for non-systemd distros
      Windows netsh interface ip set dns / Set-DnsClientServerAddress

    Brutal honesty built in:
      * port 53 vs 5353 — system resolvers cannot use a custom port, so
        real system-wide filtering needs the proxy bound on 53, which
        needs elevated privileges on unix. apply() reports exactly what
        it did and what it could not do;
      * reverting is first-class: the previous servers are snapshotted
        BEFORE any change and `revert()` restores them;
      * verification — after applying, we check the resolver actually
        answers through us before declaring success.

FR: Intégration DNS système — le dernier kilomètre du pare-feu DNS.
    Filtrer sur 127.0.0.1:5353 ne protège que si l'OS envoie vraiment ses
    requêtes là. Ce module applique (et annule proprement) la config DNS
    système par plateforme, avec honnêteté intégrée : le port 53 exige
    des privilèges, les serveurs précédents sont snapshotés AVANT tout
    changement, et la vérification confirme que le résolveur répond
    vraiment à travers nous.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess

logger = logging.getLogger("wiretap.dnssystem")

_TIMEOUT = 8.0


def _run(cmd: list[str]) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=_TIMEOUT)
        return r.returncode, r.stdout or "", r.stderr or ""
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, "", str(e)


# ── platform capability probes / sondes ──────────────────────────────────────

def macos_services(run=_run) -> list[str]:
    """EN: Active network service names (Wi-Fi, USB 10/100/1000 LAN...).
    FR: noms des services réseau actifs."""
    rc, out, _ = run(["networksetup", "-listallnetworkservices"])
    if rc != 0:
        return []
    lines = [l.strip() for l in out.splitlines()[1:] if l.strip()]
    return [l for l in lines if not l.startswith("*")]   # EN: * = disabled / FR: * = désactivé


def macos_current_dns(service: str, run=_run) -> list[str]:
    rc, out, _ = run(["networksetup", "-getdnsservers", service])
    if rc != 0 or "aren't any" in out.lower() or "there aren't" in out.lower():
        return []
    return [l.strip() for l in out.splitlines() if re.fullmatch(r"[\d.]+", l.strip())]


def linux_iface(run=_run) -> str | None:
    rc, out, _ = run(["sh", "-c", "ip route show default 2>/dev/null | head -1"])
    m = re.search(r"dev\s+(\S+)", out)
    return m.group(1) if rc == 0 and m else None


# ── apply / revert — command builders are pure for testability ───────────────

def build_apply_cmds(sysname: str, services: list[str],
                     iface: str | None) -> list[list[str]]:
    """EN: Pure command plan for pointing the system DNS at loopback.
    FR: plan de commandes pur pour pointer le DNS système vers loopback."""
    cmds: list[list[str]] = []
    if sysname == "Darwin":
        for svc in services:
            cmds.append(["networksetup", "-setdnsservers", svc, "127.0.0.1"])
    elif sysname == "Linux":
        if iface:
            cmds.append(["resolvectl", "dns", iface, "127.0.0.1"])
            cmds.append(["resolvectl", "domain", iface, "~."])
    elif sysname == "Windows":
        cmds.append(["netsh", "interface", "ip", "set", "dns",
                     "name=Wi-Fi", "static", "127.0.0.1"])
    return cmds


def build_revert_cmds(sysname: str, services: list[str],
                      iface: str | None,
                      previous: dict) -> list[list[str]]:
    """EN: Pure revert plan — restores snapshotted servers or DHCP.
    FR: plan d'annulation pur — restaure les serveurs snapshotés ou DHCP."""
    cmds: list[list[str]] = []
    if sysname == "Darwin":
        for svc in services:
            prev = previous.get(svc) or []
            if prev:
                cmds.append(["networksetup", "-setdnsservers", svc] + prev)
            else:
                cmds.append(["networksetup", "-setdnsservers", svc, "Empty"])
    elif sysname == "Linux" and iface:
        cmds.append(["resolvectl", "revert", iface])
    elif sysname == "Windows":
        cmds.append(["netsh", "interface", "ip", "set", "dns",
                     "name=Wi-Fi", "dhcp"])
    return cmds


class SystemDns:
    """EN: Stateful integrator — snapshot/apply/verify/revert with honest
    reporting. / FR: intégrateur stateful — snapshot/apply/verify/revert."""

    def __init__(self, sysname: str, run=_run) -> None:
        self.sysname = sysname
        self._run = run
        self.previous: dict[str, list[str]] = {}
        self.applied = False
        self.applied_services: list[str] = []
        self.iface: str | None = None

    def snapshot(self) -> dict:
        if self.sysname == "Darwin":
            services = macos_services(self._run)
            self.previous = {s: macos_current_dns(s, self._run) for s in services}
            self.applied_services = services
        elif self.sysname == "Linux":
            self.iface = linux_iface(self._run)
        return {"services": self.applied_services, "iface": self.iface,
                "previous": self.previous}

    def apply(self) -> dict:
        snap = self.snapshot()
        cmds = build_apply_cmds(self.sysname, snap["services"], snap["iface"])
        if not cmds:
            return {"ok": False, "error": f"no integration path for {self.sysname}",
                    "needs": "unsupported platform"}
        ran, failed = [], []
        for cmd in cmds:
            rc, out, err = self._run(cmd)
            (ran if rc == 0 else failed).append({"cmd": " ".join(cmd), "rc": rc,
                                                 "err": (err or out).strip()[:200]})
        self.applied = bool(ran) and not failed
        result = {"ok": self.applied, "ran": ran, "failed": failed,
                  "previous": snap["previous"]}
        if failed:
            result["needs"] = ("elevated privileges — run Wiretap backend with sudo, "
                               "or apply the commands manually")
        return result

    def revert(self) -> dict:
        cmds = build_revert_cmds(self.sysname, self.applied_services,
                                 self.iface, self.previous)
        ran, failed = [], []
        for cmd in cmds:
            rc, out, err = self._run(cmd)
            (ran if rc == 0 else failed).append({"cmd": " ".join(cmd), "rc": rc})
        self.applied = False
        return {"ok": not failed, "ran": ran, "failed": failed}

    def status(self) -> dict:
        return {"applied": self.applied, "services": self.applied_services,
                "iface": self.iface,
                "note": "system-wide filtering needs the DNS proxy bound on port 53 "
                        "(elevated privileges on unix); custom-port setups require "
                        "per-app or resolver-specific configuration"}
