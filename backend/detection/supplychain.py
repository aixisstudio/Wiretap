"""
EN: Supply-chain watch — npm/pip/cargo install-time network governance.
    The classic malware install vector is the postinstall script that
    phones home while you trustingly run `npm install`. Wiretap watches:

      * registry enforcement — package managers talking to hosts OUTSIDE
        the curated registry allowlist (npmjs, PyPI, crates.io,
        rubygems...) is a typosquat/dependency-confusion signal;
      * install-window correlation — processes NEVER SEEN BEFORE that
        open connections within minutes of package-manager activity get
        flagged as postinstall-shaped execution.

    Degrades honestly: without cmdline visibility we use process names +
    timing correlation, and the alerts say exactly that.

FR: Veille supply-chain — gouvernance réseau des installs npm/pip/cargo.
    Le vecteur classique est le script postinstall qui phone home pendant
    le `npm install`. Wiretap surveille : application d'une allowlist de
    registries, et corrélation temporelle des processus jamais vus qui
    ouvrent des connexions dans la foulée d'une install. Dégradation
    honnête documentée dans les alertes.
"""

from __future__ import annotations

import threading
import time

# EN: Package manager process names (lowercased basename).
# FR: noms des gestionnaires de paquets (basename minuscule).
PKG_MANAGERS = {"npm", "npm.cmd", "yarn", "pnpm", "pip", "pip3", "pipx",
                "cargo", "gem", "composer", "go", "nuget", "mvn", "gradle",
                "bundler", "poetry", "uv", "brew"}

# EN: First-party registry suffixes per ecosystem — talking anywhere else
#     during install is the anomaly. / FR: suffixes first-party.
REGISTRY_ALLOWLIST = {
    "npmjs.com", "npmjs.org", "yarnpkg.com",
    "pypi.org", "pythonhosted.org",
    "crates.io", "static.crates.io",
    "rubygems.org", "packagist.org", "repo.packagist.org",
    "nuget.org", "api.nuget.org",
    "github.com", "githubusercontent.com", "codeload.github.com",
    "registry.npmjs.org", "go.dev", "proxy.golang.org",
    "repo.maven.apache.org", "plugins.gradle.org",
    "formulae.brew.sh", "ghcr.io",
}

_CORRELATION_WINDOW_S = 600          # EN: 10 min after pkg activity / FR: 10 min après activité
_RESEEN_FORGET_S = 86400             # EN: process novelty memory / FR: mémoire de nouveauté


def in_allowlist(hostname: str) -> bool:
    h = (hostname or "").lower().rstrip(".")
    return any(h == d or h.endswith("." + d) for d in REGISTRY_ALLOWLIST)


class SupplyChainWatch:
    """EN: Lock-guarded observer fed per-packet from the capture loop.
    FR: observateur protégé par verrou, alimenté paquet par paquet."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.enabled = True
        self._last_pkg_activity = 0.0
        self._seen_processes: dict[str, float] = {}   # EN: proc -> first seen ts / FR: proc -> 1ère vue
        self._alerted: set[str] = set()               # EN: dedupe keys / FR: dédup

    def observe(self, process_name: str, hostname: str,
                direction: str, remote_ip: str) -> list[dict]:
        if not self.enabled or not process_name or direction != "out":
            return []
        proc = process_name.lower()
        now = time.time()
        alerts: list[dict] = []
        with self._lock:
            # EN: gc the novelty memory / FR: gc de la mémoire
            if len(self._seen_processes) > 20000:
                cutoff = now - _RESEEN_FORGET_S
                self._seen_processes = {p: ts for p, ts in self._seen_processes.items() if ts > cutoff}

            is_pkg = proc in PKG_MANAGERS or any(
                proc.startswith(p + " ") or proc == p for p in PKG_MANAGERS)
            if is_pkg:
                self._last_pkg_activity = now
                if hostname and not in_allowlist(hostname):
                    key = f"reg:{proc}:{hostname}"
                    if key not in self._alerted:
                        self._alerted.add(key)
                        alerts.append({
                            "type": "PKG_REGISTRY_ANOMALY",
                            "severity": "warning",
                            "message": f"{process_name} contacted {hostname} — outside the "
                                       f"curated registry allowlist (typosquat/dependency-confusion check)",
                            "details": {"process": process_name, "hostname": hostname,
                                        "remote_ip": remote_ip},
                        })
            else:
                first = self._seen_processes.get(proc)
                if first is None:
                    self._seen_processes[proc] = now
                    # EN: postinstall-shaped — brand-new process networking
                    #     inside the install window / FR: forme postinstall —
                    #     processus tout neuf qui réseaute dans la fenêtre
                    if (now - self._last_pkg_activity < _CORRELATION_WINDOW_S
                            and self._last_pkg_activity > 0):
                        key = f"pi:{proc}"
                        if key not in self._alerted:
                            self._alerted.add(key)
                            alerts.append({
                                "type": "POSTINSTALL_NET",
                                "severity": "critical",
                                "message": f"Never-before-seen process {process_name} opened a "
                                           f"connection to {hostname or remote_ip} minutes after "
                                           f"package-manager activity — classic postinstall malware pattern",
                                "details": {"process": process_name,
                                            "hostname": hostname, "remote_ip": remote_ip},
                            })
        return alerts

    def note_pkg_activity(self) -> None:
        """EN: Test/maintenance hook. / FR: crochet test/maintenance."""
        with self._lock:
            self._last_pkg_activity = time.time()

    def status(self) -> dict:
        with self._lock:
            return {
                "enabled": self.enabled,
                "processes_tracked": len(self._seen_processes),
                "alerts_deduped": len(self._alerted),
                "last_pkg_activity": self._last_pkg_activity,
            }
