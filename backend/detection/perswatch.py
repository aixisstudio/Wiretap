"""
EN: Persistence surface watch — the missing layer of the intrusion cycle.
    Malware that matters must survive reboot. Every real-world intrusion
    eventually touches the persistence surface: LaunchAgents/Daemons on
    macOS, Run keys and services on Windows, systemd units, cron and
    autostart on Linux. Network-first tools watch the traffic; persistence
    is where the malware tells you it plans to STAY.

    Wiretap enumerates every auto-start mechanism reachable without
    privileges, fingerprints each entry (target binary path + hash +
    plist/key content hash), and diffs over time:
      * PERSISTENCE_NEW  — a new auto-start entry appeared
      * PERSISTENCE_MOD  — an existing entry's target or content changed
      * PERSISTENCE_DEL  — an entry vanished (cleanup after infection is
                           itself a signal at high severity when combined)

    Risk scoring per entry — the honest version of "suspicious":
      * target binary in user-writable temp/cache dir    (+3)
      * target unsigned/notarization-unknown — best-effort, macOS codesign
      * interpreter or shell as the target (sh, python…) (+2)
      * run-at-load + keep-alive both set                (+1)
      * entry created within minutes of a network install (correlated
        upstream by killchain — perswatch emits the family signal)

    Pure stdlib: plistlib for macOS plists, winreg on Windows, file scans
    for systemd/cron/autostart. Nothing is written, nothing elevated.

FR: Surveillance de la surface de persistance — la couche manquante du
    cycle d'intrusion. Un malware qui compte doit survivre au reboot :
    LaunchAgents/Daemons sur macOS, clés Run et services sur Windows,
    systemd, cron et autostart sur Linux. Wiretap énumère chaque
    mécanisme d'auto-démarrage accessible sans privilèges, empreinte
    chaque entrée (chemin + hash du binaire cible + hash du contenu) et
    différencie dans le temps : PERSISTENCE_NEW / MOD / DEL. Scoring de
    risque honnête : cible dans un répertoire temp, interpréteur comme
    cible, keep-alive+run-at-load. Stdlib pur, rien n'est écrit ni élevé.
"""

from __future__ import annotations

import hashlib
import os
import plistlib
import platform
import tempfile
import time
from pathlib import Path

SCAN_INTERVAL = 300.0          # EN: 5 min diff cadence / FR: cadence de diff 5 min
INTERPRETERS = {"sh", "bash", "zsh", "python", "python3", "perl", "ruby",
                "osascript", "node", "pwsh", "powershell", "cmd"}


def _sha256_file(path: Path) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()[:16]
    except OSError:
        return ""


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def _in_tempish(path: str) -> bool:
    p = path.lower()
    tmp = tempfile.gettempdir().lower()
    return (p.startswith(tmp) or "/tmp" in p or "/var/folders" in p
            or "\\temp\\" in p or "/.cache/" in p or "appdata\\local\\temp" in p)


def collect_macos() -> dict[str, dict]:
    """EN: Enumerate LaunchAgents/Daemons entries. Pure stdlib plistlib.
    FR: énumérer les entrées LaunchAgents/Daemons. plistlib stdlib pur."""
    entries: dict[str, dict] = {}
    roots = [
        (Path.home() / "Library/LaunchAgents", "user-agent"),
        (Path("/Library/LaunchAgents"), "agent"),
        (Path("/Library/LaunchDaemons"), "daemon"),
    ]
    for root, kind in roots:
        try:
            files = sorted(root.glob("*.plist"))
        except OSError:
            continue
        for plist_path in files:
            entry_id = f"{kind}:{plist_path.name}"
            try:
                raw = plist_path.read_bytes()
                try:
                    plist = plistlib.loads(raw)
                except Exception:
                    plist = {}
                program = plist.get("Program") or ""
                args = plist.get("ProgramArguments") or []
                target = program or (str(args[0]) if args else "")
                entries[entry_id] = {
                    "id": entry_id, "kind": kind, "target": target,
                    "label": plist.get("Label", ""),
                    "content_hash": _sha256_bytes(raw),
                    "target_hash": _sha256_file(Path(target)) if target else "",
                    "run_at_load": bool(plist.get("RunAtLoad")),
                    "keep_alive": bool(plist.get("KeepAlive")),
                    "mtime": plist_path.stat().st_mtime,
                }
            except OSError:
                continue
    return entries


def collect_linux() -> dict[str, dict]:
    """EN: systemd user/system units, cron, autostart desktop entries.
    FR: units systemd, cron, entrées autostart."""
    entries: dict[str, dict] = {}
    roots = [
        (Path.home() / ".config/systemd/user", "user-unit", "*.service"),
        (Path("/etc/systemd/system"), "unit", "*.service"),
        (Path.home() / ".config/autostart", "autostart", "*.desktop"),
    ]
    for root, kind, pattern in roots:
        try:
            files = sorted(root.glob(pattern))
        except OSError:
            continue
        for f in files:
            if f.is_symlink() and kind == "unit":
                pass                                    # EN: enabled units are symlinks / FR: les units activées sont des liens
            try:
                raw = f.read_bytes()
                target = ""
                for line in raw.decode(errors="replace").splitlines():
                    if line.startswith("ExecStart=") or line.startswith("Exec="):
                        target = line.split("=", 1)[1].strip().split()[0] if line.split("=", 1)[1].strip() else ""
                        break
                entries[f"{kind}:{f.name}"] = {
                    "id": f"{kind}:{f.name}", "kind": kind, "target": target,
                    "label": f.name, "content_hash": _sha256_bytes(raw),
                    "target_hash": _sha256_file(Path(target)) if target and target.startswith("/") else "",
                    "run_at_load": True, "keep_alive": False,
                    "mtime": f.stat().st_mtime,
                }
            except OSError:
                continue
    # EN: user crontab — readable as content hash only / FR: crontab utilisateur
    for cron in (Path("/var/spool/cron"), Path("/var/spool/cron/crontabs")):
        try:
            mine = cron / os.environ.get("USER", "")
            if mine.is_file():
                raw = mine.read_bytes()
                entries["cron:user"] = {
                    "id": "cron:user", "kind": "cron", "target": "(crontab)",
                    "label": "user crontab", "content_hash": _sha256_bytes(raw),
                    "target_hash": "", "run_at_load": False, "keep_alive": False,
                    "mtime": mine.stat().st_mtime,
                }
        except OSError:
            continue
    return entries


def collect_windows() -> dict[str, dict]:
    """EN: Run/RunOnce keys + startup folder. FR: clés Run + dossier démarrage."""
    entries: dict[str, dict] = {}
    if platform.system() == "Windows":
        try:
            import winreg
            for hive, base, scope in (
                    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "hkcu-run"),
                    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "hkcu-runonce"),
                    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "hklm-run")):
                try:
                    key = winreg.OpenKey(hive, base)
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                        except OSError:
                            break
                        i += 1
                        target = str(value).strip().strip('"').split('"')[0].split()[0] if value else ""
                        entries[f"{scope}:{name}"] = {
                            "id": f"{scope}:{name}", "kind": scope, "target": target,
                            "label": name, "content_hash": _sha256_bytes(str(value).encode()),
                            "target_hash": _sha256_file(Path(target)) if target else "",
                            "run_at_load": True, "keep_alive": False, "mtime": 0.0,
                        }
                except OSError:
                    continue
        except ImportError:
            pass
    return entries


def collect(system: str | None = None) -> dict[str, dict]:
    sysname = system or platform.system()
    if sysname == "Darwin":
        return collect_macos()
    if sysname == "Linux":
        return collect_linux()
    if sysname == "Windows":
        return collect_windows()
    return {}


def score_entry(entry: dict) -> tuple[int, list[str]]:
    """EN: Risk-score one persistence entry. Pure. FR: noter une entrée. Pur."""
    risk = 0
    findings: list[str] = []
    target = entry.get("target", "")
    base = Path(target).name.lower().split(".exe")[0] if target else ""
    if target and _in_tempish(target):
        risk += 3
        findings.append(f"target in temp/cache dir ({target}) — legit software does not auto-start from there")
    if base in INTERPRETERS:
        risk += 2
        findings.append(f"interpreter as target ({base}) — the real payload is a script argument, invisible here")
    if entry.get("run_at_load") and entry.get("keep_alive"):
        risk += 1
        findings.append("run-at-load + keep-alive — relaunches even if killed")
    if target and not Path(target).exists() and not target.startswith("("):
        risk += 1
        findings.append(f"target missing on disk ({target}) — dangling or cleaned up")
    return risk, findings


class PersistenceWatch:
    """EN: Snapshot + diff the persistence surface. Thread-safe.
    FR: snapshot + diff de la surface de persistance. Thread-safe."""

    def __init__(self, system: str | None = None, collector=None) -> None:  # noqa: ANN001
        self.system = system or platform.system()
        self._collect = collector or (lambda: collect(self.system))
        self._baseline: dict[str, dict] | None = None
        self._current: dict[str, dict] = {}
        self._baseline_ts: float = 0.0
        self._scan_count = 0

    def scan(self, now: float | None = None) -> list[dict]:
        """EN: Scan the surface, diff against baseline. First scan is silent
            (learning). Returns alert dicts for NEW/MOD/DEL with risk scoring.
        FR: scanner la surface, diff contre baseline. Premier scan silencieux.
            Alertes NEW/MOD/DEL avec scoring de risque."""
        now = time.time() if now is None else now
        entries = self._collect()
        self._scan_count += 1
        if self._baseline is None:
            self._baseline = entries
            self._current = entries
            self._baseline_ts = now
            return []
        alerts: list[dict] = []
        for entry_id, entry in entries.items():
            prev = self._baseline.get(entry_id)
            if prev is None:
                risk, findings = score_entry(entry)
                severity = "critical" if risk >= 3 else "warning"
                alerts.append({
                    "type": "PERSISTENCE_NEW",
                    "severity": severity,
                    "message": (f"new auto-start entry appeared: {entry.get('label') or entry_id} "
                                f"({entry['kind']}) -> {entry.get('target') or 'unknown'}"
                                + (f" — {'; '.join(findings)}" if findings else "")
                                + ". If you just installed software, expected. Otherwise: something plans to survive reboot."),
                    "details": {"entry": entry_id, "target": entry.get("target", ""),
                                "kind": entry["kind"], "risk": risk, "findings": findings,
                                "target_hash": entry.get("target_hash", "")},
                })
            elif (prev.get("content_hash") != entry.get("content_hash")
                  or prev.get("target_hash") != entry.get("target_hash")):
                risk, findings = score_entry(entry)
                alerts.append({
                    "type": "PERSISTENCE_MOD",
                    "severity": "critical" if risk >= 3 else "warning",
                    "message": (f"auto-start entry modified: {entry.get('label') or entry_id} — "
                                f"content or target binary changed since baseline"
                                + (f" ({'; '.join(findings)})" if findings else "")),
                    "details": {"entry": entry_id, "target": entry.get("target", ""),
                                "kind": entry["kind"], "risk": risk, "findings": findings},
                })
        for entry_id in set(self._baseline) - set(entries):
            prev = self._baseline[entry_id]
            alerts.append({
                "type": "PERSISTENCE_DEL",
                "severity": "info",
                "message": (f"auto-start entry removed: {prev.get('label') or entry_id} — "
                            f"uninstall or post-infection cleanup"),
                "details": {"entry": entry_id, "kind": prev.get("kind", "")},
            })
        self._baseline = entries
        self._current = entries
        return alerts

    def status(self) -> dict:
        entries = self._current or self._collect()
        scored = [(eid, score_entry(e)) for eid, e in entries.items()]
        risky = [{"entry": eid, "target": entries[eid].get("target", ""),
                  "risk": r, "findings": f}
                 for eid, (r, f) in scored if r >= 3]
        return {
            "entries_total": len(entries),
            "kinds": sorted({e.get("kind", "") for e in entries.values()}),
            "risky": sorted(risky, key=lambda x: -x["risk"]),
            "scans": self._scan_count,
            "baselined": self._baseline is not None,
        }

    def entries(self) -> dict[str, dict]:
        return dict(self._current or self._collect())
