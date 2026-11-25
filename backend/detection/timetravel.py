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


def _proc_socket_inodes() -> dict[str, tuple[int, str]]:
    """EN: socket-inode -> (pid, comm) resolved by scanning /proc/[pid]/fd
        plus /proc/[pid]/comm — the zero-dependency Linux way, no lsof
        needed (lsof is absent on minimal/server installs).
    FR: inode-socket -> (pid, comm) en scannant /proc/[pid]/fd — voie
        zéro-dépendance, lsof étant souvent absent des installs minimales."""
    import os
    inode_map: dict[str, tuple[int, str]] = {}
    proc_root = Path("/proc")
    try:
        pids = [int(p.name) for p in proc_root.iterdir() if p.name.isdigit()]
    except OSError:
        return inode_map
    for pid in pids[:4000]:                              # EN: bounded scan / FR: scan borné
        fd_dir = proc_root / str(pid) / "fd"
        try:
            comm = (proc_root / str(pid) / "comm").read_text(errors="replace").strip()
        except OSError:
            comm = ""
        try:
            for fd in os.listdir(fd_dir):
                try:
                    target = os.readlink(fd_dir / fd)
                except OSError:
                    continue
                if target.startswith("socket:["):
                    inode_map[target[8:-1]] = (pid, comm)
        except OSError:                                  # EN: permission or gone / FR: permission ou parti
            continue
    return inode_map


def _collect_listeners_linux() -> dict[str, dict]:
    """EN: Listening TCP sockets from /proc/net/tcp{,6} — state 0A means
        LISTEN, no parsing of localized text possible because it is hex.
        Process resolution best-effort via fd scan; ports appear even when
        the owner is another user's process (honest empty process field).
    FR: sockets en écoute depuis /proc/net/tcp{,6} — l'état 0A = LISTEN en
        hexa, aucune localisation possible. Résolution des processus au
        mieux ; les ports apparaissent même sans propriétaire lisible."""
    listeners: dict[str, dict] = {}
    inodes = _proc_socket_inodes()
    for proc_file in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = Path(proc_file).read_text(errors="replace").splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 10 or parts[3] != "0A":     # EN: 0A = LISTEN / FR: 0A = LISTEN
                continue
            local = parts[1].rsplit(":", 1)[-1]
            try:
                port = int(local, 16)
            except ValueError:
                continue
            inode = parts[9] if len(parts) > 9 else ""
            pid, comm = inodes.get(inode, (0, ""))
            listeners[str(port)] = {"port": port, "process": comm, "pid": pid}
    return listeners


def _run_capture(cmd: list[str], timeout: int = 10) -> str:
    """EN: Run a command capturing bytes and decoding leniently — Windows
        console output encoding varies by locale (cp850/cp1252/utf-8), and
        text=True would either crash or silently mangle. Bytes + replace
        never fails. / FR: capture en bytes, décodage tolérant."""
    import subprocess
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return out.stdout.decode(errors="replace")
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _windows_tasklist_names() -> dict[int, str]:
    """EN: pid -> process name from tasklist CSV. The /fo csv format is
        positional, not word-parsed, so it survives localization.
    FR: pid -> nom depuis tasklist CSV. Positionnel, survit à la locale."""
    names: dict[int, str] = {}
    out = _run_capture(["tasklist", "/fo", "csv", "/nh"], timeout=10)
    for row in out.splitlines():
        cells = row.strip('"').split('","')
        if len(cells) >= 2 and cells[1].isdigit():
            names[int(cells[1])] = cells[0]
    return names


def _collect_listeners_windows() -> dict[str, dict]:
    """EN: Listening TCP sockets on Windows, localization-proof.
        Primary: PowerShell Get-NetTCPConnection — structured objects, no
        text parsing, immune to locale. Fallback: netstat -ano with a
        locale-independent heuristic — a LISTENING socket is identifiable
        by its foreign address 0.0.0.0:0 / [::]:0, NOT by the state word
        which is localized ('LISTENING', 'ABHÖREN', 'ÉCOUTE'...).
    FR: sockets TCP en écoute, à l'épreuve de la localisation. PowerShell
        structuré en primaire ; netstat en repli avec heuristique
        positionnelle — l'adresse distante 0.0.0.0:0 identifie un listener
        sans dépendre du mot d'état localisé."""
    listeners: dict[str, dict] = {}
    names = _windows_tasklist_names()
    ps_out = _run_capture(
        ["powershell", "-NoProfile", "-Command",
         "Get-NetTCPConnection -State Listen | "
         "Select-Object LocalPort,OwningProcess | "
         "ForEach-Object { \"$($_.LocalPort) $($_.OwningProcess)\" }"], timeout=15)
    for line in ps_out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            port, pid = int(parts[0]), int(parts[1])
            listeners[str(port)] = {"port": port, "process": names.get(pid, ""), "pid": pid}
    if listeners:
        return listeners
    # EN: fallback netstat — foreign-address heuristic / FR: repli netstat
    out = _run_capture(["netstat", "-ano", "-p", "tcp"], timeout=10)
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0].upper() != "TCP" or not parts[-1].isdigit():
            continue
        foreign = parts[2].rsplit(":", 1)
        is_listener = (len(foreign) == 2 and foreign[1] == "0"
                       and foreign[0] in ("0.0.0.0", "[::]", "::", "[0:0:0:0:0:0:0:0]"))
        if not is_listener:
            continue
        local = parts[1].rsplit(":", 1)[-1]
        pid = int(parts[-1])
        if local.isdigit():
            listeners[local] = {"port": int(local), "process": names.get(pid, ""), "pid": pid}
    return listeners


def collect_listeners() -> dict[str, dict]:
    """EN: Listening ports with owning process. Pure /proc parse on Linux,
        lsof fallback elsewhere — best-effort, zero privileges.
    FR: ports en écoute avec processus propriétaire. Best-effort."""
    listeners: dict[str, dict] = {}
    import platform as _plat
    if _plat.system() == "Windows":
        return _collect_listeners_windows()
    if _plat.system() == "Linux":
        return _collect_listeners_linux()
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
    import platform as _plat
    if _plat.system() == "Windows":
        out = _run_capture(["tasklist", "/fo", "csv", "/nh"], timeout=10)
        for row in out.splitlines():
            cells = row.strip('"').split('","')
            if len(cells) >= 1 and cells[0]:
                name = cells[0].replace(".exe", "")
                agg = procs.setdefault(name, {"name": name, "count": 0, "path": cells[0]})
                agg["count"] += 1
        return procs
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
