"""
EN: Process-lineage verdicts — malware hides in ancestry. A connection
    from `python` means nothing; the SAME connection from
    `browser -> sh -> curl -> python` tells the real story. This module
    walks the parent chain of a suspicious pid and scores it:

      +2  chain passes through a shell/interpreter (sh, bash, python,
          node, perl, ruby, pwsh) — script-based execution
      +2  chain ROOT is a browser, office app, email client or terminal
          — user-content-driven spawn, the classic infection vector
      +1  depth >= 4 — legitimate app flows rarely nest that deep
      +1  grandparent is a package manager or terminal — postinstall shape
      -1  root is a system launcher (launchd/systemd/init) — daemon shape

    score >= 4 -> LINEAGE_SUSPECT critical alert with the full chain.
    The point is not that deep trees are evil — developers nest deep all
    day — but that the chain makes the anomaly EXPLAINABLE: the alert
    reads "your browser spawned a shell that spawned this binary", and
    that sentence is either obviously fine or obviously not.

    Cross-platform honest degradation: psutil-free implementation via
    /proc on Linux, `ps` on macOS, WMI-less `wmic`/powershell on Windows;
    a pid that dies before inspection yields chain=[name] and score 0.

FR: Verdicts par lignée de processus — le malware se cache dans l'ascen-
    dance. Une connexion depuis `python` ne dit rien ; la MÊME depuis
    `browser -> sh -> curl -> python` raconte tout. Le module remonte la
    chaîne parentale et la note : shells/interpréteurs, racine navigateur/
    office/terminal, profondeur. score >= 4 = alerte LINEAGE_SUSPECT
    critique avec la chaîne complète — la phrase « votre navigateur a
    engendré un shell qui a engendré ce binaire » est soit évidemment
    normale, soit évidemment pas.
"""

from __future__ import annotations

import subprocess
import threading
import time

INTERPRETERS = {"sh", "bash", "zsh", "dash", "fish", "python", "python3",
                "node", "perl", "ruby", "pwsh", "powershell", "cmd",
                "osascript", "php", "java"}
CONTENT_ROOTS = {"chrome", "firefox", "safari", "edge", "brave", "arc",
                 "outlook", "thunderbird", "mail", "winword", "excel",
                 "powerpnt", "soffice", "iterm", "terminal", "wezterm",
                 "alacritty", "kitty", "warp", "hyper"}
SYSTEM_ROOTS = {"launchd", "systemd", "init", "kernel_task", "svchost",
                "services.exe", "wininit"}
PKG_ROOTS = {"npm", "pip", "pip3", "yarn", "pnpm", "cargo", "gem", "brew"}

DEPTH_BONUS = 4
SCORE_THRESHOLD = 4
_CACHE_TTL = 300.0


def _ps_table() -> dict[int, tuple[int, str]]:
    """EN: pid -> (ppid, comm-name) for the whole table, best effort.
    FR: pid -> (ppid, nom) pour toute la table, au mieux."""
    table: dict[int, tuple[int, str]] = {}
    import platform as _plat
    if _plat.system() == "Windows":
        # EN: Windows has no ps — the process table comes from CIM via
        #     PowerShell (present since Win7), wmic as legacy fallback.
        # FR: pas de ps sous Windows — table via CIM PowerShell, wmic en repli.
        for cmd, parser in (
            (["powershell", "-NoProfile", "-Command",
              "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name "
              "| ForEach-Object { \"$($_.ProcessId) $($_.ParentProcessId) $($_.Name)\" }"], "cim"),
            (["wmic", "process", "get", "processid,parentprocessid,name", "/format:csv"], "wmic"),
        ):
            try:
                out = subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
            except (OSError, subprocess.TimeoutExpired):
                continue
            for line in out.splitlines():
                parts = line.strip().split()
                nums = [p for p in parts if p.isdigit()]
                if parser == "cim" and len(parts) >= 3 and parts[0].isdigit() and parts[1].isdigit():
                    name = parts[2].lower().replace(".exe", "")
                    table[int(parts[0])] = (int(parts[1]), name)
                elif parser == "wmic" and "," in line and len(nums) >= 2:
                    cells = line.split(",")
                    if len(cells) >= 4 and cells[-2].isdigit() and cells[-1].isdigit():
                        name = cells[-3].lower().replace(".exe", "")
                        table[int(cells[-1])] = (int(cells[-2]), name)
            if table:
                break
        return table
    try:
        out = subprocess.run(["ps", "-eo", "pid,ppid,comm"],
                             capture_output=True, text=True, timeout=4).stdout
        for line in out.splitlines()[1:]:
            parts = line.split(None, 2)
            if len(parts) == 3 and parts[0].isdigit():
                name = parts[2].rsplit("/", 1)[-1].lower()
                table[int(parts[0])] = (int(parts[1]), name)
    except (OSError, subprocess.TimeoutExpired):
        pass
    return table


def walk_chain(pid: int, table: dict[int, tuple[int, str]] | None = None,
               max_depth: int = 12) -> list[str]:
    """EN: [self, parent, ..., root] process names. Pure function given a
    table. / FR: [soi, parent, ..., racine]. Fonction pure étant donné une table."""
    if table is None:
        table = _ps_table()
    chain: list[str] = []
    seen: set[int] = set()
    cur = pid
    while cur and cur not in seen and len(chain) < max_depth:
        seen.add(cur)
        entry = table.get(cur)
        if entry is None:
            break
        ppid, name = entry
        chain.append(name)
        cur = ppid
    return chain


def score_chain(chain: list[str]) -> tuple[int, list[str]]:
    """EN: (score, reasons) for a lineage chain. Pure.
    FR: (score, raisons) pour une chaîne. Pur."""
    if not chain:
        return 0, []
    score = 0
    reasons: list[str] = []
    ancestors = chain[1:]                         # EN: everything above self / FR: tout au-dessus de soi
    root = chain[-1]
    interpreters_hit = [n for n in ancestors if n in INTERPRETERS]
    if interpreters_hit:
        score += 2
        reasons.append(f"shell/interpreter in chain: {', '.join(interpreters_hit[:3])}")
    # EN: Content apps anywhere in the ANCESTRY — on posix everything
    #     descends from launchd/init, so the root itself is meaningless;
    #     "browser/terminal/Office somewhere above me" is the real signal.
    # FR: apps de contenu n'importe où dans l'ascendance — sous posix tout
    #     descend de launchd/init, la racine ne veut rien dire.
    content_hit = [n for n in ancestors if n in CONTENT_ROOTS]
    if content_hit:
        score += 2
        reasons.append(f"spawned under user-content app: {content_hit[0]}")
    if root in SYSTEM_ROOTS and not content_hit and not interpreters_hit:
        score -= 1
        reasons.append(f"clean system daemon shape: {root}")
    if len(chain) >= DEPTH_BONUS:
        score += 1
        reasons.append(f"nesting depth {len(chain)}")
    if any(n in PKG_ROOTS for n in ancestors):
        score += 1
        reasons.append("package-manager ancestry")
    return max(0, score), reasons


class LineageWatch:
    """EN: Cache + verdict wrapper, deduped per chain signature.
    FR: cache + verdict, dédupliqué par signature de chaîne."""

    def __init__(self, table_probe=_ps_table) -> None:
        self._probe = table_probe
        self.enabled = True
        self._cache: dict[int, tuple[float, list[str]]] = {}
        self._alerted: set[str] = set()
        self._lock = threading.Lock()

    def chain_for(self, pid: int) -> list[str]:
        now = time.time()
        with self._lock:
            hit = self._cache.get(pid)
            if hit and now - hit[0] < _CACHE_TTL:
                return hit[1]
        chain = walk_chain(pid, self._probe())
        with self._lock:
            self._cache[pid] = (now, chain)
            if len(self._cache) > 5000:
                cutoff = now - _CACHE_TTL
                self._cache = {p: v for p, v in self._cache.items() if v[0] > cutoff}
        return chain

    def verdict(self, pid: int, process_name: str,
                context: str = "") -> dict | None:
        """EN: Score the lineage of a suspicious process. Alert when the
        chain itself is the evidence. / FR: noter la lignée d'un processus
        suspect. Alerte quand la chaîne est elle-même la preuve."""
        if not self.enabled or not pid:
            return None
        chain = self.chain_for(pid)
        score, reasons = score_chain(chain)
        if score < SCORE_THRESHOLD:
            return None
        sig = "->".join(chain)
        with self._lock:
            if sig in self._alerted:
                return None
            self._alerted.add(sig)
        return {
            "type": "LINEAGE_SUSPECT",
            "severity": "critical",
            "message": f"Suspicious ancestry for {process_name}: {' -> '.join(chain)} — "
                       f"{'; '.join(reasons)}. This sentence is either obviously fine or obviously not.",
            "details": {"pid": pid, "process": process_name, "chain": chain,
                        "score": score, "reasons": reasons, "context": context},
        }
