"""
EN: MCP governance — the AI-era plugin attack surface, finally watched.
    Model Context Protocol servers run with the user's full privileges,
    are installed by copy-pasting JSON into a config file, and can read
    files, run shell commands and open sockets. They are the new browser
    extensions: everyone installs them, nobody audits them.

    What Wiretap watches:

      1. CONFIG AUDIT — MCP configs live in known locations
         (~/.cursor/mcp.json, ~/.claude.json, Claude Desktop, Windsurf,
         Zed, VS Code). Each declared server is parsed and risk-scored:
         command type (npx/uvx download-and-run = high), env secrets
         passed to the server (API keys visible to a third-party binary!),
         network endpoints, unscoped filesystem access.
      2. CAPABILITY FLAGS — server names/args hinting at shell, filesystem,
         browser or network powers.
      3. secrets passed in plain env to MCP servers are cross-referenced
         with the secretwatch registry shapes — same redaction discipline.

    Everything is a LOCAL READ of the user's own config files — nothing
    executes, nothing contacts the servers, finding output never carries
    secret values (shapes only).

FR: Gouvernance MCP — la surface d'attaque des plugins de l'ère IA,
    enfin surveillée. Les serveurs MCP tournent avec les privilèges
    complets de l'utilisateur, s'installent en copiant-collant du JSON et
    peuvent lire des fichiers, exécuter des shells et ouvrir des sockets.
    Wiretap audite les configs connues (Cursor, Claude, Windsurf, Zed,
    VS Code) et note le risque : download-and-run npx/uvx, secrets passés
    en env, accès filesystem non scopé, capacités shell/réseau. Lecture
    locale uniquement — rien n'exécute, les valeurs ne sortent jamais.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import os as _os
import platform as _platform

# EN: Config locations per platform — the same app stores its MCP config in
#     different roots on macOS / Windows / Linux. Paths are home-relative
#     unless they start with a %VAR% (Windows env expansion).
# FR: chemins par plateforme — la même app stocke sa config MCP dans des
#     racines différentes selon l'OS.
def _appdata(rel: str) -> str:
    base = _os.environ.get("APPDATA", "")
    return str(_os.path.join(base, rel)) if base else rel

if _platform.system() == "Darwin":
    _claude_desktop = "Library/Application Support/Claude/claude_desktop_config.json"
    _vscode = "Library/Application Support/Code/User/settings.json"
elif _platform.system() == "Windows":
    _claude_desktop = _appdata("Claude/claude_desktop_config.json")
    _vscode = _appdata("Code/User/settings.json")
else:
    _claude_desktop = ".config/Claude/claude_desktop_config.json"
    _vscode = ".config/Code/User/settings.json"

CONFIG_LOCATIONS = [
    ("Cursor", ".cursor/mcp.json"),
    ("Claude Desktop", _claude_desktop),
    ("Claude Code", ".claude.json"),
    ("Windsurf", ".codeium/windsurf/mcp_config.json"),
    ("Zed", ".config/zed/settings.json"),
    ("VS Code", _vscode),
    ("Devin CLI", ".config/devin/mcp_config.json"),
]

# EN: capabilities inferred from names/args — lowercase substring hints.
# FR: capacités inférées des noms/args — indices en minuscules.
CAPABILITY_HINTS = {
    "shell":     ("shell", "exec", "terminal", "command", "bash", "subprocess"),
    "filesystem": ("filesystem", "fs-", "-fs", "files", "directory"),
    "browser":   ("browser", "playwright", "puppeteer", "chrome"),
    "network":   ("fetch", "http", "webhook", "request"),
    "database":  ("postgres", "sqlite", "mysql", "mongo", "redis"),
    "git":       ("github", "gitlab", "git-"),
}

SECRET_ENV_RE = re.compile(r"(key|token|secret|password|passwd)", re.I)


def _shape(value: str) -> str:
    if len(value) <= 8:
        return "…"
    return f"{value[:3]}…{value[-4:]}"


def capabilities_for(name: str, args: list[str]) -> list[str]:
    hay = f"{name} {' '.join(args)}".lower()
    return sorted({cap for cap, hints in CAPABILITY_HINTS.items()
                   if any(h in hay for h in hints)})


def score_server(name: str, spec: dict) -> dict:
    """EN: Risk-score one MCP server declaration. Pure function.
    FR: noter le risque d'une déclaration de serveur. Fonction pure."""
    risk = 0
    findings: list[str] = []
    cmd = str(spec.get("command", ""))
    args = [str(a) for a in (spec.get("args") or [])]
    env = spec.get("env") or {}

    if cmd in ("npx", "uvx", "pipx", "bunx") or cmd.endswith(("/npx", "/uvx")):
        risk += 2
        findings.append(f"download-and-run launcher ({cmd}) — package fetched at runtime, no pinning audit possible")
    if any(a.startswith(("http://", "https://")) for a in args) or spec.get("url"):
        risk += 1
        findings.append("network endpoint — remote MCP server or download URL")
    caps = capabilities_for(name, args)
    if "shell" in caps:
        risk += 2
        findings.append("shell execution capability")
    if "filesystem" in caps:
        # EN: scoped filesystem is the whole point of fs servers — but
        #     unscoped (/, ~) access is the red flag / FR: non scopé = drapeau rouge
        risk += 1
        wide = [a for a in args if a in ("/", "~", str(Path.home()), "$HOME")]
        if wide:
            risk += 2
            findings.append(f"UNSCOPED filesystem access ({wide[0]}) — the server can read everything you can")
        else:
            findings.append("filesystem capability (scoped)")
    for var, val in env.items():
        if SECRET_ENV_RE.search(var) and val:
            risk += 2
            findings.append(f"secret passed in env: {var} ({_shape(str(val))}) — visible to a third-party binary")
    return {"name": name, "command": cmd, "risk": risk,
            "findings": findings, "capabilities": caps}


def audit_config(path: Path) -> dict | None:
    """EN: Parse one MCP config file, score every server.
    FR: parser une config MCP, noter chaque serveur."""
    try:
        data = json.loads(path.read_text(errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None
    servers = data.get("mcpServers") or data.get("mcp", {}).get("servers") or {}
    if not isinstance(servers, dict):
        servers = {}
    # EN: Claude Code nests servers per project — merge them all, tagging the
    #     project so the user knows WHERE the server is active.
    # FR: Claude Code niche les serveurs par projet — tout fusionner en
    #     taguant le projet pour savoir OÙ le serveur est actif.
    projects = data.get("projects")
    if isinstance(projects, dict):
        for proj_path, proj in projects.items():
            if not isinstance(proj, dict):
                continue
            for name, spec in (proj.get("mcpServers") or {}).items():
                if isinstance(spec, dict):
                    spec = dict(spec, _project=proj_path)
                servers.setdefault(f"{name}@{Path(str(proj_path)).name or proj_path}", spec)
    if not servers:
        return None
    scored = []
    for name, spec in servers.items():
        s = score_server(name, spec if isinstance(spec, dict) else {})
        if isinstance(spec, dict) and spec.get("_project"):
            s["project"] = spec["_project"]
        scored.append(s)
    return {"servers": scored}


class McpWatch:
    """EN: Config audit across all known locations. Refreshable.
    FR: audit de toutes les configs connues. Rafraîchissable."""

    def __init__(self, home: Path | None = None) -> None:
        self.home = home or Path.home()
        self._report: dict | None = None

    def scan(self) -> dict:
        clients = {}
        for client, rel in CONFIG_LOCATIONS:
            path = self.home / rel
            if not path.is_file():
                continue
            audited = audit_config(path)
            if audited:
                clients[client] = {"path": str(path), **audited}
        all_servers = [s for c in clients.values() for s in c["servers"]]
        total_risk = sum(s["risk"] for s in all_servers)
        self._report = {
            "clients": clients,
            "servers_total": len(all_servers),
            "high_risk": [s for c in clients.values() for s in c["servers"] if s["risk"] >= 5],
            "total_risk": total_risk,
            "capabilities_seen": sorted({cap for s in all_servers for cap in s["capabilities"]}),
        }
        return self._report

    def status(self) -> dict:
        return self._report or self.scan()
