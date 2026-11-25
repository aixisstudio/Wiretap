"""
EN: AI traffic governance — the blind spot nobody watches. Since agents,
    copilots and MCP servers became everyday software, the sensitive
    question changed: not just "who does my computer talk to" but "which
    AI tools ship what data to which model providers". Wiretap answers it
    locally:

      * AI endpoint registry — curated suffix-matched domains of the major
        model providers and agent platforms (OpenAI, Anthropic, Google,
        Mistral, xAI, DeepSeek, Cursor, Copilot, Hugging Face...);
      * per (service, process) byte accounting — "Cursor uploaded 2.3 MB
        to api.anthropic.com today" becomes a fact, not a guess;
      * SHADOW_AI alert — the FIRST time a process is seen talking to an
        AI endpoint. A build tool, a shell or a random binary reaching
        OpenAI is exactly the signal a supply-chain/prompt-injection
        incident produces;
      * AI_UPLOAD_SPIKE — upload volume to AI endpoints crossing a
        configurable threshold inside an hour (mass export pattern:
        scraping your codebase/documents into a model);
      * MCP watch — processes that look like MCP servers (name or path)
        get their own accounting row, because local MCP servers run with
        user privileges and are the new plugin attack surface.

    Everything is metadata-only (destinations, volumes, process names) —
    Wiretap never inspects payload content, and nothing leaves the machine.

FR: Gouvernance du trafic IA — l'angle mort que personne ne surveille.
    Depuis que agents, copilotes et serveurs MCP sont des logiciels
    quotidiens, la question sensible a changé : pas seulement « à qui
    parle mon ordinateur » mais « quels outils IA envoient quelles
    données vers quels fournisseurs de modèles ». Wiretap y répond en
    local : registre d'endpoints IA, comptage par (service, processus),
    alerte SHADOW_AI à la première connexion d'un processus vers une API
    IA, AI_UPLOAD_SPIKE sur pic de volume, et comptabilité dédiée des
    serveurs MCP. Métadonnées uniquement — jamais le contenu, rien ne
    sort de la machine.
"""

from __future__ import annotations

import threading
import time

# EN: Curated registry — suffix-matched. Keeping it small and honest: only
#     first-party provider/agent domains, no CDNs shared with unrelated apps.
# FR: Registre curé — match par suffixe. Petit et honnête volontairement :
#     domaines first-party seulement, pas de CDN partagés.
AI_SERVICES: dict[str, dict] = {
    "openai":      {"name": "OpenAI", "domains": ["api.openai.com", "chatgpt.com", "openai.com", "oaiusercontent.com"]},
    "anthropic":   {"name": "Anthropic", "domains": ["api.anthropic.com", "claude.ai", "anthropic.com"]},
    "google_ai":   {"name": "Google AI", "domains": ["generativelanguage.googleapis.com", "aiplatform.googleapis.com", "gemini.google.com"]},
    "mistral":     {"name": "Mistral", "domains": ["api.mistral.ai", "mistral.ai"]},
    "xai":         {"name": "xAI", "domains": ["api.x.ai"]},
    "deepseek":    {"name": "DeepSeek", "domains": ["api.deepseek.com", "deepseek.com"]},
    "cohere":      {"name": "Cohere", "domains": ["api.cohere.com", "cohere.ai"]},
    "groq":        {"name": "Groq", "domains": ["api.groq.com"]},
    "together":    {"name": "Together", "domains": ["api.together.xyz", "together.ai"]},
    "fireworks":   {"name": "Fireworks", "domains": ["api.fireworks.ai", "fireworks.ai"]},
    "replicate":   {"name": "Replicate", "domains": ["api.replicate.com", "replicate.com"]},
    "huggingface": {"name": "Hugging Face", "domains": ["huggingface.co", "api-inference.huggingface.co", "hf.co"]},
    "perplexity":  {"name": "Perplexity", "domains": ["api.perplexity.ai", "perplexity.ai"]},
    "copilot":     {"name": "Microsoft Copilot", "domains": ["copilot.microsoft.com", "api.githubcopilot.com", "copilot-proxy.githubusercontent.com"]},
    "cursor":      {"name": "Cursor", "domains": ["api2.cursor.sh", "api3.cursor.sh", "cursor.sh", "repo42.cursor.sh"]},
    "stability":   {"name": "Stability AI", "domains": ["api.stability.ai", "stability.ai"]},
    "elevenlabs":  {"name": "ElevenLabs", "domains": ["api.elevenlabs.io", "elevenlabs.io"]},
    "openrouter":  {"name": "OpenRouter", "domains": ["openrouter.ai"]},
    "bedrock":     {"name": "AWS Bedrock", "domains": ["bedrock-runtime.amazonaws.com"]},
    "azure_openai": {"name": "Azure OpenAI", "domains": ["openai.azure.com"]},
    "cognition":   {"name": "Cognition", "domains": ["devin.ai", "api.devin.ai"]},
}

# EN: Processes that are EXPECTED AI clients — IDEs/agents/CLIs. Anything
#     not in this list talking to an AI endpoint is more suspicious.
# FR: Processus clients IA ATTENDUS — IDE/agents/CLI. Tout ce qui n'y est
#     pas et parle à une API IA est plus suspect.
KNOWN_AI_CLIENTS = {
    "cursor", "code", "code - insiders", "windsurf", "zed", "copilot",
    "claude", "claude-code", "aider", "continue", "cody", "tabnine",
    "devin", "codeium", "supermaven", "kiro", "trae", "void",
}

# EN: MCP server process hints — matching lowercased exe name/path fragments.
# FR: Indices de processus serveur MCP — fragments de nom/chemin en minuscules.
MCP_HINTS = ("mcp-server", "mcp_server", "-mcp", "mcp@",
             "modelcontextprotocol", "/mcp/", "\\mcp\\")


def match_service(hostname: str) -> str | None:
    """EN: Registry key whose domain suffix matches, or None.
    FR: clé du registre dont le suffixe matche, ou None."""
    if not hostname:
        return None
    h = hostname.lower().rstrip(".")
    for key, svc in AI_SERVICES.items():
        for dom in svc["domains"]:
            if h == dom or h.endswith("." + dom):
                return key
    return None


def looks_like_mcp(process_name: str, exe_path: str = "") -> bool:
    hay = f"{process_name or ''} {exe_path or ''}".lower()
    return any(hint in hay for hint in MCP_HINTS)


class AiWatch:
    """EN: Lock-guarded observer — fed one packet at a time from the capture
    loop, keeps per (service, process) counters and emits alert dicts for
    first-contact and upload spikes. / FR: Observateur protégé par verrou —
    alimenté paquet par paquet depuis la boucle de capture, garde les
    compteurs par (service, processus) et émet des alertes."""

    def __init__(self, upload_spike_mb: float = 50.0,
                 spike_window_s: int = 3600) -> None:
        self._lock = threading.Lock()
        # EN: (service, process) -> accounting row / FR: ligne de comptage
        self._rows: dict[tuple[str, str], dict] = {}
        self._known_clients: set[str] = set()    # EN: processes already alerted / FR: déjà alertés
        self.upload_spike_mb = upload_spike_mb
        self.spike_window_s = spike_window_s
        self._spike_window_start = time.time()
        self._spike_bytes = 0
        self._spike_alerted_at = 0.0
        self.enabled = True

    # ── observation / observation ───────────────────────────────────────────

    def observe(self, process_name: str, hostname: str,
                direction: str, size: int,
                exe_path: str = "") -> list[dict]:
        """EN: Feed one flow observation. Returns zero or more alert dicts.
        FR: alimenter une observation. Renvoie zéro ou plusieurs alertes."""
        if not self.enabled or not process_name:
            return []
        svc_key = match_service(hostname or "")
        proc = process_name.lower()
        is_mcp = looks_like_mcp(process_name, exe_path)
        if not svc_key and not is_mcp:
            return []
        alerts: list[dict] = []
        now = time.time()
        with self._lock:
            if svc_key:
                key = (svc_key, proc)
                row = self._rows.setdefault(key, {
                    "service": svc_key, "service_name": AI_SERVICES[svc_key]["name"],
                    "process": process_name, "bytes_out": 0, "bytes_in": 0,
                    "first_seen": now, "last_seen": now, "mcp": is_mcp,
                })
                row["last_seen"] = now
                if direction == "out":
                    row["bytes_out"] += size
                    self._spike_bytes += size
                else:
                    row["bytes_in"] += size

                # EN: SHADOW_AI — first contact of an unknown process with an
                #     AI endpoint. Known AI clients only alert when MCP-shaped.
                # FR: SHADOW_AI — premier contact d'un processus inconnu avec
                #     un endpoint IA. Les clients connus n'alertent que si MCP.
                known = proc in KNOWN_AI_CLIENTS or any(
                    proc.startswith(k) for k in KNOWN_AI_CLIENTS)
                if proc not in self._known_clients and not known:
                    self._known_clients.add(proc)
                    alerts.append({
                        "type": "SHADOW_AI",
                        "severity": "warning",
                        "message": f"{process_name} contacted "
                                   f"{AI_SERVICES[svc_key]['name']} for the first time — "
                                   f"verify this AI usage is expected",
                        "details": {"process": process_name, "service": svc_key,
                                    "hostname": hostname, "mcp": is_mcp},
                    })
                else:
                    self._known_clients.add(proc)

                # EN: AI_UPLOAD_SPIKE — sliding window volume check.
                # FR: AI_UPLOAD_SPIKE — vérif du volume sur fenêtre glissante.
                if now - self._spike_window_start > self.spike_window_s:
                    self._spike_window_start = now
                    self._spike_bytes = size if direction == "out" else 0
                    self._spike_alerted_at = 0.0
                elif (self._spike_bytes > self.upload_spike_mb * 1024 * 1024
                      and now - self._spike_alerted_at > self.spike_window_s):
                    self._spike_alerted_at = now
                    mb = self._spike_bytes / (1024 * 1024)
                    alerts.append({
                        "type": "AI_UPLOAD_SPIKE",
                        "severity": "critical",
                        "message": f"{mb:.0f} MB uploaded to AI services in the last hour — "
                                   f"mass export pattern (codebase/documents into a model?)",
                        "details": {"mb": round(mb, 1),
                                    "window_s": self.spike_window_s},
                    })
            elif is_mcp and direction == "out":
                # EN: MCP-shaped process talking anywhere — row without service.
                # FR: processus MCP qui parle — ligne sans service.
                key = ("(mcp-unclassified)", proc)
                row = self._rows.setdefault(key, {
                    "service": "(mcp-unclassified)", "service_name": "Unclassified (MCP)",
                    "process": process_name, "bytes_out": 0, "bytes_in": 0,
                    "first_seen": now, "last_seen": now, "mcp": True,
                })
                row["last_seen"] = now
                row["bytes_out"] += size
        return alerts

    # ── state / état ────────────────────────────────────────────────────────

    def load_known(self, procs: list[str]) -> None:
        with self._lock:
            self._known_clients.update(p.lower() for p in procs)

    def dump_known(self) -> list[str]:
        with self._lock:
            return sorted(self._known_clients)

    def reset_rows(self) -> None:
        """EN: Drop accounting rows (privacy-respecting reset). FR: purge."""
        with self._lock:
            self._rows.clear()

    def activity(self) -> dict:
        """EN: Snapshot for the API — rows sorted by upload volume.
        FR: instantané pour l'API — lignes triées par volume uploadé."""
        with self._lock:
            rows = sorted(self._rows.values(),
                          key=lambda r: r["bytes_out"], reverse=True)
            by_service: dict[str, dict] = {}
            for r in rows:
                if r["service"] == "(mcp-unclassified)":
                    continue
                s = by_service.setdefault(r["service"], {
                    "service_name": r["service_name"], "bytes_out": 0,
                    "bytes_in": 0, "processes": set()})
                s["bytes_out"] += r["bytes_out"]
                s["bytes_in"] += r["bytes_in"]
                s["processes"].add(r["process"])
            for s in by_service.values():
                s["processes"] = sorted(s["processes"])
            mcp_rows = [r for r in rows if r["mcp"]]
            return {
                "enabled": self.enabled,
                "services_tracked": len(by_service),
                "by_service": by_service,
                "top_rows": [{**r, "first_seen": round(r["first_seen"], 1),
                              "last_seen": round(r["last_seen"], 1)}
                             for r in rows[:50]],
                "mcp_processes": sorted({r["process"] for r in mcp_rows}),
                "registry_size": len(AI_SERVICES),
                "upload_spike_mb": self.upload_spike_mb,
            }
