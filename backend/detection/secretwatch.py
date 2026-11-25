"""
EN: Secrets egress watch — local DLP for the AI era. Two honest signals:

      1. PLAINTEXT LEAK: registered secrets (API keys/tokens harvested
         LOCALLY from env vars and standard dotfiles) are scanned against
         outbound plaintext payloads. If your AWS key crosses the wire in
         the clear, that is a critical fact — whoever sent it.
      2. AI ENDPOINT CORRELATION: a process whose environment CONTAINS
         registered secrets is flagged when it uploads to an AI provider.
         TLS hides the content, but "this agent holds your keys AND talks
         to a model API" is exactly the exfiltration precondition — the
         user decides what to do with that knowledge.

    Privacy construction: secret VALUES never appear in logs, alerts,
    the API or persistence — only salted hashes and redacted shapes
    (sk-…xxxx). Registration is opt-in scanning of the user's own
    machine; nothing is ever transmitted anywhere.

FR: Veille d'exfiltration de secrets — DLP local pour l'ère IA. Deux
    signaux honnêtes : fuite en clair (scan des payloads plaintext
    sortants contre les secrets enregistrés) et corrélation endpoint IA
    (processus dont l'environnement contient des secrets ET qui uploade
    vers une API IA). Les VALEURS n'apparaissent jamais nulle part —
    hashes salés et formes masquées seulement. Rien n'est transmis.
"""

from __future__ import annotations

import hashlib
import os
import re
import threading
from pathlib import Path

# EN: Well-known secret shapes — prefix + rough length. Used both to find
#     candidates in env/dotfiles and to report redacted shapes.
# FR: Formes de secrets connues — préfixe + longueur approximative.
SECRET_PATTERNS = [
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("openai_key",     re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("anthropic_key",  re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("github_token",   re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    ("gitlab_token",   re.compile(r"\bglpat-[A-Za-z0-9_-]{15,}\b")),
    ("slack_token",    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    ("stripe_key",     re.compile(r"\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("huggingface",    re.compile(r"\bhf_[A-Za-z0-9]{25,}\b")),
    ("generic_secret", re.compile(r"\b[A-Za-z0-9_-]{32,64}\b")),  # EN: only in KEY-ish env vars / FR: vars env à nom suspect
]

# EN: Env var names whose values are harvested even without a known prefix.
# FR: noms de vars env récoltés même sans préfixe connu.
SECRET_ENV_HINTS = ("_KEY", "_TOKEN", "_SECRET", "PASSWORD", "APIKEY", "API_KEY")

# EN: dotfiles scanned (small, user-owned, never followed outside $HOME).
# FR: dotfiles scannés (petits, à l'utilisateur, jamais hors $HOME).
DOTFILES = (".aws/credentials", ".config/gcloud/credentials.db",
            ".env", ".netrc", ".huggingface/token")

_SALT = b"wiretap-secretwatch-v1"


def _hash(value: str) -> str:
    return hashlib.sha256(_SALT + value.encode()).hexdigest()


def _shape(value: str) -> str:
    """EN: Redacted shape safe for alerts — `sk-…xxxx` style.
    FR: forme masquée sûre pour les alertes."""
    if len(value) <= 8:
        return "…"
    return f"{value[:3]}…{value[-4:]}"


def harvest(env: dict | None = None, home: Path | None = None) -> dict[str, list[dict]]:
    """EN: Harvest secrets from env vars and standard dotfiles. Returns
    {hash: [{kind, shape, source}]} — never the values themselves.
    FR: récolte les secrets depuis env et dotfiles. Renvoie {hash: [...]}
    — jamais les valeurs."""
    env = dict(os.environ if env is None else env)
    home = Path.home() if home is None else home
    found: dict[str, list[dict]] = {}

    def _add(value: str, kind: str, source: str) -> None:
        h = _hash(value)
        entry = {"kind": kind, "shape": _shape(value), "source": source}
        if h not in found:
            found[h] = {**entry, "value": value}   # EN: value stays in RAM only / FR: valeur en RAM seulement

    for name, val in env.items():
        if len(val) < 12:
            continue
        for kind, pat in SECRET_PATTERNS:
            m = pat.search(val)
            if m and (kind != "generic_secret"
                      or any(hint in name.upper() for hint in SECRET_ENV_HINTS)):
                _add(m.group(0), kind, f"env:{name}")
                break

    for rel in DOTFILES:
        try:
            p = home / rel
            if p.is_file() and p.stat().st_size < 256 * 1024:
                text = p.read_text(errors="replace")
                for kind, pat in SECRET_PATTERNS[:-1]:   # EN: no generic in dotfiles / FR: pas de générique
                    for m in pat.finditer(text):
                        _add(m.group(0), kind, f"file:{rel}")
        except OSError:
            continue
    return found


class SecretWatch:
    """EN: Lock-guarded registry + scanner. `register()` loads the harvest;
    `scan_payload()` matches outbound plaintext; `correlate()` answers
    whether a process environment holds any registered secret.
    FR: registre + scanner protégés par verrou."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._secrets: dict[str, dict] = {}       # EN: hash -> meta(+value in RAM) / FR: hash -> méta
        self.enabled = True
        self._correlation_alerted: set[str] = set()

    def register(self, env: dict | None = None, home: Path | None = None) -> int:
        harvested = harvest(env=env, home=home)
        with self._lock:
            for h, meta in harvested.items():
                self._secrets[h] = meta
            return len(self._secrets)

    def status(self) -> dict:
        """EN: API-safe state — NO values, shapes + kinds + sources only.
        FR: état sûr pour l'API — PAS de valeurs, formes/kinds/sources."""
        with self._lock:
            by_kind: dict[str, int] = {}
            for meta in self._secrets.values():
                by_kind[meta["kind"]] = by_kind.get(meta["kind"], 0) + 1
            return {
                "enabled": self.enabled,
                "registered": len(self._secrets),
                "by_kind": by_kind,
                "sources": sorted({m["source"].split(":")[0] for m in self._secrets.values()}),
            }

    def scan_payload(self, payload: bytes, process_name: str,
                     remote: str) -> list[dict]:
        """EN: Scan an outbound PLAINTEXT payload for registered secrets.
        Returns critical alerts — values are never embedded, shapes only.
        FR: scanne un payload plaintext sortant. Renvoie des alertes
        critiques — jamais les valeurs, les formes seulement."""
        if not self.enabled or not payload:
            return []
        alerts = []
        with self._lock:
            items = list(self._secrets.items())
        for h, meta in items:
            val = meta.get("value", "")
            if len(val) >= 12 and val.encode() in payload:
                alerts.append({
                    "type": "SECRET_PLAINTEXT_LEAK",
                    "severity": "critical",
                    "message": f"{meta['kind']} ({meta['shape']}) sent in PLAINTEXT "
                               f"by {process_name or 'unknown'} to {remote} — rotate this secret now",
                    "details": {"kind": meta["kind"], "shape": meta["shape"],
                                "process": process_name, "remote": remote,
                                "source": meta["source"]},
                })
        return alerts

    def correlate_ai(self, process_name: str, pid: int,
                     service_name: str) -> dict | None:
        """EN: If the process environment holds registered secrets and the
        process uploads to an AI provider, emit a warning once per process.
        FR: si l'env du processus contient des secrets enregistrés et qu'il
        uploade vers une API IA, alerte warning une fois par processus."""
        if not self.enabled or not pid:
            return None
        proc_key = process_name.lower()
        with self._lock:
            if proc_key in self._correlation_alerted:
                return None
            hashes = dict(self._secrets)
        if not hashes:
            return None
        try:
            env_text = Path(f"/proc/{pid}/environ").read_bytes().decode(errors="replace") \
                if os.name != "nt" else ""
        except OSError:
            env_text = ""
        if os.name == "nt" or not env_text:
            return None                     # EN: honest degradation / FR: dégradation honnête
        hits = []
        for h, meta in hashes.items():
            if meta.get("value") and meta["value"] in env_text:
                hits.append(meta)
        if not hits:
            return None
        with self._lock:
            self._correlation_alerted.add(proc_key)
        kinds = ", ".join(sorted({m["kind"] for m in hits}))
        return {
            "type": "AI_SECRET_EXPOSURE",
            "severity": "warning",
            "message": f"{process_name} holds {len(hits)} registered secret(s) ({kinds}) "
                       f"AND talks to {service_name} — verify this AI tool should have that access",
            "details": {"process": process_name, "pid": pid,
                        "service": service_name,
                        "kinds": sorted({m["kind"] for m in hits}),
                        "count": len(hits)},
        }
