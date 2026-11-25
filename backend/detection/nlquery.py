"""
EN: Natural-language query over YOUR traffic — "did anything talk to
    Russia this week?" should be a question, not a SQL job. Architecture:

      1. deterministic intent parsing (regex slots: country, process,
         host, timeframe) → answer computed straight from SQLite — always
         works, never hallucinates, zero dependency;
      2. optional LocalSlm pass — when the user runs a local model, the
         STRUCTURED facts are rephrased in natural language; the model
         never invents data, it only narrates what the query layer found.

FR: Requêtes en langage naturel sur VOTRE trafic — « est-ce que quelque
    chose a parlé à la Russie cette semaine ? » doit être une question,
    pas un boulot SQL. Parsing d'intention déterministe → réponse calculée
    depuis SQLite (jamais d'hallucination), puis narration optionnelle par
    le SLM local — le modèle n'invente rien, il raconte les faits trouvés.
"""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timedelta, timezone

# EN: Country aliases → ISO codes present in the geo enrichment cache rows.
# FR: alias de pays → codes ISO.
COUNTRIES = {
    "russia": "RU", "russie": "RU", "china": "CN", "chine": "CN",
    "iran": "IR", "north korea": "KP", "corée du nord": "KP",
    "usa": "US", "united states": "US", "états-unis": "US", "france": "FR",
    "germany": "DE", "allemagne": "DE", "uk": "GB", "royaume-uni": "GB",
    "netherlands": "NL", "pays-bas": "NL", "ukraine": "UA", "india": "IN",
    "inde": "IN", "brazil": "BR", "brésil": "BR", "japan": "JP", "japon": "JP",
}

WINDOWS = [
    (re.compile(r"\b(week|semaine)\b", re.I), 7 * 24 * 60),
    (re.compile(r"\b(month|mois)\b", re.I), 30 * 24 * 60),
    (re.compile(r"\btoday|aujourd", re.I), 24 * 60),
    (re.compile(r"\bhour|heure\b", re.I), 60),
]


def parse_window(q: str) -> int:
    for pat, minutes in WINDOWS:
        if pat.search(q):
            return minutes
    return 24 * 60                                    # EN: default 24h / FR: défaut 24h


def _since(minutes: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M")


def answer(conn: sqlite3.Connection, question: str,
           alerts: list[dict] | None = None,
           aiwatch_activity: dict | None = None) -> dict:
    """EN: Deterministic answerer. Returns {answer, facts, intent}.
    FR: répondeur déterministe. Renvoie {answer, facts, intent}."""
    q = question.lower().strip()
    minutes = parse_window(q)
    since = _since(minutes)
    facts: dict = {"window_minutes": minutes}

    # ── intent: country traffic / trafic par pays ──────────────────────────
    for name, code in COUNTRIES.items():
        if name in q:
            rows = conn.execute(
                "SELECT key, SUM(bytes) b FROM history WHERE dim='host'"
                " AND minute >= ? GROUP BY key ORDER BY b DESC", (since,)).fetchall()
            # EN: geo country lives in the enrichment cache, not the DB —
            #     match on suffix in details when alerts carry it, else answer
            #     honestly that per-country history is not queryable yet for hosts.
            # FR: le pays geo vit dans le cache d'enrichissement.
            country_alerts = [a for a in (alerts or [])
                              if (a.get("details") or {}).get("country_code") == code
                              or (a.get("details") or {}).get("country") == code]
            facts.update(intent="country", country=code,
                         alerts=len(country_alerts),
                         hosts_checked=len(rows))
            if country_alerts:
                facts["answer"] = (f"Yes — {len(country_alerts)} alert(s) involving {code} "
                                   f"in the window. Latest: {country_alerts[0].get('message', '')[:120]}")
            else:
                facts["answer"] = (f"No alert involving {code} in the last "
                                   f"{minutes // 60}h. Note: per-country host history is "
                                   f"tracked via alerts/enrichment, not raw flows.")
            return facts

    # ── intent: biggest uploader / plus gros uploadeur ─────────────────────
    if re.search(r"upload|envoy|most data|plus de don|biggest|top\b", q):
        rows = conn.execute(
            "SELECT key, SUM(bytes) b FROM history WHERE dim='process'"
            " AND minute >= ? GROUP BY key ORDER BY b DESC LIMIT 5", (since,)).fetchall()
        facts.update(intent="top_processes",
                     top=[{"process": r[0], "bytes": r[1]} for r in rows])
        if rows:
            def mb(n): return f"{n / (1024 * 1024):.1f} MB"
            facts["answer"] = (f"Top processes in the window: "
                               + ", ".join(f"{r[0]} ({mb(r[1])})" for r in rows))
        else:
            facts["answer"] = "No process traffic recorded in the window."
        return facts

    # ── intent: AI traffic / trafic IA ─────────────────────────────────────
    if re.search(r"\b(ai|ia|openai|anthropic|llm|model|claude|gpt)\b", q):
        aw = aiwatch_activity or {}
        svcs = aw.get("by_service") or {}
        facts.update(intent="ai",
                     services={k: v["bytes_out"] for k, v in svcs.items()})
        if svcs:
            parts = [f"{v['service_name']}: {v['bytes_out'] / (1024 * 1024):.2f} MB up"
                     for v in sorted(svcs.values(), key=lambda x: -x["bytes_out"])]
            facts["answer"] = "AI provider traffic: " + "; ".join(parts)
        else:
            facts["answer"] = "No AI provider traffic observed."
        return facts

    # ── intent: critical alerts / alertes critiques ────────────────────────
    if re.search(r"critical|critique|alert|danger|threat|menace", q):
        rows = conn.execute(
            "SELECT type, severity, message, ts FROM alerts_log"
            " WHERE ts >= ? ORDER BY ts DESC LIMIT 10", (since,)).fetchall()
        crit = [r for r in rows if r[1] == "critical"]
        facts.update(intent="alerts", total=len(rows), critical=len(crit),
                     latest=[{"type": r[0], "severity": r[1], "message": r[2][:100]} for r in rows[:5]])
        facts["answer"] = (f"{len(rows)} alert(s) in the window, {len(crit)} critical."
                           + (f" Latest critical: {crit[0][2][:120]}" if crit else ""))
        return facts

    # ── intent: new devices / nouveaux appareils ───────────────────────────
    if re.search(r"device|appareil|nouveau|new\b|lan|network", q):
        n = conn.execute("SELECT COUNT(*) FROM devices WHERE first_seen >= ?", (since,)).fetchone()[0]
        tot = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        facts.update(intent="devices", new=n, total=tot)
        facts["answer"] = f"{n} new device(s) joined the LAN in the window ({tot} known total)."
        return facts

    # ── fallback / repli ───────────────────────────────────────────────────
    facts.update(intent="unknown")
    facts["answer"] = ("I can answer: traffic by country, top uploading processes, "
                       "AI provider activity, alerts/critical events, new LAN devices. "
                       "Try: 'did anything talk to Russia this week?'")
    return facts
