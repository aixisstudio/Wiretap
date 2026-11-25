"""
EN: Shareable privacy digest — "what did my computer do this week?".
    Aggregates the LOCAL history (traffic, alerts, devices, DNS-firewall
    counters) into a compact report and renders it as a self-contained
    HTML card people can export or screenshot — no external resources,
    no network calls, no tracking. This is the anti-fog weapon: nobody
    else shows the user their own exposure in one honest page.

    Honesty rules:
      * the window is what the retention actually holds (default 24 h —
        the digest says so instead of pretending a week);
      * counters come from the local database only, never estimated;
      * the HTML is fully self-contained (inline CSS, no fonts/CDN).

FR: Digest de confidentialité partageable — « qu'a fait mon ordinateur
    cette semaine ? ». Agrège l'historique LOCAL (trafic, alertes,
    appareils, compteurs du pare-feu DNS) en un rapport compact rendu en
    carte HTML autonome à exporter/capturer — aucune ressource externe,
    aucun appel réseau, aucun tracking. L'arme anti-brouillard : personne
    d'autre ne montre l'exposition réelle en une page honnête.
"""

from __future__ import annotations

import html
import json
import sqlite3
from datetime import datetime, timedelta, timezone

# EN: Wiretap dark palette — same family as the UI.
# FR: palette sombre Wiretap — même famille que l'UI.
_CSS = """
body{margin:0;background:#0b0e14;color:#d5dbe5;font-family:-apple-system,
 'Segoe UI',system-ui,sans-serif;padding:32px;display:flex;justify-content:center}
.card{max-width:640px;width:100%;background:#11151d;border:1px solid #232a38;
 border-radius:14px;padding:28px}
h1{font-size:20px;margin:0 0 4px;letter-spacing:.5px}
.sub{color:#8a93a5;font-size:12px;margin-bottom:20px}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:20px}
.stat{background:#0d1119;border:1px solid #1e2532;border-radius:10px;padding:12px}
.stat .n{font-size:22px;font-weight:600;color:#fff}
.stat .l{font-size:11px;color:#8a93a5;margin-top:2px}
.warn .n{color:#f59e0b}.bad .n{color:#ef4444}.good .n{color:#22c55e}
h2{font-size:13px;color:#8a93a5;text-transform:uppercase;letter-spacing:1px;
 margin:18px 0 8px;border-bottom:1px solid #1e2532;padding-bottom:6px}
table{width:100%;border-collapse:collapse;font-size:12px}
td{padding:5px 4px;border-bottom:1px solid #161c27;color:#c3cad6}
td.num{text-align:right;color:#8a93a5;font-variant-numeric:tabular-nums}
.foot{margin-top:20px;font-size:10px;color:#56607207;color:#566072}
.tag{display:inline-block;background:#1a2230;border-radius:6px;padding:1px 7px;
 font-size:10px;color:#7f9dc9;margin-left:6px}
"""


def _since_iso(minutes: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S")


def collect(conn: sqlite3.Connection, minutes: int,
            dnsfw_stats: dict | None = None) -> dict:
    """EN: Aggregate the digest data from the local DB. Pure read-only.
    FR: Agrège les données du digest depuis la DB locale. Lecture seule."""
    since = _since_iso(minutes)
    out: dict = {"window_minutes": minutes, "since": since}

    row = conn.execute(
        "SELECT COALESCE(SUM(bytes),0), COALESCE(SUM(packets),0) FROM traffic WHERE minute >= ?",
        (since,)).fetchone()
    out["total_bytes"] = int(row[0] or 0)
    out["total_packets"] = int(row[1] or 0)

    out["top_hosts"] = [
        {"key": r[0], "bytes": int(r[1])} for r in conn.execute(
            "SELECT key, SUM(bytes) b FROM history WHERE dim='host' AND minute >= ?"
            " GROUP BY key ORDER BY b DESC LIMIT 10", (since,)).fetchall()
    ]
    out["top_processes"] = [
        {"key": r[0], "bytes": int(r[1])} for r in conn.execute(
            "SELECT key, SUM(bytes) b FROM history WHERE dim='process' AND minute >= ?"
            " GROUP BY key ORDER BY b DESC LIMIT 10", (since,)).fetchall()
    ]
    out["distinct_hosts"] = conn.execute(
        "SELECT COUNT(DISTINCT key) FROM history WHERE dim='host' AND minute >= ?",
        (since,)).fetchone()[0]
    out["distinct_processes"] = conn.execute(
        "SELECT COUNT(DISTINCT key) FROM history WHERE dim='process' AND minute >= ?",
        (since,)).fetchone()[0]

    alerts = conn.execute(
        "SELECT severity, COUNT(*) FROM alerts_log WHERE ts >= ? GROUP BY severity",
        (since,)).fetchall()
    out["alerts_by_severity"] = {r[0]: int(r[1]) for r in alerts}
    out["alerts_total"] = sum(out["alerts_by_severity"].values())
    out["top_alert_types"] = [
        {"key": r[0], "count": int(r[1])} for r in conn.execute(
            "SELECT type, COUNT(*) c FROM alerts_log WHERE ts >= ?"
            " GROUP BY type ORDER BY c DESC LIMIT 5", (since,)).fetchall()
    ]

    out["devices"] = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    out["new_devices"] = conn.execute(
        "SELECT COUNT(*) FROM devices WHERE first_seen >= ?", (since,)).fetchone()[0]

    ds = dnsfw_stats or {}
    out["dnsfw"] = {
        "queries": int(ds.get("queries", 0)),
        "blocked": int(ds.get("blocked", 0)),
        "per_category": ds.get("per_category", {}),
    }
    return out


def human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n/1:.1f} {unit}".replace(".0 ", " ")
        n /= 1024
    return f"{n:.1f} TB"


def render_html(data: dict, app_version: str = "") -> str:
    """EN: Self-contained HTML card — shareable by file, screenshot or print.
    FR: Carte HTML autonome — partageable par fichier, capture ou print."""
    e = html.escape
    hours = data["window_minutes"] // 60
    window = f"{hours} h" if hours < 48 else f"{hours // 24} d"
    sev = data["alerts_by_severity"]
    rows_hosts = "".join(
        f"<tr><td>{e(h['key'])}</td><td class='num'>{human_bytes(h['bytes'])}</td></tr>"
        for h in data["top_hosts"]) or "<tr><td colspan='2'>—</td></tr>"
    rows_procs = "".join(
        f"<tr><td>{e(p['key'])}</td><td class='num'>{human_bytes(p['bytes'])}</td></tr>"
        for p in data["top_processes"]) or "<tr><td colspan='2'>—</td></tr>"
    rows_alerts = "".join(
        f"<tr><td>{e(a['key'])}</td><td class='num'>{a['count']}</td></tr>"
        for a in data["top_alert_types"])
    dnsfw = data["dnsfw"]
    crit = int(sev.get("critical", 0))
    stat_cls = "bad" if crit else ("warn" if data["alerts_total"] else "good")
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Wiretap privacy digest</title><style>{_CSS}</style></head>
<body><div class="card">
<h1>WIRETAP<span class="tag">privacy digest</span></h1>
<div class="sub">{e(data['since'][:10])} → now · window {window} · generated locally, nothing uploaded</div>
<div class="grid">
 <div class="stat"><div class="n">{data['distinct_hosts']}</div><div class="l">servers contacted</div></div>
 <div class="stat"><div class="n">{human_bytes(data['total_bytes'])}</div><div class="l">total traffic</div></div>
 <div class="stat"><div class="n">{data['distinct_processes']}</div><div class="l">processes online</div></div>
 <div class="stat {stat_cls}"><div class="n">{data['alerts_total']}</div><div class="l">alerts ({crit} critical)</div></div>
 <div class="stat good"><div class="n">{dnsfw['blocked']}</div><div class="l">DNS blocked / {dnsfw['queries']} queries</div></div>
 <div class="stat {'warn' if data['new_devices'] else ''}"><div class="n">{data['new_devices']}</div><div class="l">new LAN devices / {data['devices']}</div></div>
</div>
<h2>Top destinations</h2><table>{rows_hosts}</table>
<h2>Top processes</h2><table>{rows_procs}</table>
{"<h2>Top alert types</h2><table>" + rows_alerts + "</table>" if rows_alerts else ""}
<div class="foot">Generated by Wiretap {e(app_version)} — local-first network monitor · github.com/aixisstudio/Wiretap</div>
</div></body></html>"""


def render_text(data: dict) -> str:
    """EN: Plain-text summary for clipboard/Slack-style sharing.
    FR: Résumé texte brut pour partage type presse-papier/Slack."""
    hours = data["window_minutes"] // 60
    window = f"{hours}h" if hours < 48 else f"{hours // 24}d"
    dnsfw = data["dnsfw"]
    lines = [
        f"Wiretap privacy digest ({window})",
        f"  {data['distinct_hosts']} servers contacted · {human_bytes(data['total_bytes'])} traffic · "
        f"{data['distinct_processes']} processes online",
        f"  {data['alerts_total']} alerts ({data['alerts_by_severity'].get('critical', 0)} critical) · "
        f"{dnsfw['blocked']} DNS blocked / {dnsfw['queries']} queries",
        f"  {data['new_devices']} new devices on the LAN ({data['devices']} known)",
        "  top destinations: " + (", ".join(h["key"] for h in data["top_hosts"][:5]) or "—"),
    ]
    return "\n".join(lines)
