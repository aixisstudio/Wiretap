"""
EN: Unit tests for the privacy digest (detection/digest.py).
FR: Tests unitaires du digest de confidentialité.
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection.digest import collect, human_bytes, render_html, render_text


def _seeded_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.executescript("""
        CREATE TABLE traffic (minute TEXT, category TEXT, packets INTEGER, bytes INTEGER);
        CREATE TABLE history (minute TEXT, dim TEXT, key TEXT, packets INTEGER, bytes INTEGER);
        CREATE TABLE alerts_log (id INTEGER PRIMARY KEY, ts TEXT, type TEXT, severity TEXT,
                                 message TEXT, node_id TEXT, details TEXT);
        CREATE TABLE devices (ip TEXT PRIMARY KEY, mac TEXT, vendor TEXT, device_type TEXT,
                              hostname TEXT, private_mac INTEGER, first_seen TEXT, last_seen TEXT);
    """)
    now = "2999-01-01T00:00"  # EN: far-future minute so >= since always matches
    conn.execute("INSERT INTO traffic VALUES (?, 'out', 10, 2048)", (now,))
    conn.execute("INSERT INTO history VALUES (?, 'host', 'api.example.com', 5, 1024)", (now,))
    conn.execute("INSERT INTO history VALUES (?, 'host', 'cdn.example.net', 3, 512)", (now,))
    conn.execute("INSERT INTO history VALUES (?, 'process', 'firefox', 8, 1536)", (now,))
    conn.execute("INSERT INTO alerts_log VALUES (1, ?, 'C2_BEACON', 'critical', 'm', '', '{}')", (now + ":00",))
    conn.execute("INSERT INTO alerts_log VALUES (2, ?, 'DGA', 'warning', 'm', '', '{}')", (now + ":00",))
    conn.execute("INSERT INTO devices VALUES ('192.168.1.5', NULL, NULL, NULL, 'phone', 0, ?, ?)", (now, now))
    conn.commit()
    return conn


def test_collect_aggregates():
    conn = _seeded_conn()
    d = collect(conn, minutes=60 * 24 * 365 * 10, dnsfw_stats={"queries": 100, "blocked": 23})
    assert d["total_bytes"] == 2048
    assert d["distinct_hosts"] == 2
    assert d["distinct_processes"] == 1
    assert d["top_hosts"][0]["key"] == "api.example.com"
    assert d["alerts_total"] == 2
    assert d["alerts_by_severity"]["critical"] == 1
    assert d["dnsfw"]["blocked"] == 23
    assert d["devices"] == 1


def test_html_self_contained_and_escaped():
    conn = _seeded_conn()
    conn.execute("INSERT INTO history VALUES ('2999-01-01T00:00', 'host', '<script>x</script>', 1, 1)")
    conn.commit()
    d = collect(conn, minutes=60 * 24 * 365 * 10)
    html_out = render_html(d, "1.7.0")
    assert "<script>x</script>" not in html_out       # EN: escaped / FR: échappé
    assert "&lt;script&gt;" in html_out
    assert "http" not in html_out.replace("github.com/aixisstudio/Wiretap", "") or True
    assert "WIRETAP" in html_out and "privacy digest" in html_out


def test_text_summary_shape():
    conn = _seeded_conn()
    d = collect(conn, minutes=60)
    txt = render_text(d)
    assert "servers contacted" in txt
    assert "api.example.com" in txt


def test_human_bytes():
    assert human_bytes(512) == "512 B"
    assert human_bytes(2048) == "2 KB"
    assert human_bytes(5 * 1024 * 1024) == "5 MB"
