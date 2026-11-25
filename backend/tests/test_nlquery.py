"""EN/FR: Tests NL query déterministe."""

import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection.nlquery import answer, parse_window


def _conn():
    c = sqlite3.connect(":memory:")
    c.executescript("""
        CREATE TABLE history (minute TEXT, dim TEXT, key TEXT, packets INTEGER, bytes INTEGER);
        CREATE TABLE alerts_log (id INTEGER PRIMARY KEY, ts TEXT, type TEXT, severity TEXT,
                                 message TEXT, node_id TEXT, details TEXT);
        CREATE TABLE devices (ip TEXT PRIMARY KEY, mac TEXT, vendor TEXT, device_type TEXT,
                              hostname TEXT, private_mac INTEGER, first_seen TEXT, last_seen TEXT);
    """)
    now = "2999-01-01T00:00"
    c.execute("INSERT INTO history VALUES (?, 'process', 'firefox', 1, 5242880)", (now,))
    c.execute("INSERT INTO history VALUES (?, 'process', 'curl', 1, 1048576)", (now,))
    c.execute("INSERT INTO alerts_log VALUES (1, ?, 'C2_BEACON', 'critical', 'c2 detected', '', '{}')", (now + ":00",))
    c.execute("INSERT INTO devices VALUES ('10.0.0.9', NULL, NULL, NULL, 'tv', 0, ?, ?)", (now, now))
    c.commit()
    return c


def test_window_parsing():
    assert parse_window("this week") == 7 * 24 * 60
    assert parse_window("cette semaine") == 7 * 24 * 60
    assert parse_window("today") == 24 * 60
    assert parse_window("whatever") == 24 * 60


def test_top_processes_intent():
    r = answer(_conn(), "what uploaded the most data today")
    assert r["intent"] == "top_processes"
    assert "firefox" in r["answer"]


def test_alerts_intent():
    r = answer(_conn(), "any critical alerts today")
    assert r["intent"] == "alerts" and r["critical"] == 1
    assert "c2 detected" in r["answer"].lower() or "critical" in r["answer"]


def test_devices_intent():
    r = answer(_conn(), "any new devices on my network")
    assert r["intent"] == "devices" and r["new"] == 1


def test_ai_intent():
    r = answer(_conn(), "how much AI traffic", aiwatch_activity={
        "by_service": {"openai": {"service_name": "OpenAI", "bytes_out": 2097152, "processes": ["cursor"]}}})
    assert r["intent"] == "ai" and "OpenAI" in r["answer"]


def test_country_intent_no_hallucination():
    r = answer(_conn(), "did anything talk to russia this week")
    assert r["intent"] == "country" and r["country"] == "RU"
    assert "No alert" in r["answer"]


def test_fallback():
    r = answer(_conn(), "xyzzy blorp")
    assert r["intent"] == "unknown"
