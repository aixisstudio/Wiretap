"""
EN: Unit tests for AI traffic governance (detection/aiwatch.py).
FR: Tests unitaires de la gouvernance du trafic IA.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection.aiwatch import AiWatch, match_service, looks_like_mcp


def test_match_service_suffixes():
    assert match_service("api.openai.com") == "openai"
    assert match_service("foo.api.anthropic.com") == "anthropic"
    assert match_service("generativelanguage.googleapis.com") == "google_ai"
    assert match_service("api2.cursor.sh") == "cursor"
    assert match_service("cdn.jsdelivr.net") is None
    assert match_service("") is None
    assert match_service("notopenai.com") is None           # EN: no partial match / FR: pas de match partiel


def test_mcp_detection():
    assert looks_like_mcp("node", "/opt/mcp-server-fs/index.js")
    assert looks_like_mcp("mcp-server-github")
    assert looks_like_mcp("firefox") is False


def test_shadow_ai_alert_once():
    w = AiWatch()
    a1 = w.observe("evilbuild.sh", "api.openai.com", "out", 100)
    assert len(a1) == 1 and a1[0]["type"] == "SHADOW_AI"
    a2 = w.observe("evilbuild.sh", "api.openai.com", "out", 100)
    assert a2 == []                                    # EN: once only / FR: une seule fois


def test_known_client_no_alert():
    w = AiWatch()
    assert w.observe("cursor", "api2.cursor.sh", "out", 100) == []
    assert w.observe("code", "api.openai.com", "out", 100) == []


def test_accounting_rows():
    w = AiWatch()
    w.observe("mycli", "api.anthropic.com", "out", 1000)
    w.observe("mycli", "api.anthropic.com", "out", 500)
    w.observe("mycli", "api.anthropic.com", "in", 3000)
    act = w.activity()
    svc = act["by_service"]["anthropic"]
    assert svc["bytes_out"] == 1500 and svc["bytes_in"] == 3000
    assert "mycli" in svc["processes"]


def test_upload_spike():
    w = AiWatch(upload_spike_mb=1, spike_window_s=3600)
    w.load_known(["bulk"])                              # EN: suppress shadow alert / FR: pas d'alerte shadow
    mb = 1024 * 1024
    for _ in range(5):
        alerts = w.observe("bulk", "api.openai.com", "out", mb // 4)
    types = [a["type"] for a in alerts]
    assert "AI_UPLOAD_SPIKE" in types or any(
        "AI_UPLOAD_SPIKE" in [x["type"] for x in w.observe("bulk", "api.openai.com", "out", mb)] for _ in [0])


def test_mcp_unclassified_row():
    w = AiWatch()
    w.observe("node", "random-cdn.net", "out", 100, exe_path="/mcp/server.js")
    act = w.activity()
    assert "node" in act["mcp_processes"]


def test_disabled_and_reset():
    w = AiWatch()
    w.enabled = False
    assert w.observe("x", "api.openai.com", "out", 10) == []
    w.enabled = True
    w.observe("y", "api.openai.com", "out", 10)
    w.reset_rows()
    assert w.activity()["top_rows"] == []
