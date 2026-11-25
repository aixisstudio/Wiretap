"""EN/FR: tests MCP governance."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection.mcpwatch import McpWatch, score_server, capabilities_for


def test_capabilities():
    assert "shell" in capabilities_for("shell-exec", [])
    assert "filesystem" in capabilities_for("filesystem", ["serve"])
    assert "browser" in capabilities_for("x", ["playwright-mcp"])
    assert capabilities_for("random", []) == []


def test_score_download_and_run():
    r = score_server("x", {"command": "npx", "args": ["-y", "some-mcp"]})
    assert r["risk"] >= 2
    assert any("download-and-run" in f for f in r["findings"])


def test_score_unscoped_fs_and_secrets():
    r = score_server("filesystem", {
        "command": "npx", "args": ["fs-mcp", "/"],
        "env": {"API_KEY": "sk-1234567890abcd"}})
    assert r["risk"] >= 5
    assert any("UNSCOPED" in f for f in r["findings"])
    assert any("secret passed" in f for f in r["findings"])
    # EN: secret value never in findings, shape only / FR: jamais la valeur
    assert not any("sk-1234567890abcd" in f for f in r["findings"])


def test_benign_server_low_risk():
    r = score_server("time", {"command": "python", "args": ["-m", "time_mcp"]})
    assert r["risk"] == 0


def test_scan_with_fixture_home(tmp_path):
    cfg = tmp_path / ".cursor"
    cfg.mkdir()
    (cfg / "mcp.json").write_text(json.dumps({"mcpServers": {
        "fs": {"command": "npx", "args": ["fs-mcp", "/"]}}}))
    w = McpWatch(home=tmp_path)
    report = w.scan()
    assert report["servers_total"] == 1
    assert len(report["high_risk"]) == 1
    assert "filesystem" in report["capabilities_seen"]


def test_scan_empty_home(tmp_path):
    w = McpWatch(home=tmp_path)
    report = w.scan()
    assert report["servers_total"] == 0
    assert report["clients"] == {}
