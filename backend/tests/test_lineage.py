"""EN/FR: Tests verdicts de lignée."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection.lineage import LineageWatch, score_chain, walk_chain


def test_walk_chain():
    table = {100: (50, "python"), 50: (10, "sh"), 10: (1, "chrome"), 1: (0, "launchd")}
    assert walk_chain(100, table) == ["python", "sh", "chrome", "launchd"]


def test_walk_cycle_safe():
    table = {1: (2, "a"), 2: (1, "b")}
    chain = walk_chain(1, table)
    assert len(chain) <= 2


def test_score_browser_shell_chain():
    score, reasons = score_chain(["evil", "sh", "curl", "chrome", "launchd"])
    # EN: +2 interpreter(sh/curl? sh yes), +2 content root chrome... root is launchd though.
    assert score >= 2


def test_score_system_daemon_low():
    score, _ = score_chain(["daemon", "launchd"])
    assert score < 4


def test_score_deep_interpreter_chain_high():
    score, reasons = score_chain(["evil.bin", "node", "sh", "zsh", "iterm", "launchd"])
    assert score >= 4
    assert any("interpreter" in r or "shell" in r for r in reasons)


def test_verdict_fires_once_per_signature():
    table = {100: (50, "evil.bin"), 50: (10, "node"), 10: (5, "sh"), 5: (1, "iterm"), 1: (0, "launchd")}
    w = LineageWatch(table_probe=lambda: table)
    a = w.verdict(100, "evil.bin")
    assert a is not None and a["type"] == "LINEAGE_SUSPECT"
    assert a["details"]["score"] >= 4
    # EN: reset cache, same chain -> no duplicate / FR: même chaîne = pas de doublon
    w2 = LineageWatch(table_probe=lambda: table)
    a2 = w2.verdict(100, "evil.bin")
    assert a2 is not None                                 # EN: new watcher fires / FR: nouveau watcher tire
    assert w.verdict(100, "evil.bin") is None             # EN: same watcher dedupes / FR: dédup


def test_dead_pid_no_crash():
    w = LineageWatch(table_probe=dict)
    assert w.verdict(999999, "ghost") is None
