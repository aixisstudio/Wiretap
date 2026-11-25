"""EN/FR: Tests présence/exfiltration."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection.presence import PresenceWatch, classify


def _watch(idle):
    return PresenceWatch("Darwin", idle_probe=lambda s: idle)


def test_classify():
    assert classify(None) == "unknown"
    assert classify(5) == "interactive"
    assert classify(100) == "ambient"
    assert classify(3600) == "unattended"


def test_interactive_never_alerts():
    w = _watch(2.0)
    assert w.grade("cursor", "api.anthropic.com", 5 * 1024 * 1024) is None
    assert w.status()["flow_classes"]["interactive"] == 1


def test_unattended_alerts():
    w = _watch(3600.0)
    a = w.grade("evilbuild", "api.openai.com", 5 * 1024 * 1024)
    assert a is not None
    assert a["type"] == "UNATTENDED_EXFIL"
    assert a["severity"] == "critical"                      # EN: >=1MB / FR: >=1Mo
    assert "away" in a["message"]


def test_unattended_small_volume_warning():
    w = _watch(3600.0)
    a = w.grade("suspect", "x.com", 100 * 1024)
    assert a["severity"] == "warning"


def test_dedup_per_process():
    w = _watch(3600.0)
    w.grade("evil", "x.com", 1024 * 1024)
    assert w.grade("evil", "x.com", 1024 * 1024) is None    # EN: once/hour / FR: une fois/heure


def test_ambient_no_alert_but_counted():
    w = _watch(100.0)
    assert w.grade("x", "y.com", 1024) is None
    assert w.status()["flow_classes"]["ambient"] == 1


def test_unknown_presence_no_alert():
    w = _watch(None)
    assert w.grade("x", "y.com", 10 * 1024 * 1024) is None  # EN: never guesses / FR: ne devine jamais


def test_real_probe_macos():
    from detection.presence import idle_seconds
    v = idle_seconds("Darwin")
    assert v is None or v >= 0                              # EN: real machine probe / FR: sonde réelle
