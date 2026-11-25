"""EN/FR: tests persistence watch."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection.perswatch import PersistenceWatch, score_entry, collect_macos


def _collector(entries):
    """EN: mutable fixture collector / FR: collecteur fixture mutable"""
    return lambda: dict(entries)


def _mk(entries, eid, target="/usr/bin/ssh", content=b"x"):
    entries[eid] = {"id": eid, "kind": "user-agent", "target": target,
                    "label": eid, "content_hash": content.hex()[:4] + str(len(content)),
                    "target_hash": "", "run_at_load": True,
                    "keep_alive": False, "mtime": 1.0}


def test_first_scan_silent():
    e = {}
    _mk(e, "a:com.test.plist")
    w = PersistenceWatch(system="Darwin", collector=_collector(e))
    assert w.scan() == []
    assert w._baseline is not None


def test_new_entry_alert():
    e = {}
    _mk(e, "a:com.test.plist")
    box = dict(e)
    w = PersistenceWatch(system="Darwin", collector=lambda: {k: dict(v) for k, v in box.items()})
    w.scan()
    _mk(box, "a:com.evil.plist", target="/tmp/evil")
    alerts = w.scan()
    assert len(alerts) == 1
    assert alerts[0]["type"] == "PERSISTENCE_NEW"
    assert alerts[0]["severity"] == "critical"   # /tmp target = risk 3
    assert "evil" in alerts[0]["details"]["target"]


def test_modified_entry_alert():
    e = {}
    _mk(e, "a:com.test.plist")
    box = dict(e)
    w = PersistenceWatch(system="Darwin", collector=lambda: {k: dict(v) for k, v in box.items()})
    w.scan()
    box["a:com.test.plist"]["content_hash"] = "changed"
    alerts = w.scan()
    assert any(a["type"] == "PERSISTENCE_MOD" for a in alerts)


def test_deleted_entry_alert():
    e = {}
    _mk(e, "a:com.test.plist")
    box = dict(e)
    w = PersistenceWatch(system="Darwin", collector=lambda: {k: dict(v) for k, v in box.items()})
    w.scan()
    box.clear()
    alerts = w.scan()
    assert any(a["type"] == "PERSISTENCE_DEL" for a in alerts)


def test_scoring(monkeypatch):
    r, f = score_entry({"target": "/var/folders/x/malware", "run_at_load": True, "keep_alive": True})
    assert r >= 4
    r2, _ = score_entry({"target": "/bin/bash", "run_at_load": False, "keep_alive": False})
    assert r2 >= 2                         # interpreter
    # EN: benign case must not depend on the host filesystem — a path that
    #     exists on macOS does not exist on the Ubuntu CI runner. Control
    #     existence explicitly. / FR: le cas bénin ne doit pas dépendre de
    #     l'hôte — existence contrôlée explicitement.
    monkeypatch.setattr(Path, "exists", lambda self: True)
    r3, _ = score_entry({"target": "/opt/vendor/agent",
                         "run_at_load": True, "keep_alive": False})
    assert r3 == 0


def test_real_macos_collection():
    entries = collect_macos()
    assert isinstance(entries, dict)       # EN: runs without exception on any OS
    for e in entries.values():
        assert "content_hash" in e and "kind" in e
