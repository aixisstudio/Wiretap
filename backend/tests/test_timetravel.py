"""EN/FR: tests time-travel diff."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection.timetravel import TimeTravel, diff_states


def _state(ts, pers=None, listeners=None, procs=None):
    return {"ts": ts, "persistence": pers or {}, "listeners": listeners or {},
            "processes": procs or {}}


def test_diff_appeared_vanished_mutated():
    old = _state(100, pers={"a": {"target": "/x", "content_hash": "1"},
                            "b": {"target": "/y", "content_hash": "2"}})
    new = _state(200, pers={"b": {"target": "/y", "content_hash": "CHANGED"},
                            "c": {"target": "/z", "content_hash": "3"}})
    d = diff_states(old, new)
    p = d["sections"]["persistence"]
    assert [x["id"] for x in p["appeared"]] == ["c"]
    assert [x["id"] for x in p["vanished"]] == ["a"]
    assert [x["id"] for x in p["mutated"]] == ["b"]
    assert any("auto-start" in r for r in d["risk_notes"])
    assert d["changes_total"] == 3


def test_diff_identical_is_empty():
    s = _state(100, pers={"a": {"target": "/x", "content_hash": "1"}})
    d = diff_states(s, dict(s))
    assert d["changes_total"] == 0
    assert d["risk_notes"] == []


def test_empty_store_honest():
    tt = TimeTravel(collector=dict)
    d = tt.diff_since()
    assert "error" in d and "baseline" in d["error"]


def test_snapshot_and_diff(tmp_path):
    states = [
        {"agent:x": {"target": "/a", "content_hash": "1"}},
        {"agent:x": {"target": "/a", "content_hash": "1"},
         "agent:evil": {"target": "/tmp/evil", "content_hash": "9"}},
    ]
    idx = {"i": 0}
    tt = TimeTravel(store_dir=tmp_path, collector=lambda: states[min(idx["i"], 1)])
    tt.snapshot(now=1000)
    idx["i"] = 1                       # EN: evil appears / FR: evil apparaît
    d = tt.diff_since()
    assert d["changes_total"] >= 1
    ids = [x["id"] for x in d["sections"]["persistence"]["appeared"]]
    assert "agent:evil" in ids


def test_diff_since_picks_closest(tmp_path):
    tt = TimeTravel(store_dir=tmp_path, collector=dict)
    tt.snapshot(now=1000)
    tt.snapshot(now=2000)
    d = tt.diff_since(since_ts=1500)
    assert d["from_ts"] == 2000       # EN: first snapshot >= 1500
    d2 = tt.diff_since(since_ts=None)
    assert d2["from_ts"] == 1000      # EN: oldest by default
