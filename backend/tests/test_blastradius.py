"""EN/FR: tests blast radius."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection.blastradius import BlastRadius, open_files_for_pid


def _wired():
    b = BlastRadius()
    b.register_sources(
        network_footprint=lambda proc: [{"dest": "1.2.3.4", "bytes_out": 5000}],
        ai_exposure=lambda proc: [{"service": "OpenAI"}],
        secret_count=lambda proc, pid=0: 3,
        persistence_hit=lambda proc, path: [{"entry": "x"}] if proc == "evil" else [],
        lineage=lambda pid: [{"name": "launchd"}, {"name": "evil"}] if pid else [],
    )
    return b


def test_assess_full():
    a = _wired().assess("evil", pid=0, target_path="/tmp/evil")
    assert a["sections"]["network"]["destinations"] == 1
    assert a["sections"]["ai_exposure"]["providers"] == 1
    assert a["sections"]["secret_access"]["count"] == 3
    assert a["sections"]["persistence"]["auto_start"] is True
    assert "SURVIVES REBOOT" in a["worst_case"]
    assert "OpenAI" in a["worst_case"]


def test_assess_benign():
    b = _wired()
    a = b.assess("Safari", pid=0)
    assert a["sections"]["persistence"]["auto_start"] is False
    assert "SURVIVES" not in a["worst_case"]


def test_sources_fail_gracefully():
    b = BlastRadius()
    b.register_sources(network_footprint=lambda p: 1 / 0)
    a = b.assess("x")
    assert a["sections"]["network"]["value"] == "unknown"
    assert a["sections"]["network"]["confidence"] == "unavailable"


def test_no_sources_at_all():
    a = BlastRadius().assess("x")
    assert a["worst_case"].startswith("no measurable")
    assert a["sections"]["network"]["confidence"] == "unavailable"


def test_attach_and_get():
    b = _wired()
    a = b.assess("evil")
    b.attach("alert-1", a)
    assert b.get("alert-1")["process"] == "evil"
    assert b.get("nope") is None


def test_open_files_self():
    import os
    r = open_files_for_pid(os.getpid())
    assert r["source"] in ("procfs", "lsof", "none")
    assert isinstance(r["files"], list)
