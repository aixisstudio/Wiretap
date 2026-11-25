"""EN/FR: tests flow DNA."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection.flowdna import FlowDNA, _cv, _entropy


def test_cv_and_entropy():
    assert _cv([10, 10, 10]) == 0.0
    assert _cv([1, 100]) > 0.5
    assert _entropy([]) == 0.0
    assert _entropy(["a", "a"]) == 0.0
    assert _entropy(["a", "b"]) == 1.0


def _feed(proc, dna, n, size, dests, now_start=1000.0, ratio_out=1.0):
    now = now_start
    for i in range(n):
        direction = "out" if i % 2 == 0 or ratio_out > 2 else "in"
        dna.observe(proc, direction, size, dests[i % len(dests)], now)
        now += 1.0


def test_no_alert_during_learning():
    dna = FlowDNA()
    for i in range(29):
        assert dna.observe("firefox", "out", 500, f"host{i % 5}.com", 1000.0 + i) is None


def test_stable_metabolism_no_alert():
    dna = FlowDNA()
    _feed("firefox", dna, 60, 500, [f"host{i}.com" for i in range(8)])
    # EN: baseline built at 30, live window also stable -> no alert / FR: stable = silence
    assert all(dna.observe("firefox", "out", 500, "host1.com", 2000.0 + i) is None for i in range(5))


def test_drift_alert_multifeature():
    dna = FlowDNA()
    # EN: baseline — many small flows to many hosts / FR: baseline — petits flux variés
    _feed("firefox", dna, 60, 400, [f"cdn{i}.example.com" for i in range(10)])
    assert "firefox" in dna._baseline
    # EN: drift — huge sustained uploads to ONE host / FR: dérive — gros uploads vers UN hôte
    alerted = None
    for i in range(40):
        r = dna.observe("firefox", "out", 60000, "evil-single.com", 5000.0 + i * 0.01)
        if r:
            alerted = r
            break
    assert alerted is not None, "expected FLOW_DRIFT"
    assert alerted["type"] == "FLOW_DRIFT"
    assert alerted["details"]["features_drifted"] >= 2
    assert "metabolism" in alerted["message"]


def test_rebaseline():
    dna = FlowDNA()
    _feed("x", dna, 60, 400, ["a.com", "b.com"])
    assert dna.rebaseline("x") is True
    assert dna.rebaseline("unknown") is False


def test_disabled():
    dna = FlowDNA()
    dna.enabled = False
    assert dna.observe("x", "out", 1, "a.com", 1.0) is None
