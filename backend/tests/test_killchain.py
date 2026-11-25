"""EN/FR: Tests corrélateur kill-chain."""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection.killchain import KillChain


def test_single_signal_no_chain():
    kc = KillChain()
    assert kc.observe("POSTINSTALL_NET", "critical", {"process": "evil.sh"}) is None


def test_same_family_twice_not_a_chain():
    kc = KillChain()
    kc.observe("SHADOW_AI", "warning", {"process": "evil.sh"})
    assert kc.observe("AI_UPLOAD_SPIKE", "critical", {"process": "evil.sh"}) is None


def test_three_families_fire_chain():
    kc = KillChain()
    assert kc.observe("POSTINSTALL_NET", "critical", {"process": "evil.sh"}) is None
    assert kc.observe("SHADOW_AI", "warning", {"process": "evil.sh"}) is None
    chain = kc.observe("SECRET_PLAINTEXT_LEAK", "critical", {"process": "evil.sh"})
    assert chain is not None
    assert chain["type"] == "KILLCHAIN" and chain["severity"] == "critical"
    assert len(chain["details"]["families"]) == 3
    assert len(chain["details"]["chain"]) == 3                      # EN: timeline preserved / FR: timeline


def test_chain_consumed_after_fire():
    kc = KillChain()
    for t in ("POSTINSTALL_NET", "SHADOW_AI", "SECRET_PLAINTEXT_LEAK"):
        kc.observe(t, "critical", {"process": "evil.sh"})
    # EN: firing consumed the chain AND cooldown blocks immediate re-fire
    # FR: chaîne consommée + cooldown
    assert kc.observe("C2_BEACON", "critical", {"process": "evil.sh"}) is None


def test_window_expiry():
    kc = KillChain(window_s=10)
    kc.observe("POSTINSTALL_NET", "critical", {"process": "evil.sh"})
    # EN: simulate old event by direct manipulation / FR: simuler un événement vieux
    with kc._lock:
        kc._events["proc:evil.sh"] = [(time.time() - 20, "supplychain", "POSTINSTALL_NET", "m")]
    kc.observe("SHADOW_AI", "warning", {"process": "evil.sh"})
    assert kc.observe("SECRET_PLAINTEXT_LEAK", "critical", {"process": "evil.sh"}) is None


def test_ip_entity_key():
    kc = KillChain()
    kc.observe("C2_BEACON", "critical", {}, node_id="1.2.3.4")
    kc.observe("HIGH_ENTROPY", "info", {}, node_id="1.2.3.4")
    chain = kc.observe("HONEYPORT_TOUCH", "critical", {}, node_id="1.2.3.4")
    assert chain is not None and chain["details"]["entity"] == "ip:1.2.3.4"


def test_unknown_type_ignored():
    kc = KillChain()
    assert kc.observe("SOME_RANDOM_TYPE", "critical", {"process": "x"}) is None
    assert kc.status()["entities_tracked"] == 0


def test_disabled():
    kc = KillChain()
    kc.enabled = False
    assert kc.observe("POSTINSTALL_NET", "critical", {"process": "x"}) is None


def test_no_entity_no_track():
    kc = KillChain()
    assert kc.observe("POSTINSTALL_NET", "critical", {}) is None
    assert kc.status()["entities_tracked"] == 0
