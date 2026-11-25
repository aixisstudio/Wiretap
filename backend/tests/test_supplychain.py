"""EN/FR: Tests unitaires supply-chain watch."""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection.supplychain import SupplyChainWatch, in_allowlist


def test_allowlist():
    assert in_allowlist("registry.npmjs.org")
    assert in_allowlist("files.pythonhosted.org")
    assert not in_allowlist("npmjs.evil.com")
    assert not in_allowlist("")


def test_registry_anomaly_alert_once():
    w = SupplyChainWatch()
    a1 = w.observe("npm", "evil-mirror.cn", "out", "1.2.3.4")
    assert len(a1) == 1 and a1[0]["type"] == "PKG_REGISTRY_ANOMALY"
    assert w.observe("npm", "evil-mirror.cn", "out", "1.2.3.4") == []
    assert w.observe("npm", "registry.npmjs.org", "out", "1.2.3.4") == []


def test_postinstall_correlation():
    w = SupplyChainWatch()
    w.observe("npm", "registry.npmjs.org", "out", "1.1.1.1")   # EN: pkg activity / FR: activité install
    a = w.observe("unknown-helper", "c2.bad.xyz", "out", "2.2.2.2")
    assert len(a) == 1 and a[0]["type"] == "POSTINSTALL_NET"
    assert a[0]["severity"] == "critical"
    assert w.observe("unknown-helper", "c2.bad.xyz", "out", "2.2.2.2") == []  # EN: once / FR: une fois


def test_no_correlation_without_pkg():
    w = SupplyChainWatch()
    assert w.observe("brandnewproc", "x.com", "out", "2.2.2.2") == []


def test_no_correlation_after_window():
    w = SupplyChainWatch()
    w.note_pkg_activity()
    w._last_pkg_activity = time.time() - 700                   # EN: outside 600s window / FR: hors fenêtre
    assert w.observe("lateproc", "x.com", "out", "2.2.2.2") == []


def test_inbound_ignored():
    w = SupplyChainWatch()
    w.observe("npm", "evil.com", "in", "1.2.3.4")
    assert w.status()["alerts_deduped"] == 0


def test_disabled():
    w = SupplyChainWatch()
    w.enabled = False
    assert w.observe("npm", "evil.com", "out", "1.2.3.4") == []
