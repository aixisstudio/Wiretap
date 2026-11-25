"""
EN: Unit tests for network-aware profile switching (detection/netprofile.py).
FR: Tests unitaires de la bascule de profil selon le réseau.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection import netprofile
from detection.netprofile import NetworkProfiler
from detection.firewall import FirewallManager


class _Fw(FirewallManager):
    def __init__(self):
        pass  # EN: skip filesystem init / FR: pas d'init disque


def test_ssid_parsing_macos():
    out = "some noise\n SSID : MyHomeWifi\n BSSID : aa:bb:cc:dd:ee:ff\n"
    with patch.object(netprofile, "_run", return_value=out):
        ssid, bssid = netprofile.wifi_ssid_bssid("Darwin")
    assert ssid == "MyHomeWifi"
    assert bssid == "aa:bb:cc:dd:ee:ff"


def test_ssid_parsing_windows():
    out = "There is 1 interface\n    SSID                   : CorpNet\n    BSSID                : 11:22:33:44:55:66\n"
    with patch.object(netprofile, "_run", return_value=out):
        ssid, bssid = netprofile.wifi_ssid_bssid("Windows")
    assert ssid == "CorpNet" and bssid == "11:22:33:44:55:66"


def test_ssid_none_when_not_wifi():
    with patch.object(netprofile, "_run", return_value=""):
        assert netprofile.wifi_ssid_bssid("Darwin") == (None, None)


def test_fingerprint_wifi_preferred():
    with patch.object(netprofile, "wifi_ssid_bssid", return_value=("Cafe", "aa:bb:cc:dd:ee:ff")):
        fp = netprofile.current_fingerprint("Darwin")
    assert fp["kind"] == "wifi" and fp["fp"] == "wifi:Cafe@aa:bb:cc:dd:ee:ff"


def test_fingerprint_gateway_fallback():
    with patch.object(netprofile, "wifi_ssid_bssid", return_value=(None, None)), \
         patch.object(netprofile, "gateway_fingerprint", return_value="gw:aa:bb/192.168.1"):
        fp = netprofile.current_fingerprint("Linux")
    assert fp["kind"] == "gateway"


def test_assign_and_mapping_filter():
    fw = _Fw()
    npf = NetworkProfiler(fw, "Darwin")
    with patch.object(netprofile, "current_fingerprint",
                      return_value={"kind": "wifi", "ssid": "Cafe", "bssid": None, "fp": "wifi:Cafe"}):
        r = npf.assign_current("strict")
        assert r["ok"] and r["mappings"] == {"wifi:Cafe": "strict"}
        r = npf.assign_current("bogus_profile")
        assert not r["ok"]
        r = npf.assign_current("none")
        assert r["mappings"] == {}


def test_configure_drops_invalid_profiles():
    fw = _Fw()
    npf = NetworkProfiler(fw, "Darwin")
    st = npf.configure(mappings={"wifi:Cafe": "strict", "wifi:Home": "nope"})
    assert st["mappings"] == {"wifi:Cafe": "strict"}


def test_watcher_applies_on_change():
    fw = _Fw()
    applied = []
    fw.apply_profile = lambda name: applied.append(name) or {"profile": name}
    npf = NetworkProfiler(fw, "Darwin")
    npf.enabled = True
    npf.mappings = {"wifi:Cafe": "strict"}
    fps = iter([
        {"kind": "wifi", "fp": "wifi:Home", "ssid": "Home", "bssid": None},
        {"kind": "wifi", "fp": "wifi:Cafe", "ssid": "Cafe", "bssid": None},
        {"kind": "wifi", "fp": "wifi:Cafe", "ssid": "Cafe", "bssid": None},
    ])
    with patch.object(netprofile, "current_fingerprint", side_effect=lambda s: next(fps)), \
         patch.object(netprofile, "_POLL_INTERVAL", 0.01):
        import threading
        npf._stop.clear()
        t = threading.Thread(target=npf._loop, daemon=True)
        t.start()
        t.join(timeout=1.0)
        npf._stop.set()
    assert "strict" in applied
    assert npf.last_applied == "strict"
