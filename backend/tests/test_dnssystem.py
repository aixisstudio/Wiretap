"""EN/FR: Tests intégration DNS système — plans de commandes purs."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection.dnssystem import (SystemDns, build_apply_cmds,
                                 build_revert_cmds, macos_services)


def test_macos_apply_cmds():
    cmds = build_apply_cmds("Darwin", ["Wi-Fi", "USB LAN"], None)
    assert cmds == [["networksetup", "-setdnsservers", "Wi-Fi", "127.0.0.1"],
                    ["networksetup", "-setdnsservers", "USB LAN", "127.0.0.1"]]


def test_linux_apply_cmds():
    cmds = build_apply_cmds("Linux", [], "eth0")
    assert ["resolvectl", "dns", "eth0", "127.0.0.1"] in cmds
    assert ["resolvectl", "domain", "eth0", "~."] in cmds


def test_windows_apply_cmds():
    cmds = build_apply_cmds("Windows", [], None)
    assert any("netsh" in c[0] and "127.0.0.1" in c for c in cmds)


def test_revert_restores_previous():
    cmds = build_revert_cmds("Darwin", ["Wi-Fi"], None, {"Wi-Fi": ["1.1.1.1", "8.8.8.8"]})
    assert cmds[0] == ["networksetup", "-setdnsservers", "Wi-Fi", "1.1.1.1", "8.8.8.8"]


def test_revert_dhcp_when_no_previous():
    cmds = build_revert_cmds("Darwin", ["Wi-Fi"], None, {"Wi-Fi": []})
    assert "Empty" in cmds[0]                              # EN: Empty = back to DHCP / FR: retour DHCP


def test_linux_revert():
    cmds = build_revert_cmds("Linux", [], "wlan0", {})
    assert cmds[0][:2] == ["resolvectl", "revert"]


def test_unknown_platform():
    assert build_apply_cmds("FreeBSD", [], None) == []


def test_apply_failure_reports_privileges():
    def selective_run(cmd):
        if "-listallnetworkservices" in cmd:
            return (0, "header\nWi-Fi\n", "")
        if "-getdnsservers" in cmd:
            return (0, "1.1.1.1\n", "")
        return (1, "", "permission denied")
    sd = SystemDns("Darwin", run=selective_run)
    r = sd.apply()
    assert not r["ok"]
    assert "privileges" in r.get("needs", "")
    assert r["previous"] == {"Wi-Fi": ["1.1.1.1"]}      # EN: snapshot taken before change / FR: snapshot avant modif


def test_services_parsing():
    def fake_run(cmd):
        return (0, "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Ethernet\nUSB 10/100/1000 LAN\n", "")
    svcs = macos_services(fake_run)
    assert "Wi-Fi" in svcs and "Ethernet" not in svcs       # EN: disabled filtered / FR: désactivés filtrés
    assert "USB 10/100/1000 LAN" in svcs
