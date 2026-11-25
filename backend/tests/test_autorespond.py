"""EN/FR: Tests réponse automatique."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection.autorespond import AutoResponder


class FakeFw:
    lockdown = False


def test_disabled_by_default():
    ar = AutoResponder(FakeFw())
    assert ar.observe("RANSOMWARE_CANARY", "critical") == []


def test_lockdown_action():
    fw = FakeFw()
    ar = AutoResponder(fw)
    ar.configure(enabled=True, actions={"RANSOMWARE_CANARY": ["lockdown"]})
    recs = ar.observe("RANSOMWARE_CANARY", "critical")
    assert len(recs) == 1 and recs[0]["ok"] and fw.lockdown


def test_cooldown_dedupes():
    fw = FakeFw()
    fw.lockdown = False
    ar = AutoResponder(fw)
    ar.configure(enabled=True, actions={"RANSOMWARE_CANARY": ["lockdown"]})
    ar.observe("RANSOMWARE_CANARY", "critical")
    fw.lockdown = False
    assert ar.observe("RANSOMWARE_CANARY", "critical") == []     # EN: inside cooldown / FR: cooldown


def test_warning_never_acts():
    ar = AutoResponder(FakeFw())
    ar.configure(enabled=True, actions={"RANSOMWARE_CANARY": ["lockdown"]})
    assert ar.observe("RANSOMWARE_CANARY", "warning") == []


def test_invalid_types_and_actions_filtered():
    ar = AutoResponder(FakeFw())
    st = ar.configure(enabled=True, actions={
        "RANSOMWARE_CANARY": ["lockdown", "delete_hard_drive"],
        "NOT_A_REAL_TYPE": ["lockdown"],
    })
    assert st["actions"] == {"RANSOMWARE_CANARY": ["lockdown"]}


def test_suspend_no_pid():
    ar = AutoResponder(FakeFw())
    ar.configure(enabled=True, actions={"POSTINSTALL_NET": ["suspend"]})
    recs = ar.observe("POSTINSTALL_NET", "critical", pid=None)
    assert recs[0]["detail"] == "no pid in alert"


def test_audit_log():
    ar = AutoResponder(FakeFw())
    ar.configure(enabled=True, actions={"HONEYPORT_TOUCH": ["lockdown"]})
    ar.observe("HONEYPORT_TOUCH", "critical")
    st = ar.status()
    assert len(st["recent"]) == 1
    assert "C2_BEACON" in st["eligible_types"]
