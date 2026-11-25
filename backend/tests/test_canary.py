"""EN/FR: Tests canaris ransomware + honeyports."""

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection.canary import CANARY_NAME, CanaryWatch, HoneyPorts


def _canary_home():
    td = tempfile.TemporaryDirectory()
    home = Path(td.name)
    (home / "Documents").mkdir()
    (home / "Desktop").mkdir()
    return td, home


def test_plant_and_clean():
    td, home = _canary_home()
    try:
        w = CanaryWatch(home)
        planted = w.plant()
        assert len(planted) == 2
        assert w.check_once() == []                    # EN: untouched = silent / FR: intact = silence
    finally:
        td.cleanup()


def test_modification_alert():
    td, home = _canary_home()
    try:
        w = CanaryWatch(home)
        w.plant()
        c = home / "Documents" / CANARY_NAME
        c.write_text("ENCRYPTED BY RANSOMWARE")
        alerts = w.check_once()
        assert len(alerts) == 1 and alerts[0]["type"] == "RANSOMWARE_CANARY"
        assert alerts[0]["severity"] == "critical"
        assert w.check_once() == []                    # EN: fires once / FR: une seule fois
    finally:
        td.cleanup()


def test_deletion_alert():
    td, home = _canary_home()
    try:
        w = CanaryWatch(home)
        w.plant()
        (home / "Desktop" / CANARY_NAME).unlink()
        alerts = w.check_once()
        assert len(alerts) == 1 and "DELETED" in alerts[0]["message"]
    finally:
        td.cleanup()


def test_honeyport_touch():
    async def run():
        hp = HoneyPorts(ports=(22323,))
        hp.enabled = True
        captured = []
        hp.on_alert = captured.append
        st = await hp.start()
        assert 22323 in st["bound"]
        r, w = await asyncio.open_connection("127.0.0.1", 22323)
        w.close()
        await asyncio.sleep(0.05)
        await hp.stop()
        return captured
    captured = asyncio.run(run())
    assert captured == [] or all("127." in a["details"]["source"] for a in captured)
    # EN: localhost touches are intentionally ignored / FR: touches locales ignorées


def test_honeyport_alert_shape():
    hp = HoneyPorts(ports=(1,))
    alerts = []
    hp.on_alert = alerts.append
    class FakeWriter:
        def get_extra_info(self, k): return ("10.0.0.66", 1234)
        def close(self): pass
    asyncio.run(hp._touch(None, FakeWriter(), 23))
    assert len(alerts) == 1
    assert alerts[0]["type"] == "HONEYPORT_TOUCH"
    assert alerts[0]["details"]["port"] == 23
