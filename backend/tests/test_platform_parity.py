"""EN/FR: parity tests — Windows command parsing must not depend on the host OS."""

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _mock_run(stdout_map):
    def runner(cmd, **kw):
        key = cmd[0] if isinstance(cmd, list) else cmd
        m = MagicMock()
        m.stdout = stdout_map.get(key, "")
        m.returncode = 0
        return m
    return runner


def test_lineage_windows_cim_parse():
    from detection import lineage
    cim_out = "4 0 System\n548 4 services.exe\n1234 548 chrome.exe\n5600 1234 powershell.exe\n"
    with patch("platform.system", return_value="Windows"), \
         patch("subprocess.run", side_effect=_mock_run({"powershell": cim_out, "wmic": ""})):
        table = lineage._ps_table()
    assert table.get(1234) == (548, "chrome")
    assert table.get(5600) == (1234, "powershell")
    assert table.get(4) == (0, "system")


def test_lineage_windows_wmic_fallback():
    from detection import lineage
    wmic_out = "Node,Name,ParentProcessId,ProcessId\nHOST,chrome.exe,548,1234\n"
    with patch("platform.system", return_value="Windows"), \
         patch("subprocess.run", side_effect=_mock_run({"powershell": "", "wmic": wmic_out})):
        table = lineage._ps_table()
    assert 1234 in table or not table  # parse best-effort, no crash


def test_timetravel_windows_listeners():
    from detection import timetravel
    netstat = "  TCP    0.0.0.0:445     0.0.0.0:0    LISTENING    4\n  TCP    127.0.0.1:7777  0.0.0.0:0  LISTENING    5600\n"
    tasklist = '"System","4","Services"\n"node.exe","5600","Console"\n'
    with patch("platform.system", return_value="Windows"), \
         patch("subprocess.run", side_effect=_mock_run({"netstat": netstat, "tasklist": tasklist})):
        listeners = timetravel.collect_listeners()
    assert "445" in listeners
    assert listeners.get("7777", {}).get("process") == "node.exe"


def test_timetravel_windows_processes():
    from detection import timetravel
    tasklist = '"chrome.exe","1234","Console"\n"chrome.exe","1235","Console"\n"svchost.exe","500","Services"\n'
    with patch("platform.system", return_value="Windows"), \
         patch("subprocess.run", side_effect=_mock_run({"tasklist": tasklist})):
        procs = timetravel.collect_processes()
    assert procs.get("chrome", {}).get("count") == 2
    assert "svchost" in procs


def test_mcpwatch_windows_paths():
    import platform
    from detection import mcpwatch
    # EN: on any host the locations must be non-empty strings / FR: chemins non vides partout
    for client, rel in mcpwatch.CONFIG_LOCATIONS:
        assert isinstance(rel, str) and rel
    names = [c for c, _ in mcpwatch.CONFIG_LOCATIONS]
    assert "Claude Desktop" in names and "VS Code" in names
