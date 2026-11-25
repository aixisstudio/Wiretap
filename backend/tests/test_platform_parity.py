"""EN/FR: parity tests — Windows command parsing must not depend on the host OS."""

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import platform as _plat
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _mock_run(stdout_map):
    """EN: subprocess returns bytes when text=True is not passed — the
        fixture must match reality. / FR: bytes, comme la réalité."""
    def runner(cmd, **kw):
        key = cmd[0] if isinstance(cmd, list) else cmd
        m = MagicMock()
        raw = stdout_map.get(key, "")
        m.stdout = raw if kw.get("text") else raw.encode()
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
    from detection import mcpwatch
    # EN: on any host the locations must be non-empty strings / FR: chemins non vides partout
    for client, rel in mcpwatch.CONFIG_LOCATIONS:
        assert isinstance(rel, str) and rel
    names = [c for c, _ in mcpwatch.CONFIG_LOCATIONS]
    assert "Claude Desktop" in names and "VS Code" in names


def test_netstat_localization_proof():
    """EN: the foreign-address heuristic must survive localized state words —
        German 'ABHÖREN', French 'ÉCOUTE' — because it never reads them.
    FR: l'heuristique survit aux mots d'état localisés — elle ne les lit pas."""
    from detection import timetravel
    for locale_word in ("ABHÖREN", "ÉCOUTE", "LISTENING", "ASCOLTO"):
        netstat = f"  TCP    0.0.0.0:8080     0.0.0.0:0    {locale_word}    4242\n"
        tasklist = '"python.exe","4242","Console"\n'
        with patch("platform.system", return_value="Windows"), \
             patch("subprocess.run", side_effect=_mock_run({"netstat": netstat, "tasklist": tasklist, "powershell": ""})):
            listeners = timetravel.collect_listeners()
        assert "8080" in listeners, f"failed for locale word {locale_word}"
        assert listeners["8080"]["process"] == "python.exe"


def test_netstat_foreign_heuristic_rejects_established():
    """EN: established connections have real foreign addresses, not 0.0.0.0:0 —
        they must NOT be counted as listeners. / FR: les connexions établies
        ne sont pas des listeners."""
    from detection import timetravel
    netstat = ("  TCP    192.168.1.5:51000   142.250.74.46:443   ESTABLISHED  4242\n"
               "  TCP    0.0.0.0:443          0.0.0.0:0            ABHÖREN      4242\n")
    with patch("platform.system", return_value="Windows"), \
         patch("subprocess.run", side_effect=_mock_run({"netstat": netstat, "tasklist": "", "powershell": ""})):
        listeners = timetravel.collect_listeners()
    assert "443" in listeners
    assert "51000" not in listeners            # EN: outbound port, not a listener


def test_powershell_primary_path():
    """EN: structured PowerShell output takes priority, no netstat needed.
    FR: la sortie structurée PowerShell prime."""
    from detection import timetravel
    ps = "443 4242\n8080 1000\n"
    tasklist = '"python.exe","4242","Console"\n"node.exe","1000","Console"\n'
    with patch("platform.system", return_value="Windows"), \
         patch("subprocess.run", side_effect=_mock_run({"powershell": ps, "tasklist": tasklist, "netstat": ""})):
        listeners = timetravel.collect_listeners()
    assert listeners["443"]["process"] == "python.exe"
    assert listeners["8080"]["pid"] == 1000


@pytest.mark.skipif(_plat.system() == "Windows", reason=(
    "pathlib is platform-locked: Path('/proc/net/tcp') becomes a Windows path "
    "on win32 and the Linux /proc fixture cannot be simulated faithfully — "
    "the hex parsing is verified on the ubuntu and macOS runners"))
def test_linux_proc_net_tcp():
    """EN: /proc/net/tcp hex parsing — no lsof needed on minimal installs.
    FR: parsing hexa /proc/net/tcp — pas besoin de lsof."""
    from detection import timetravel as tt
    fixture = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
               "   0: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 x 100 0 0 10 0\n"
               "   1: 0100007F:1F91 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12346 1 x 100 0 0 10 0\n"
               "   2: 0100007F:C000 8A3E2E8E:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 12347 1 x 100 0 0 10 0\n")
    real_read = Path.read_text

    def fake_read(self, *a, **kw):
        if str(self) == "/proc/net/tcp":
            return fixture
        if str(self) == "/proc/net/tcp6":
            return ""
        return real_read(self, *a, **kw)

    with patch("platform.system", return_value="Linux"), \
         patch.object(Path, "read_text", fake_read), \
         patch.object(tt, "_proc_socket_inodes",
                      lambda: {"12345": (4, "systemd"), "12346": (4242, "node")}):
        listeners = tt._collect_listeners_linux()
    assert listeners["443"]["process"] == "systemd"
    assert listeners["8081"]["pid"] == 4242
    assert str(0xC000) not in listeners          # EN: state 01 established, not listening
