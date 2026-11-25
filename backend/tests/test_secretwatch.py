"""
EN: Unit tests for secrets egress watch (detection/secretwatch.py).
FR: Tests unitaires de la veille d'exfiltration de secrets.
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection.secretwatch import SecretWatch, _shape, harvest

AWS = "AKIAIOSFODNN7EXAMPLE"
OAI = "sk-" + "a" * 40


def test_harvest_env_patterns():
    found = harvest(env={"AWS_ACCESS_KEY_ID": AWS, "OPENAI_API_KEY": OAI,
                         "PATH": "/usr/bin"}, home=Path("/nonexistent-home-xyz"))
    kinds = {m["kind"] for m in found.values()}
    assert "aws_access_key" in kinds and "openai_key" in kinds
    assert len(found) == 2                                # EN: PATH ignored / FR: PATH ignoré


def test_harvest_dotfile(tmp_path: Path = None):
    with tempfile.TemporaryDirectory() as td:
        home = Path(td)
        (home / ".aws").mkdir()
        (home / ".aws/credentials").write_text(f"[default]\naws_access_key_id = {AWS}\n")
        found = harvest(env={}, home=home)
        assert any(m["source"] == "file:.aws/credentials" for m in found.values())


def test_shape_redaction():
    s = _shape(OAI)
    assert s.startswith("sk-") and "aaaa" not in s[3:-4]
    assert len(s) < len(OAI)


def test_plaintext_leak_alert_no_values():
    w = SecretWatch()
    w.register(env={"AWS_ACCESS_KEY_ID": AWS}, home=Path("/nonexistent-home-xyz"))
    payload = f"POST data key={AWS}&more=1".encode()
    alerts = w.scan_payload(payload, "curl", "evil.example.com")
    assert len(alerts) == 1
    a = alerts[0]
    assert a["type"] == "SECRET_PLAINTEXT_LEAK" and a["severity"] == "critical"
    assert AWS not in str(a)                              # EN: value never in alert / FR: valeur jamais dans l'alerte
    assert a["details"]["shape"].startswith("AKI")


def test_no_alert_on_clean_payload():
    w = SecretWatch()
    w.register(env={"AWS_ACCESS_KEY_ID": AWS}, home=Path("/nonexistent-home-xyz"))
    assert w.scan_payload(b"harmless body", "curl", "x.com") == []


def test_status_never_exposes_values():
    w = SecretWatch()
    w.register(env={"OPENAI_API_KEY": OAI}, home=Path("/nonexistent-home-xyz"))
    st = w.status()
    assert OAI not in str(st)
    assert st["registered"] == 1 and st["by_kind"]["openai_key"] == 1


def test_disabled():
    w = SecretWatch()
    w.register(env={"AWS_ACCESS_KEY_ID": AWS}, home=Path("/nonexistent-home-xyz"))
    w.enabled = False
    assert w.scan_payload(AWS.encode(), "curl", "x.com") == []
