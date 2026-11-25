"""EN/FR: Tests chaîne forensique."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detection.forensic import GENESIS, chain_hash, verify_chain


def _row(i, prev):
    a = {"type": "TEST", "severity": "warning", "message": f"m{i}",
         "node_id": None, "details": {}, "timestamp": f"2026-01-01T00:00:{i:02d}"}
    h = chain_hash(prev, a)
    return {**a, "hash": h, "prev_hash": prev}


def _chain(n):
    rows, prev = [], GENESIS
    for i in range(n):
        r = _row(i, prev)
        rows.append(r)
        prev = r["hash"]
    return rows


def test_valid_chain():
    rows = _chain(5)
    r = verify_chain(rows)
    assert r["valid"] and r["length"] == 5
    assert r["head"] == rows[-1]["hash"]


def test_modified_row_detected():
    rows = _chain(5)
    rows[2]["message"] = "tampered"
    r = verify_chain(rows)
    assert not r["valid"] and r["first_bad_index"] == 2
    assert "modified" in r["detail"]


def test_deleted_row_detected():
    rows = _chain(5)
    del rows[2]                                            # EN: attacker wipes one / FR: effacement
    r = verify_chain(rows)
    assert not r["valid"]
    assert r["first_bad_index"] == 2


def test_empty_chain_valid():
    r = verify_chain([])
    assert r["valid"] and r["head"] == GENESIS


def test_canonical_deterministic():
    a = {"type": "X", "severity": "info", "message": "m",
         "node_id": None, "details": {"b": 1, "a": 2}, "timestamp": "t"}
    assert chain_hash(GENESIS, a) == chain_hash(GENESIS, dict(reversed(list(a.items()))))
