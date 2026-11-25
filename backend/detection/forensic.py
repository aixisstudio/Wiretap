"""
EN: Tamper-evident forensic alert log — the difference between "a tool
    said something happened" and "evidence that survives scrutiny".
    Every alert is hash-chained to the previous one:

        hash[n] = sha256(hash[n-1] | canonical(alert[n]))

    exactly like a transparency log (certificate transparency, git).
    Consequences nobody else in this class of tools offers:

      * an attacker who wipes or edits past alerts BREAKS THE CHAIN —
        deletion itself becomes detectable;
      * the incident timeline becomes exportable evidence: hand the CSV
        plus the chain head to an insurer, a lawyer or an auditor and
        they can verify it was not rewritten after the fact;
      * verification is offline and instant — no trust in Wiretap needed.

    The chain head is also exposed in the API so a paranoid user can pin
    it elsewhere (a note, an email to self) — pinning turns retroactive
    tampering into a mathematical impossibility rather than a difficulty.

FR: Journal d'alertes forensique inviolable — la différence entre « un
    outil a dit que quelque chose s'est passé » et « une preuve qui
    survit à l'examen ». Chaque alerte est hash-chainée à la précédente
    comme un transparency log : un attaquant qui efface ou modifie le
    passé CASSE LA CHAÎNE — la suppression elle-même devient détectable.
    Vérification offline instantanée, tête de chaîne exposable pour
    épingleage externe.
"""

from __future__ import annotations

import hashlib
import json

GENESIS = "0" * 64


def canonical(alert: dict) -> str:
    """EN: Deterministic serialization — sorted keys, fixed separators.
    FR: sérialisation déterministe — clés triées, séparateurs fixes."""
    keep = {k: alert.get(k) for k in ("type", "severity", "message",
                                      "node_id", "details", "timestamp")}
    return json.dumps(keep, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str)


def chain_hash(prev_hash: str, alert: dict) -> str:
    return hashlib.sha256(
        (prev_hash + "|" + canonical(alert)).encode()).hexdigest()


def verify_chain(rows: list[dict]) -> dict:
    """EN: Verify a chain of (row dicts with `hash` + `prev_hash`, ordered
    by insertion). Returns {valid, length, first_bad_index, head}.
    FR: vérifier une chaîne de lignes ordonnées. Renvoie valid/length/etc."""
    prev = GENESIS
    for i, row in enumerate(rows):
        expected = chain_hash(prev, row)
        if row.get("prev_hash") != prev or row.get("hash") != expected:
            return {"valid": False, "length": len(rows),
                    "first_bad_index": i,
                    "head": rows[-1].get("hash") if rows else GENESIS,
                    "detail": f"chain broken at index {i}: "
                              f"{'missing/altered row before it' if row.get('prev_hash') != prev else 'row content modified'}"}
        prev = row["hash"]
    return {"valid": True, "length": len(rows), "first_bad_index": None,
            "head": prev}
