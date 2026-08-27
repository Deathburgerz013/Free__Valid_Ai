"""Replay verification evidence against the frozen admission index."""

from __future__ import annotations

from typing import Any, Mapping

from .checks import run_json_pointer_check, run_source_sha256_check
from .claims import ClaimContractError
from .frozen_index import admitted_check


_RUNNERS = {
    "source_sha256_equals": run_source_sha256_check,
    "json_pointer_equals": run_json_pointer_check,
}
_FIELDS = {
    "check_id", "check_version", "claim", "observed_bytes_hex", "receipt"
}


def replay_evidence_item(
    item: Any,
    *,
    frozen_index: Mapping[str, Any],
) -> str | None:
    """Return the recomputed receipt result, or None for invalid evidence."""
    if not isinstance(item, Mapping) or set(item) != _FIELDS:
        return None
    admitted = admitted_check(
        frozen_index, item["check_id"], item["check_version"]
    )
    if admitted is None:
        return None
    receipt = item["receipt"]
    encoded = item["observed_bytes_hex"]
    if not isinstance(receipt, Mapping) or not isinstance(encoded, str):
        return None
    try:
        observed = bytes.fromhex(encoded)
    except ValueError:
        return None
    if receipt.get("sequence") != 1 or receipt.get("previous_receipt_hash") is not None:
        return None
    runner = _RUNNERS.get(item["check_id"])
    if runner is None:
        return None
    try:
        rebuilt = runner(
            claim=item["claim"],
            verifier_id=receipt["verifier_id"],
            observed_at=receipt["observed_at"],
            observed_bytes=observed,
        )
    except (ClaimContractError, KeyError, TypeError, ValueError):
        return None
    if rebuilt != dict(receipt):
        return None
    if (
        receipt["method"]["method_id"] != admitted["procedure_id"]
        or receipt["method"]["procedure_sha256"] != admitted["procedure_sha256"]
    ):
        return None
    return receipt["result"]


def replay_evidence_references(
    references: Any,
    evidence: Mapping[str, Any],
    *,
    frozen_index: Mapping[str, Any],
) -> tuple[list[str] | None, list[str]]:
    """Replay a non-empty exact reference list and return results and used IDs."""
    if not isinstance(references, list) or not references:
        return None, []
    results: list[str] = []
    used: list[str] = []
    for evidence_id in references:
        if not isinstance(evidence_id, str) or evidence_id not in evidence:
            return None, used
        result = replay_evidence_item(
            evidence[evidence_id], frozen_index=frozen_index
        )
        if result is None:
            return None, used
        results.append(result)
        used.append(evidence_id)
    return results, used
