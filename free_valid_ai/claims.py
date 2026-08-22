"""Hash-bound claims and append-only verification receipts.

This module verifies record integrity and declared boundaries.  It does not
grant truth, acceptance, write, deletion, or execution authority.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime
from typing import Any, Iterable, Mapping


CLAIM_TYPE = "free_valid_claim"
CLAIM_VERSION = 1
RECEIPT_TYPE = "free_valid_claim_verification_receipt"
RECEIPT_VERSION = 1

RESULTS = {"HELD", "CONTRADICTED", "UNKNOWN", "BLOCKED"}
USAGE_DECISIONS = {"PERMITTED", "PROHIBITED"}

_CLAIM_FIELDS = {
    "type", "version", "statement", "scope", "conditions", "sources",
    "author", "observed_at", "valid_until", "supersedes_claim_hash",
    "accepted", "truth_claimed", "write_authority", "execution_authority",
    "deletion_authority", "claim_hash",
}
_AUTHOR_FIELDS = {"author_id", "display_name"}
_SOURCE_FIELDS = {
    "source_id", "locator", "creator_id", "creator_name", "license",
    "content_sha256", "usage_terms",
}
_USAGE_FIELDS = {
    "training_use", "commercial_use", "redistribution",
    "attribution_required", "compensation_terms", "consent_receipt",
}
_RECEIPT_FIELDS = {
    "type", "version", "claim_hash", "verifier_id", "method",
    "observed_at", "evidence", "result", "limitations", "sequence",
    "previous_receipt_hash", "accepted", "truth_claimed",
    "write_authority", "execution_authority", "deletion_authority",
    "receipt_hash",
}
_METHOD_FIELDS = {"method_id", "description", "procedure_sha256"}
_EVIDENCE_FIELDS = {"evidence_id", "locator", "content_sha256"}


class ClaimContractError(ValueError):
    """A claim or receipt violates the closed contract."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ClaimContractError("value_not_canonical_json") from exc


def _hash(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _closed(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ClaimContractError(f"{label}_must_be_object")
    decoded = json.loads(_canonical(dict(value)).decode("utf-8"))
    if set(decoded) != fields:
        raise ClaimContractError(f"{label}_fields_mismatch")
    return decoded


def _nonempty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ClaimContractError(f"{label}_must_be_nonempty_string")
    return value


def _sha256(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise ClaimContractError(f"{label}_must_be_lowercase_sha256")
    return value


def _moment(value: Any, label: str) -> datetime:
    text = _nonempty(value, label)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ClaimContractError(f"{label}_must_be_iso8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ClaimContractError(f"{label}_must_include_timezone")
    return parsed


def _strings(values: Any, label: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(values, list) or (not values and not allow_empty):
        raise ClaimContractError(f"{label}_must_be_list")
    return [_nonempty(value, f"{label}_item") for value in values]


def _author(value: Any) -> dict[str, Any]:
    author = _closed(value, _AUTHOR_FIELDS, "author")
    _nonempty(author["author_id"], "author_id")
    _nonempty(author["display_name"], "author_display_name")
    return author


def _source(value: Any) -> dict[str, Any]:
    source = _closed(value, _SOURCE_FIELDS, "source")
    for field in (
        "source_id", "locator", "creator_id", "creator_name", "license"
    ):
        _nonempty(source[field], f"source_{field}")
    _sha256(source["content_sha256"], "source_content_sha256")
    usage = _closed(source["usage_terms"], _USAGE_FIELDS, "usage_terms")
    for field in ("training_use", "commercial_use", "redistribution"):
        if usage[field] not in USAGE_DECISIONS:
            raise ClaimContractError(f"usage_{field}_must_be_explicit")
    if not isinstance(usage["attribution_required"], bool):
        raise ClaimContractError("usage_attribution_required_must_be_boolean")
    _nonempty(usage["compensation_terms"], "usage_compensation_terms")
    _nonempty(usage["consent_receipt"], "usage_consent_receipt")
    return source


def _claim_body(
    *,
    statement: str,
    scope: Mapping[str, Any],
    conditions: list[str],
    sources: list[Mapping[str, Any]],
    author: Mapping[str, Any],
    observed_at: str,
    valid_until: str | None,
    supersedes_claim_hash: str | None,
) -> dict[str, Any]:
    if not isinstance(scope, Mapping) or not scope:
        raise ClaimContractError("scope_must_be_nonempty_object")
    closed_scope = json.loads(_canonical(dict(scope)).decode("utf-8"))
    checked_sources = [_source(source) for source in sources]
    if not checked_sources:
        raise ClaimContractError("sources_must_not_be_empty")
    observed = _moment(observed_at, "observed_at")
    if valid_until is not None:
        until = _moment(valid_until, "valid_until")
        if until <= observed:
            raise ClaimContractError("valid_until_must_follow_observed_at")
    if supersedes_claim_hash is not None:
        _sha256(supersedes_claim_hash, "supersedes_claim_hash")
    return {
        "type": CLAIM_TYPE,
        "version": CLAIM_VERSION,
        "statement": _nonempty(statement, "statement"),
        "scope": closed_scope,
        "conditions": _strings(conditions, "conditions"),
        "sources": checked_sources,
        "author": _author(author),
        "observed_at": observed_at,
        "valid_until": valid_until,
        "supersedes_claim_hash": supersedes_claim_hash,
        "accepted": False,
        "truth_claimed": False,
        "write_authority": "NONE",
        "execution_authority": "NONE",
        "deletion_authority": "NONE",
    }


def create_claim(
    *,
    statement: str,
    scope: Mapping[str, Any],
    conditions: list[str],
    sources: list[Mapping[str, Any]],
    author: Mapping[str, Any],
    observed_at: str,
    valid_until: str | None = None,
    supersedes: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Create an UNVERIFIED claim without granting authority."""
    supersedes_hash = None
    if supersedes is not None:
        verify_claim(supersedes)
        supersedes_hash = supersedes["claim_hash"]
    body = _claim_body(
        statement=statement,
        scope=scope,
        conditions=conditions,
        sources=sources,
        author=author,
        observed_at=observed_at,
        valid_until=valid_until,
        supersedes_claim_hash=supersedes_hash,
    )
    claim = {**body, "claim_hash": _hash(body)}
    verify_claim(claim)
    return claim


def verify_claim(value: Mapping[str, Any]) -> bool:
    """Verify closed schema, declared source terms, and the claim hash."""
    claim = _closed(value, _CLAIM_FIELDS, "claim")
    if claim["type"] != CLAIM_TYPE or claim["version"] != CLAIM_VERSION:
        raise ClaimContractError("claim_schema_mismatch")
    rebuilt = _claim_body(
        statement=claim["statement"],
        scope=claim["scope"],
        conditions=claim["conditions"],
        sources=claim["sources"],
        author=claim["author"],
        observed_at=claim["observed_at"],
        valid_until=claim["valid_until"],
        supersedes_claim_hash=claim["supersedes_claim_hash"],
    )
    if any(claim[key] != rebuilt[key] for key in rebuilt):
        raise ClaimContractError("claim_boundary_mismatch")
    supplied = _sha256(claim["claim_hash"], "claim_hash")
    if not secrets.compare_digest(supplied, _hash(rebuilt)):
        raise ClaimContractError("claim_hash_mismatch")
    return True


def _method(value: Any) -> dict[str, Any]:
    method = _closed(value, _METHOD_FIELDS, "method")
    _nonempty(method["method_id"], "method_id")
    _nonempty(method["description"], "method_description")
    _sha256(method["procedure_sha256"], "method_procedure_sha256")
    return method


def _evidence(value: Any) -> dict[str, Any]:
    evidence = _closed(value, _EVIDENCE_FIELDS, "evidence")
    _nonempty(evidence["evidence_id"], "evidence_id")
    _nonempty(evidence["locator"], "evidence_locator")
    _sha256(evidence["content_sha256"], "evidence_content_sha256")
    return evidence


def _receipt_body(
    *,
    claim: Mapping[str, Any],
    verifier_id: str,
    method: Mapping[str, Any],
    observed_at: str,
    evidence: list[Mapping[str, Any]],
    result: str,
    limitations: list[str],
    sequence: int,
    previous_receipt_hash: str | None,
) -> dict[str, Any]:
    verify_claim(claim)
    verifier = _nonempty(verifier_id, "verifier_id")
    if verifier == claim["author"]["author_id"]:
        raise ClaimContractError("verifier_must_differ_from_claim_author")
    checked_evidence = [_evidence(item) for item in evidence]
    if not checked_evidence:
        raise ClaimContractError("evidence_must_not_be_empty")
    when = _moment(observed_at, "receipt_observed_at")
    if when < _moment(claim["observed_at"], "claim_observed_at"):
        raise ClaimContractError("receipt_cannot_precede_claim")
    if result not in RESULTS:
        raise ClaimContractError("result_invalid")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise ClaimContractError("sequence_must_be_positive_integer")
    if previous_receipt_hash is not None:
        _sha256(previous_receipt_hash, "previous_receipt_hash")
    return {
        "type": RECEIPT_TYPE,
        "version": RECEIPT_VERSION,
        "claim_hash": claim["claim_hash"],
        "verifier_id": verifier,
        "method": _method(method),
        "observed_at": observed_at,
        "evidence": checked_evidence,
        "result": result,
        "limitations": _strings(limitations, "limitations", allow_empty=True),
        "sequence": sequence,
        "previous_receipt_hash": previous_receipt_hash,
        "accepted": False,
        "truth_claimed": False,
        "write_authority": "NONE",
        "execution_authority": "NONE",
        "deletion_authority": "NONE",
    }


def create_verification_receipt(
    *,
    claim: Mapping[str, Any],
    verifier_id: str,
    method: Mapping[str, Any],
    observed_at: str,
    evidence: list[Mapping[str, Any]],
    result: str,
    limitations: list[str] | None = None,
    previous_receipt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Append one declared check result to a claim's receipt chain."""
    sequence = 1
    previous_hash = None
    if previous_receipt is not None:
        verify_verification_receipt(previous_receipt, claim=claim)
        sequence = previous_receipt["sequence"] + 1
        previous_hash = previous_receipt["receipt_hash"]
    body = _receipt_body(
        claim=claim,
        verifier_id=verifier_id,
        method=method,
        observed_at=observed_at,
        evidence=evidence,
        result=result,
        limitations=list(limitations or []),
        sequence=sequence,
        previous_receipt_hash=previous_hash,
    )
    receipt = {**body, "receipt_hash": _hash(body)}
    verify_verification_receipt(receipt, claim=claim)
    return receipt


def verify_verification_receipt(
    value: Mapping[str, Any], *, claim: Mapping[str, Any]
) -> bool:
    """Verify one receipt's schema, claim binding, and hash."""
    receipt = _closed(value, _RECEIPT_FIELDS, "receipt")
    if receipt["type"] != RECEIPT_TYPE or receipt["version"] != RECEIPT_VERSION:
        raise ClaimContractError("receipt_schema_mismatch")
    rebuilt = _receipt_body(
        claim=claim,
        verifier_id=receipt["verifier_id"],
        method=receipt["method"],
        observed_at=receipt["observed_at"],
        evidence=receipt["evidence"],
        result=receipt["result"],
        limitations=receipt["limitations"],
        sequence=receipt["sequence"],
        previous_receipt_hash=receipt["previous_receipt_hash"],
    )
    if receipt["claim_hash"] != claim["claim_hash"]:
        raise ClaimContractError("receipt_claim_hash_mismatch")
    if any(receipt[key] != rebuilt[key] for key in rebuilt):
        raise ClaimContractError("receipt_boundary_mismatch")
    supplied = _sha256(receipt["receipt_hash"], "receipt_hash")
    if not secrets.compare_digest(supplied, _hash(rebuilt)):
        raise ClaimContractError("receipt_hash_mismatch")
    return True


def assess_claim(
    claim: Mapping[str, Any],
    receipts: Iterable[Mapping[str, Any]],
    *,
    as_of: str,
) -> dict[str, Any]:
    """Assess the latest eligible receipt without claiming timeless truth."""
    verify_claim(claim)
    moment = _moment(as_of, "as_of")
    if moment < _moment(claim["observed_at"], "claim_observed_at"):
        raise ClaimContractError("assessment_cannot_precede_claim")
    chain = list(receipts)
    previous = None
    eligible: list[Mapping[str, Any]] = []
    for expected_sequence, receipt in enumerate(chain, start=1):
        verify_verification_receipt(receipt, claim=claim)
        expected_previous = None if previous is None else previous["receipt_hash"]
        if receipt["sequence"] != expected_sequence:
            raise ClaimContractError("receipt_sequence_gap")
        if receipt["previous_receipt_hash"] != expected_previous:
            raise ClaimContractError("receipt_chain_mismatch")
        if _moment(receipt["observed_at"], "receipt_observed_at") <= moment:
            eligible.append(receipt)
        previous = receipt
    if claim["valid_until"] is not None and moment > _moment(
        claim["valid_until"], "valid_until"
    ):
        status = "STALE"
        latest_hash = eligible[-1]["receipt_hash"] if eligible else None
    elif not eligible:
        status = "UNVERIFIED"
        latest_hash = None
    else:
        status = eligible[-1]["result"]
        latest_hash = eligible[-1]["receipt_hash"]
    body = {
        "type": "free_valid_claim_assessment",
        "version": 1,
        "claim_hash": claim["claim_hash"],
        "as_of": as_of,
        "status": status,
        "latest_receipt_hash": latest_hash,
        "receipt_count": len(eligible),
        "accepted": False,
        "truth_claimed": False,
        "write_authority": "NONE",
        "execution_authority": "NONE",
        "deletion_authority": "NONE",
    }
    return {**body, "assessment_hash": _hash(body)}
