"""Hash-bound receive and pre-presentation interception contracts.

Records exact turn bytes and constrains release decisions. It calls no model,
judges no semantic truth, and grants no authority.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from typing import Any, Iterable, Mapping

from .semantics import DEFAULT_SEMANTIC_CONTRACT, verify_semantic_contract

RECEIVED_TURN_TYPE = "free_valid_ai_received_turn"
RECEIVED_TURN_VERSION = 1
INTERCEPTION_TYPE = "free_valid_ai_turn_interception"
INTERCEPTION_VERSION = 1
ROLES = {"SYSTEM", "TOOL", "USER"}
CHECK_RESULTS = {"PASS", "FAIL", "UNKNOWN"}
DECISIONS = {"UNCHANGED", "CORRECTED", "BLOCKED", "UNKNOWN"}
_AUTHORITY = {
    "accepted": False,
    "truth_claimed": False,
    "write_authority": "NONE",
    "execution_authority": "NONE",
    "deletion_authority": "NONE",
}
_RECEIVED_FIELDS = {
    "type", "version", "role", "sequence", "previous_received_turn_hash",
    "content_encoding", "content_base64", "content_byte_count",
    "content_sha256", "semantic_contract_version", "semantic_contract_hash",
    *_AUTHORITY, "received_turn_hash",
}
_CHECK_FIELDS = {"check_id", "result", "evidence_sha256"}
_INTERCEPTION_FIELDS = {
    "type", "version", "received_turn_hash", "draft_encoding",
    "draft_base64", "draft_byte_count", "draft_sha256", "checks", "decision",
    "released_encoding", "released_base64", "released_byte_count",
    "released_sha256", "correction_basis_sha256", *_AUTHORITY,
    "interception_hash",
}


class TurnBoundaryError(ValueError):
    """A received turn or interception violates its closed contract."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise TurnBoundaryError("value_not_canonical_json") from exc


def _hash(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256(value: Any, label: str) -> str:
    if (
        not isinstance(value, str) or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise TurnBoundaryError(f"{label}_must_be_lowercase_sha256")
    return value


def _closed(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TurnBoundaryError(f"{label}_must_be_object")
    decoded = json.loads(_canonical(dict(value)).decode("utf-8"))
    if set(decoded) != fields:
        raise TurnBoundaryError(f"{label}_fields_mismatch")
    return decoded


def _require_bytes(value: Any, label: str) -> bytes:
    if not isinstance(value, bytes):
        raise TurnBoundaryError(f"{label}_must_be_bytes")
    return value


def _bind(raw: bytes) -> dict[str, Any]:
    return {
        "encoding": "base64",
        "base64": base64.b64encode(raw).decode("ascii"),
        "byte_count": len(raw),
        "sha256": _digest(raw),
    }


def _decode(
    encoding: Any, encoded: Any, count: Any, digest: Any, label: str
) -> bytes:
    if encoding != "base64" or not isinstance(encoded, str):
        raise TurnBoundaryError(f"{label}_encoding_invalid")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise TurnBoundaryError(f"{label}_base64_invalid") from exc
    if not isinstance(count, int) or isinstance(count, bool) or len(raw) != count:
        raise TurnBoundaryError(f"{label}_byte_count_mismatch")
    if not secrets.compare_digest(_sha256(digest, f"{label}_sha256"), _digest(raw)):
        raise TurnBoundaryError(f"{label}_sha256_mismatch")
    return raw


def create_received_turn(
    content: bytes,
    *,
    role: str,
    sequence: int,
    previous_received_turn_hash: str | None = None,
    semantic_contract: Mapping[str, Any] = DEFAULT_SEMANTIC_CONTRACT,
) -> dict[str, Any]:
    """Bind exact externally received bytes before interpretation."""
    raw = _require_bytes(content, "content")
    if role not in ROLES:
        raise TurnBoundaryError("role_invalid")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
        raise TurnBoundaryError("sequence_invalid")
    if sequence == 0 and previous_received_turn_hash is not None:
        raise TurnBoundaryError("initial_turn_cannot_have_previous_hash")
    if sequence > 0:
        _sha256(previous_received_turn_hash, "previous_received_turn_hash")
    contract = verify_semantic_contract(semantic_contract)
    bound = _bind(raw)
    body = {
        "type": RECEIVED_TURN_TYPE,
        "version": RECEIVED_TURN_VERSION,
        "role": role,
        "sequence": sequence,
        "previous_received_turn_hash": previous_received_turn_hash,
        "content_encoding": bound["encoding"],
        "content_base64": bound["base64"],
        "content_byte_count": bound["byte_count"],
        "content_sha256": bound["sha256"],
        "semantic_contract_version": contract["version"],
        "semantic_contract_hash": contract["contract_hash"],
        **_AUTHORITY,
    }
    received = {**body, "received_turn_hash": _hash(body)}
    verify_received_turn(received, semantic_contract=contract)
    return received


def verify_received_turn(
    value: Mapping[str, Any],
    *,
    semantic_contract: Mapping[str, Any] = DEFAULT_SEMANTIC_CONTRACT,
) -> bytes:
    received = _closed(value, _RECEIVED_FIELDS, "received_turn")
    if received["type"] != RECEIVED_TURN_TYPE or received["version"] != RECEIVED_TURN_VERSION:
        raise TurnBoundaryError("received_turn_schema_mismatch")
    if received["role"] not in ROLES:
        raise TurnBoundaryError("received_turn_role_invalid")
    sequence = received["sequence"]
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
        raise TurnBoundaryError("received_turn_sequence_invalid")
    previous = received["previous_received_turn_hash"]
    if sequence == 0 and previous is not None:
        raise TurnBoundaryError("received_turn_initial_previous_hash_invalid")
    if sequence > 0:
        _sha256(previous, "received_turn_previous_hash")
    contract = verify_semantic_contract(semantic_contract)
    if (
        received["semantic_contract_version"] != contract["version"]
        or received["semantic_contract_hash"] != contract["contract_hash"]
    ):
        raise TurnBoundaryError("received_turn_semantic_contract_mismatch")
    for field, expected in _AUTHORITY.items():
        if received[field] != expected:
            raise TurnBoundaryError(f"received_turn_{field}_invalid")
    raw = _decode(
        received["content_encoding"], received["content_base64"],
        received["content_byte_count"], received["content_sha256"],
        "received_turn_content",
    )
    body = {key: received[key] for key in _RECEIVED_FIELDS - {"received_turn_hash"}}
    if not secrets.compare_digest(
        _sha256(received["received_turn_hash"], "received_turn_hash"), _hash(body)
    ):
        raise TurnBoundaryError("received_turn_hash_mismatch")
    return raw


def _check(value: Any) -> dict[str, Any]:
    check = _closed(value, _CHECK_FIELDS, "check")
    if not isinstance(check["check_id"], str) or not check["check_id"].strip():
        raise TurnBoundaryError("check_id_invalid")
    if check["result"] not in CHECK_RESULTS:
        raise TurnBoundaryError("check_result_invalid")
    _sha256(check["evidence_sha256"], "check_evidence_sha256")
    return check


def create_interception(
    received_turn: Mapping[str, Any],
    draft: bytes,
    *,
    checks: Iterable[Mapping[str, Any]],
    released: bytes | None = None,
    correction_basis_sha256: str | None = None,
    semantic_contract: Mapping[str, Any] = DEFAULT_SEMANTIC_CONTRACT,
) -> dict[str, Any]:
    """Hold a draft and derive the only release decision evidence permits."""
    verify_received_turn(received_turn, semantic_contract=semantic_contract)
    draft_raw = _require_bytes(draft, "draft")
    checked = [_check(check) for check in checks]
    if not checked:
        raise TurnBoundaryError("checks_must_not_be_empty")
    ids = [check["check_id"] for check in checked]
    if len(ids) != len(set(ids)) or ids != sorted(ids):
        raise TurnBoundaryError("checks_must_have_unique_sorted_ids")
    results = {check["result"] for check in checked}
    if "FAIL" in results:
        decision = "BLOCKED"
    elif "UNKNOWN" in results:
        decision = "UNKNOWN"
    elif released is None:
        decision = "BLOCKED"
    else:
        decision = "UNCHANGED" if _require_bytes(released, "released") == draft_raw else "CORRECTED"
    if decision in {"BLOCKED", "UNKNOWN"}:
        if released is not None or correction_basis_sha256 is not None:
            raise TurnBoundaryError("unreleased_decision_cannot_release_or_correct")
        release_bound = None
    else:
        release_bound = _bind(_require_bytes(released, "released"))
        if decision == "UNCHANGED" and correction_basis_sha256 is not None:
            raise TurnBoundaryError("unchanged_decision_cannot_have_correction_basis")
        if decision == "CORRECTED":
            _sha256(correction_basis_sha256, "correction_basis_sha256")
    draft_bound = _bind(draft_raw)
    body = {
        "type": INTERCEPTION_TYPE,
        "version": INTERCEPTION_VERSION,
        "received_turn_hash": received_turn["received_turn_hash"],
        "draft_encoding": draft_bound["encoding"],
        "draft_base64": draft_bound["base64"],
        "draft_byte_count": draft_bound["byte_count"],
        "draft_sha256": draft_bound["sha256"],
        "checks": checked,
        "decision": decision,
        "released_encoding": None if release_bound is None else release_bound["encoding"],
        "released_base64": None if release_bound is None else release_bound["base64"],
        "released_byte_count": None if release_bound is None else release_bound["byte_count"],
        "released_sha256": None if release_bound is None else release_bound["sha256"],
        "correction_basis_sha256": correction_basis_sha256,
        **_AUTHORITY,
    }
    item = {**body, "interception_hash": _hash(body)}
    verify_interception(item, received_turn=received_turn, semantic_contract=semantic_contract)
    return item


def verify_interception(
    value: Mapping[str, Any],
    *,
    received_turn: Mapping[str, Any],
    semantic_contract: Mapping[str, Any] = DEFAULT_SEMANTIC_CONTRACT,
) -> bytes | None:
    verify_received_turn(received_turn, semantic_contract=semantic_contract)
    item = _closed(value, _INTERCEPTION_FIELDS, "interception")
    if item["type"] != INTERCEPTION_TYPE or item["version"] != INTERCEPTION_VERSION:
        raise TurnBoundaryError("interception_schema_mismatch")
    if item["received_turn_hash"] != received_turn["received_turn_hash"]:
        raise TurnBoundaryError("interception_received_turn_mismatch")
    draft = _decode(
        item["draft_encoding"], item["draft_base64"], item["draft_byte_count"],
        item["draft_sha256"], "interception_draft",
    )
    checks = [_check(check) for check in item["checks"]]
    if not checks:
        raise TurnBoundaryError("interception_checks_empty")
    ids = [check["check_id"] for check in checks]
    if len(ids) != len(set(ids)) or ids != sorted(ids):
        raise TurnBoundaryError("interception_checks_not_unique_sorted")
    release_fields = (
        item["released_encoding"], item["released_base64"],
        item["released_byte_count"], item["released_sha256"],
    )
    if all(field is None for field in release_fields):
        released = None
    elif any(field is None for field in release_fields):
        raise TurnBoundaryError("interception_release_fields_partial")
    else:
        released = _decode(*release_fields, "interception_released")
    results = {check["result"] for check in checks}
    expected = (
        "BLOCKED" if "FAIL" in results else
        "UNKNOWN" if "UNKNOWN" in results else
        "BLOCKED" if released is None else
        "UNCHANGED" if released == draft else "CORRECTED"
    )
    if item["decision"] not in DECISIONS or item["decision"] != expected:
        raise TurnBoundaryError("interception_decision_not_supported")
    basis = item["correction_basis_sha256"]
    if expected == "CORRECTED":
        _sha256(basis, "interception_correction_basis_sha256")
    elif basis is not None:
        raise TurnBoundaryError("interception_correction_basis_not_permitted")
    if expected in {"BLOCKED", "UNKNOWN"} and released is not None:
        raise TurnBoundaryError("interception_release_not_permitted")
    for field, expected_value in _AUTHORITY.items():
        if item[field] != expected_value:
            raise TurnBoundaryError(f"interception_{field}_invalid")
    body = {key: item[key] for key in _INTERCEPTION_FIELDS - {"interception_hash"}}
    if not secrets.compare_digest(
        _sha256(item["interception_hash"], "interception_hash"), _hash(body)
    ):
        raise TurnBoundaryError("interception_hash_mismatch")
    return released
