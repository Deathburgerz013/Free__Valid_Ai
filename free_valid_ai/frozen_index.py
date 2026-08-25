"""Append-only, hash-bound admission index for verification checks.

The index records which check procedures are admitted for a declared scope.
Admission is local to the index: it is not truth, acceptance, write authority,
or permission for a check to operate outside its recorded scope.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from typing import Any, Iterable, Mapping

from .checks import JSON_PROCEDURE_SHA256, PROCEDURE_SHA256
from .mirrored_review import MIRRORED_REVIEW_SCHEMA_SHA256
from .semantics import DEFAULT_SEMANTIC_CONTRACT


INDEX_TYPE = "free_valid_ai_frozen_check_index"
INDEX_SCHEMA_VERSION = 1
ENTRY_TYPE = "free_valid_ai_admitted_check"
ENTRY_SCHEMA_VERSION = 1

EVALUATOR_MODES = {"DETERMINISTIC", "MIRRORED_EVIDENCE_ONLY"}
CHECK_OUTCOMES = {
    "PASS", "FAIL", "UNKNOWN", "BLOCKED", "HELD", "CONTRADICTED"
}

_AUTHORITY = {
    "accepted": False,
    "truth_claimed": False,
    "write_authority": "NONE",
    "execution_authority": "NONE",
    "deletion_authority": "NONE",
}
_ENTRY_FIELDS = {
    "type", "schema_version", "check_id", "check_version",
    "procedure_id", "procedure_sha256", "input_scope",
    "detects", "required_evidence", "dependencies", "outcomes",
    "failure_behavior", "evaluator_mode", "independence_claimed",
    "active_from_index_version", "supersedes", "admission_status",
    "authority_scope", *_AUTHORITY, "entry_hash",
}
_INDEX_FIELDS = {
    "type", "schema_version", "index_version", "entries",
    "previous_index_hash", "admission_authority", *_AUTHORITY, "index_hash",
}


class FrozenCheckIndexError(ValueError):
    """A check entry or frozen index violates its closed contract."""


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
        raise FrozenCheckIndexError("value_not_canonical_json") from exc


def _clone(value: object) -> Any:
    return json.loads(_canonical(value).decode("utf-8"))


def _hash(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _sha256(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise FrozenCheckIndexError(f"{label}_invalid")
    return value


def _nonempty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise FrozenCheckIndexError(f"{label}_must_be_nonempty_string")
    return value


def _string_set(value: Any, label: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list):
        raise FrozenCheckIndexError(f"{label}_must_be_list")
    if not allow_empty and not value:
        raise FrozenCheckIndexError(f"{label}_must_not_be_empty")
    for item in value:
        _nonempty(item, f"{label}_item")
    if len(value) != len(set(value)):
        raise FrozenCheckIndexError(f"{label}_duplicates")
    if value != sorted(value):
        raise FrozenCheckIndexError(f"{label}_must_be_sorted")
    return value


def _reference(check_id: str, check_version: int) -> str:
    return f"{check_id}@{check_version}"


def create_admitted_check(
    *,
    check_id: str,
    check_version: int,
    procedure_id: str,
    procedure_sha256: str,
    input_scope: Iterable[str],
    detects: Iterable[str],
    required_evidence: Iterable[str],
    dependencies: Iterable[str] = (),
    outcomes: Iterable[str],
    failure_behavior: str,
    evaluator_mode: str = "DETERMINISTIC",
    independence_claimed: bool = True,
    active_from_index_version: int = 1,
    supersedes: str | None = None,
) -> dict[str, Any]:
    """Create one closed admission entry; the index still decides membership."""
    _nonempty(check_id, "check_id")
    if not isinstance(check_version, int) or isinstance(check_version, bool) or check_version < 1:
        raise FrozenCheckIndexError("check_version_invalid")
    _nonempty(procedure_id, "procedure_id")
    _sha256(procedure_sha256, "procedure_sha256")
    if evaluator_mode not in EVALUATOR_MODES:
        raise FrozenCheckIndexError("evaluator_mode_invalid")
    if not isinstance(independence_claimed, bool):
        raise FrozenCheckIndexError("independence_claimed_must_be_boolean")
    if evaluator_mode == "MIRRORED_EVIDENCE_ONLY" and independence_claimed:
        raise FrozenCheckIndexError("mirrored_evidence_cannot_claim_independence")
    if (
        not isinstance(active_from_index_version, int)
        or isinstance(active_from_index_version, bool)
        or active_from_index_version < 1
    ):
        raise FrozenCheckIndexError("active_from_index_version_invalid")
    if supersedes is not None:
        _nonempty(supersedes, "supersedes")

    outcome_list = sorted(outcomes)
    _string_set(outcome_list, "outcomes")
    if not set(outcome_list) <= CHECK_OUTCOMES:
        raise FrozenCheckIndexError("outcome_unknown")

    body = {
        "type": ENTRY_TYPE,
        "schema_version": ENTRY_SCHEMA_VERSION,
        "check_id": check_id,
        "check_version": check_version,
        "procedure_id": procedure_id,
        "procedure_sha256": procedure_sha256,
        "input_scope": sorted(input_scope),
        "detects": sorted(detects),
        "required_evidence": sorted(required_evidence),
        "dependencies": sorted(dependencies),
        "outcomes": outcome_list,
        "failure_behavior": _nonempty(failure_behavior, "failure_behavior"),
        "evaluator_mode": evaluator_mode,
        "independence_claimed": independence_claimed,
        "active_from_index_version": active_from_index_version,
        "supersedes": supersedes,
        "admission_status": "ADMITTED",
        "authority_scope": "DECLARED_CHECK_SCOPE_ONLY",
        **_AUTHORITY,
    }
    for field in ("input_scope", "detects", "required_evidence"):
        _string_set(body[field], field)
    _string_set(body["dependencies"], "dependencies", allow_empty=True)
    return {**body, "entry_hash": _hash(body)}


def verify_admitted_check(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise FrozenCheckIndexError("entry_must_be_object")
    entry = _clone(dict(value))
    if set(entry) != _ENTRY_FIELDS:
        raise FrozenCheckIndexError("entry_fields_mismatch")
    if entry["type"] != ENTRY_TYPE or entry["schema_version"] != ENTRY_SCHEMA_VERSION:
        raise FrozenCheckIndexError("entry_schema_mismatch")
    rebuilt = create_admitted_check(
        check_id=entry["check_id"],
        check_version=entry["check_version"],
        procedure_id=entry["procedure_id"],
        procedure_sha256=entry["procedure_sha256"],
        input_scope=entry["input_scope"],
        detects=entry["detects"],
        required_evidence=entry["required_evidence"],
        dependencies=entry["dependencies"],
        outcomes=entry["outcomes"],
        failure_behavior=entry["failure_behavior"],
        evaluator_mode=entry["evaluator_mode"],
        independence_claimed=entry["independence_claimed"],
        active_from_index_version=entry["active_from_index_version"],
        supersedes=entry["supersedes"],
    )
    for field in _ENTRY_FIELDS - {"entry_hash"}:
        if entry[field] != rebuilt[field]:
            raise FrozenCheckIndexError(f"entry_{field}_invalid")
    if not secrets.compare_digest(
        _sha256(entry["entry_hash"], "entry_hash"), rebuilt["entry_hash"]
    ):
        raise FrozenCheckIndexError("entry_hash_mismatch")
    return entry


def _validate_entries(entries: list[dict[str, Any]], index_version: int) -> None:
    references = [_reference(item["check_id"], item["check_version"]) for item in entries]
    if references != sorted(references):
        raise FrozenCheckIndexError("entries_must_be_sorted_by_reference")
    if len(references) != len(set(references)):
        raise FrozenCheckIndexError("entry_reference_duplicate")
    known: set[str] = set()
    for entry, reference in zip(entries, references):
        if entry["active_from_index_version"] > index_version:
            raise FrozenCheckIndexError("entry_active_before_admission_invalid")
        for dependency in entry["dependencies"]:
            if dependency not in known:
                raise FrozenCheckIndexError("entry_dependency_not_previously_admitted")
        supersedes = entry["supersedes"]
        if supersedes is not None:
            if supersedes not in known:
                raise FrozenCheckIndexError("entry_supersedes_unknown")
            old_id, old_version = supersedes.rsplit("@", 1)
            if old_id != entry["check_id"] or int(old_version) >= entry["check_version"]:
                raise FrozenCheckIndexError("entry_supersedes_invalid")
        known.add(reference)


def create_frozen_check_index(
    entries: Iterable[Mapping[str, Any]],
    *,
    index_version: int = 1,
    previous_index_hash: str | None = None,
) -> dict[str, Any]:
    if not isinstance(index_version, int) or isinstance(index_version, bool) or index_version < 1:
        raise FrozenCheckIndexError("index_version_invalid")
    if index_version == 1 and previous_index_hash is not None:
        raise FrozenCheckIndexError("initial_index_cannot_have_previous_hash")
    if index_version > 1:
        _sha256(previous_index_hash, "previous_index_hash")
    checked = [verify_admitted_check(entry) for entry in entries]
    if not checked:
        raise FrozenCheckIndexError("index_entries_must_not_be_empty")
    _validate_entries(checked, index_version)
    body = {
        "type": INDEX_TYPE,
        "schema_version": INDEX_SCHEMA_VERSION,
        "index_version": index_version,
        "entries": checked,
        "previous_index_hash": previous_index_hash,
        "admission_authority": "INDEX_MEMBERSHIP_ONLY",
        **_AUTHORITY,
    }
    return {**body, "index_hash": _hash(body)}


def verify_frozen_check_index(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise FrozenCheckIndexError("index_must_be_object")
    index = _clone(dict(value))
    if set(index) != _INDEX_FIELDS:
        raise FrozenCheckIndexError("index_fields_mismatch")
    if index["type"] != INDEX_TYPE or index["schema_version"] != INDEX_SCHEMA_VERSION:
        raise FrozenCheckIndexError("index_schema_mismatch")
    rebuilt = create_frozen_check_index(
        index["entries"],
        index_version=index["index_version"],
        previous_index_hash=index["previous_index_hash"],
    )
    for field in _INDEX_FIELDS - {"index_hash"}:
        if index[field] != rebuilt[field]:
            raise FrozenCheckIndexError(f"index_{field}_invalid")
    if not secrets.compare_digest(
        _sha256(index["index_hash"], "index_hash"), rebuilt["index_hash"]
    ):
        raise FrozenCheckIndexError("index_hash_mismatch")
    return index


def extend_frozen_check_index(
    previous: Mapping[str, Any], candidate: Mapping[str, Any]
) -> dict[str, Any]:
    """Append one newly admitted entry without rewriting any prior entry."""
    prior = verify_frozen_check_index(previous)
    entry = verify_admitted_check(candidate)
    next_version = prior["index_version"] + 1
    if entry["active_from_index_version"] != next_version:
        raise FrozenCheckIndexError("candidate_admission_version_mismatch")
    entries = [*prior["entries"], entry]
    entries.sort(key=lambda item: _reference(item["check_id"], item["check_version"]))
    extended = create_frozen_check_index(
        entries,
        index_version=next_version,
        previous_index_hash=prior["index_hash"],
    )
    old_by_hash = {item["entry_hash"]: item for item in prior["entries"]}
    new_by_hash = {item["entry_hash"]: item for item in extended["entries"]}
    if any(new_by_hash.get(key) != value for key, value in old_by_hash.items()):
        raise FrozenCheckIndexError("prior_entry_rewritten")
    return extended


def admitted_check(
    index: Mapping[str, Any], check_id: str, check_version: int | None = None
) -> dict[str, Any] | None:
    """Return an admitted version, or the latest non-superseded version."""
    verified = verify_frozen_check_index(index)
    matches = [item for item in verified["entries"] if item["check_id"] == check_id]
    if check_version is not None:
        return next((item for item in matches if item["check_version"] == check_version), None)
    superseded = {item["supersedes"] for item in matches if item["supersedes"] is not None}
    active = [
        item for item in matches
        if _reference(item["check_id"], item["check_version"]) not in superseded
    ]
    return max(active, key=lambda item: item["check_version"], default=None)


def _procedure_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# Bootstrap records the verification surfaces present when schema version 1 was
# introduced.  It admits procedures, not their conclusions.  The mirrored
# reviewer is recorded only as non-independent evidence.
DEFAULT_FROZEN_CHECK_INDEX = create_frozen_check_index(
    [
        create_admitted_check(
            check_id="claim_contract",
            check_version=1,
            procedure_id="closed-hash-bound-claim-and-receipt-v1",
            procedure_sha256=_procedure_digest(
                "verify closed claim schema and claim hash; verify closed receipt "
                "schema, declared verifier separation, receipt hash, and receipt chain"
            ),
            input_scope=["claim records", "verification receipt records"],
            detects=["claim or receipt tampering", "receipt chain mismatch"],
            required_evidence=["claim record", "verification receipt record"],
            outcomes=["PASS", "FAIL"],
            failure_behavior="reject malformed, tampered, substituted, or discontinuous records",
        ),
        create_admitted_check(
            check_id="interception_receipt",
            check_version=1,
            procedure_id="closed-output-interception-v1",
            procedure_sha256=_procedure_digest(
                "verify received-turn binding, draft or correction bytes, sorted unique "
                "checks, release decision, correction basis, authority fields, and receipt hash"
            ),
            input_scope=["intercepted assistant output records"],
            detects=["invalid release", "output or evidence substitution"],
            required_evidence=["interception record", "received turn record"],
            outcomes=["BLOCKED", "PASS", "UNKNOWN"],
            failure_behavior="release no output when any check fails or remains unknown",
        ),
        create_admitted_check(
            check_id="json_pointer_equals",
            check_version=1,
            procedure_id="json_pointer_equals-v1",
            procedure_sha256=JSON_PROCEDURE_SHA256,
            input_scope=["source-bound UTF-8 JSON bytes and RFC 6901 pointer"],
            detects=["absent pointer", "source identity change", "typed value difference"],
            required_evidence=["bound claim", "presented source bytes"],
            outcomes=["BLOCKED", "CONTRADICTED", "HELD", "UNKNOWN"],
            failure_behavior="block malformed bound JSON and preserve identity mismatch as unknown",
        ),
        create_admitted_check(
            check_id="mirrored_review_receipt",
            check_version=1,
            procedure_id="mirrored-review-schema-v1",
            procedure_sha256=MIRRORED_REVIEW_SCHEMA_SHA256,
            input_scope=["same-carrier review JSON and its structural receipt"],
            detects=["malformed review", "review receipt or schema substitution"],
            required_evidence=["raw review JSON", "review receipt"],
            outcomes=["BLOCKED", "PASS", "UNKNOWN"],
            failure_behavior="block malformed or unknown review; never infer independent verification",
            evaluator_mode="MIRRORED_EVIDENCE_ONLY",
            independence_claimed=False,
        ),
        create_admitted_check(
            check_id="received_turn_receipt",
            check_version=1,
            procedure_id="exact-received-turn-binding-v1",
            procedure_sha256=_procedure_digest(
                "verify exact received bytes, role, sequence, previous turn hash, semantic "
                "contract identity, authority fields, and received-turn hash"
            ),
            input_scope=["received user or assistant turn bytes"],
            detects=["received byte substitution", "turn chain or semantic identity mismatch"],
            required_evidence=["received turn record", "semantic contract"],
            outcomes=["PASS", "FAIL"],
            failure_behavior="reject altered, unbound, or discontinuous received turns",
        ),
        create_admitted_check(
            check_id="semantic_contract",
            check_version=1,
            procedure_id="closed-semantic-contract-v1",
            procedure_sha256=DEFAULT_SEMANTIC_CONTRACT["contract_hash"],
            input_scope=["Simulator semantic contract records"],
            detects=["semantic identity or relationship change", "unknown contract fields"],
            required_evidence=["semantic contract record"],
            outcomes=["PASS", "FAIL"],
            failure_behavior="reject changed meanings, unknown fields, or asymmetric relationships",
        ),
        create_admitted_check(
            check_id="source_sha256_equals",
            check_version=1,
            procedure_id="source_sha256_equals-v1",
            procedure_sha256=PROCEDURE_SHA256,
            input_scope=["source-bound presented bytes"],
            detects=["expected digest difference", "source identity change"],
            required_evidence=["bound claim", "presented source bytes"],
            outcomes=["BLOCKED", "CONTRADICTED", "HELD", "UNKNOWN"],
            failure_behavior="block absent bytes and preserve identity mismatch as unknown",
        ),
    ]
)
