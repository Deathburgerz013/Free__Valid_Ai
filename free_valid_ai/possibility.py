"""Bounded possibility assessment without global possibility claims."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable, Mapping

from .evidence import replay_evidence_references
from .frozen_index import verify_frozen_check_index


ASSESSMENTS = {
    "POSSIBLE_WITHIN_CONSTRAINTS",
    "IMPOSSIBLE_UNDER_CONSTRAINTS",
    "CURRENTLY_INFEASIBLE",
    "OUT_OF_SCOPE",
    "UNKNOWN",
}
CONSTRAINT_KINDS = {"LOGICAL", "RESOURCE", "SCOPE"}


class PossibilityAssessmentError(ValueError):
    """The bounded possibility contract is malformed."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PossibilityAssessmentError("value_not_canonical_json") from exc


def _clone(value: object) -> Any:
    return json.loads(_canonical(value).decode("utf-8"))


def _hash(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _nonempty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PossibilityAssessmentError(f"{label}_must_be_nonempty_string")
    return value


def assess_possibility(
    *,
    scope: Mapping[str, Any],
    constraints: Iterable[Mapping[str, Any]],
    evidence: Mapping[str, Mapping[str, Any]],
    frozen_index: Mapping[str, Any],
) -> dict[str, Any]:
    """Compute a bounded assessment; callers cannot select its outcome."""
    index = verify_frozen_check_index(frozen_index)
    declared_scope = _clone(dict(scope))
    if set(declared_scope) != {"assessment_id", "proposal", "environment_id"}:
        raise PossibilityAssessmentError("scope_fields_mismatch")
    for field, value in declared_scope.items():
        _nonempty(value, f"scope_{field}")

    if isinstance(constraints, (str, bytes, Mapping)):
        raise PossibilityAssessmentError("constraints_must_be_iterable_of_objects")
    items = [_clone(dict(item)) for item in constraints]
    if not items:
        raise PossibilityAssessmentError("constraints_must_not_be_empty")
    evidence_items = _clone(dict(evidence))
    identifiers: set[str] = set()
    used: list[str] = []
    unknown: list[str] = []
    blocked: list[dict[str, str]] = []

    for item in items:
        if set(item) != {"constraint_id", "kind", "requirement", "evidence"}:
            raise PossibilityAssessmentError("constraint_fields_mismatch")
        identifier = _nonempty(item["constraint_id"], "constraint_id")
        if identifier in identifiers:
            raise PossibilityAssessmentError("constraint_id_duplicate")
        identifiers.add(identifier)
        if item["kind"] not in CONSTRAINT_KINDS:
            raise PossibilityAssessmentError("constraint_kind_invalid")
        _nonempty(item["requirement"], "constraint_requirement")
        results, references = replay_evidence_references(
            item["evidence"], evidence_items, frozen_index=index
        )
        used.extend(references)
        if results is None or any(result in {"UNKNOWN", "BLOCKED"} for result in results):
            unknown.append(f"constraint_evidence_incomplete:{identifier}")
        elif any(result == "CONTRADICTED" for result in results):
            blocked.append({"constraint_id": identifier, "kind": item["kind"]})

    if set(used) != set(evidence_items):
        unknown.append("evidence_set_not_exact")

    kinds = {item["kind"] for item in blocked}
    if unknown:
        assessment = "UNKNOWN"
    elif "LOGICAL" in kinds:
        assessment = "IMPOSSIBLE_UNDER_CONSTRAINTS"
    elif "SCOPE" in kinds:
        assessment = "OUT_OF_SCOPE"
    elif "RESOURCE" in kinds:
        assessment = "CURRENTLY_INFEASIBLE"
    else:
        assessment = "POSSIBLE_WITHIN_CONSTRAINTS"

    body = {
        "type": "free_valid_ai_bounded_possibility_assessment",
        "schema_version": 1,
        "scope": declared_scope,
        "frozen_index_hash": index["index_hash"],
        "constraints": items,
        "evidence": evidence_items,
        "assessment": assessment,
        "blocking_constraints": sorted(blocked, key=lambda item: item["constraint_id"]),
        "unknown_reasons": sorted(set(unknown)),
        "reassessment_required_if_constraints_change": True,
        "accepted": False,
        "truth_claimed": False,
        "write_authority": "NONE",
        "execution_authority": "NONE",
    }
    return {**body, "assessment_hash": _hash(body)}


def verify_possibility_assessment(
    value: Mapping[str, Any],
    *,
    frozen_index: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify the closed receipt and recompute its caller-independent result."""
    if not isinstance(value, Mapping):
        raise PossibilityAssessmentError("assessment_must_be_object")
    received = _clone(dict(value))
    fields = {
        "type", "schema_version", "scope", "frozen_index_hash", "constraints",
        "evidence", "assessment", "blocking_constraints", "unknown_reasons",
        "reassessment_required_if_constraints_change", "accepted",
        "truth_claimed", "write_authority", "execution_authority",
        "assessment_hash",
    }
    if set(received) != fields:
        raise PossibilityAssessmentError("assessment_fields_mismatch")
    if (
        received["type"] != "free_valid_ai_bounded_possibility_assessment"
        or received["schema_version"] != 1
    ):
        raise PossibilityAssessmentError("assessment_schema_mismatch")
    rebuilt = assess_possibility(
        scope=received["scope"],
        constraints=received["constraints"],
        evidence=received["evidence"],
        frozen_index=frozen_index,
    )
    if received != rebuilt:
        if received.get("assessment_hash") != rebuilt["assessment_hash"]:
            raise PossibilityAssessmentError("assessment_hash_mismatch")
        raise PossibilityAssessmentError("assessment_content_mismatch")
    return received
