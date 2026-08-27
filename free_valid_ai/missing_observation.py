"""Bounded coverage audit for declared observations."""

from __future__ import annotations

import hashlib
import inspect
import json
from typing import Any, Iterable, Mapping

from .evidence import replay_evidence_references
from .frozen_index import verify_frozen_check_index


COVERAGE_RESULTS = {"COMPLETE_DECLARED_SCOPE", "INCOMPLETE", "UNKNOWN"}
AFFECTED_SCOPES = {"SELF", "INDIVIDUAL", "GROUP", "PUBLIC", "SYSTEM", "ENVIRONMENT"}


class MissingObservationError(ValueError):
    """The missing-observation contract is malformed."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise MissingObservationError("value_not_canonical_json") from exc


def _clone(value: object) -> Any:
    return json.loads(_canonical(value).decode("utf-8"))


def _hash(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _nonempty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MissingObservationError(f"{label}_must_be_nonempty_string")
    return value


def assess_missing_observations(
    *,
    scope: Mapping[str, Any],
    required_observations: Iterable[Mapping[str, Any]],
    evidence: Mapping[str, Mapping[str, Any]],
    frozen_index: Mapping[str, Any],
) -> dict[str, Any]:
    """Audit declared observation coverage without claiming complete discovery."""
    index = verify_frozen_check_index(frozen_index)
    bound_scope = _clone(dict(scope))
    if set(bound_scope) != {
        "assessment_id", "proposal", "environment_id", "coverage_boundary"
    }:
        raise MissingObservationError("scope_fields_mismatch")
    for field, value in bound_scope.items():
        _nonempty(value, f"scope_{field}")

    if isinstance(required_observations, (str, bytes, Mapping)):
        raise MissingObservationError("required_observations_must_be_iterable")
    observations = [_clone(dict(item)) for item in required_observations]
    if not observations:
        raise MissingObservationError("required_observations_must_not_be_empty")
    evidence_items = _clone(dict(evidence))
    identifiers: set[str] = set()
    used: list[str] = []
    statuses: list[dict[str, str]] = []
    unknown_reasons: list[str] = []

    for observation in observations:
        if set(observation) != {
            "observation_id", "question", "affected_scope", "evidence"
        }:
            raise MissingObservationError("observation_fields_mismatch")
        identifier = _nonempty(observation["observation_id"], "observation_id")
        if identifier in identifiers:
            raise MissingObservationError("observation_id_duplicate")
        identifiers.add(identifier)
        _nonempty(observation["question"], "observation_question")
        if observation["affected_scope"] not in AFFECTED_SCOPES:
            raise MissingObservationError("affected_scope_invalid")
        references = observation["evidence"]
        if not isinstance(references, list):
            raise MissingObservationError("observation_evidence_must_be_list")
        if len(references) != len(set(references)):
            raise MissingObservationError("observation_evidence_duplicate")
        if not references:
            status = "MISSING"
        else:
            results, referenced = replay_evidence_references(
                references, evidence_items, frozen_index=index
            )
            used.extend(referenced)
            if results is None or any(result in {"UNKNOWN", "BLOCKED"} for result in results):
                status = "UNKNOWN"
                unknown_reasons.append(f"observation_evidence_invalid:{identifier}")
            elif any(result == "CONTRADICTED" for result in results):
                status = "CONTRADICTED"
            elif all(result == "HELD" for result in results):
                status = "OBSERVED"
            else:
                status = "UNKNOWN"
                unknown_reasons.append(f"observation_evidence_invalid:{identifier}")
        statuses.append({"observation_id": identifier, "status": status})

    if set(used) != set(evidence_items):
        unknown_reasons.append("evidence_set_not_exact")
    if unknown_reasons:
        coverage = "UNKNOWN"
    elif any(item["status"] != "OBSERVED" for item in statuses):
        coverage = "INCOMPLETE"
    else:
        coverage = "COMPLETE_DECLARED_SCOPE"

    audit_targets = [
        {
            "observation_id": observation["observation_id"],
            "question": observation["question"],
            "affected_scope": observation["affected_scope"],
            "status": next(
                item["status"] for item in statuses
                if item["observation_id"] == observation["observation_id"]
            ),
        }
        for observation in observations
        if next(
            item["status"] for item in statuses
            if item["observation_id"] == observation["observation_id"]
        ) != "OBSERVED"
    ]
    body = {
        "type": "free_valid_ai_missing_observation_assessment",
        "schema_version": 1,
        "scope": bound_scope,
        "frozen_index_hash": index["index_hash"],
        "required_observations": observations,
        "evidence": evidence_items,
        "observation_statuses": sorted(statuses, key=lambda item: item["observation_id"]),
        "coverage": coverage,
        "audit_targets": sorted(audit_targets, key=lambda item: item["observation_id"]),
        "unknown_reasons": sorted(set(unknown_reasons)),
        "overall_safety": "NOT_ASSESSED",
        "undeclared_dimensions_assessed": False,
        "probe_authority": "NONE",
        "accepted": False,
        "truth_claimed": False,
        "write_authority": "NONE",
        "execution_authority": "NONE",
    }
    return {**body, "assessment_hash": _hash(body)}


def verify_missing_observation_assessment(
    value: Mapping[str, Any], *, frozen_index: Mapping[str, Any]
) -> dict[str, Any]:
    """Recompute a closed missing-observation receipt."""
    if not isinstance(value, Mapping):
        raise MissingObservationError("assessment_must_be_object")
    received = _clone(dict(value))
    fields = {
        "type", "schema_version", "scope", "frozen_index_hash",
        "required_observations", "evidence", "observation_statuses", "coverage",
        "audit_targets", "unknown_reasons", "overall_safety",
        "undeclared_dimensions_assessed", "probe_authority", "accepted",
        "truth_claimed", "write_authority", "execution_authority", "assessment_hash",
    }
    if set(received) != fields:
        raise MissingObservationError("assessment_fields_mismatch")
    if (
        received["type"] != "free_valid_ai_missing_observation_assessment"
        or received["schema_version"] != 1
    ):
        raise MissingObservationError("assessment_schema_mismatch")
    rebuilt = assess_missing_observations(
        scope=received["scope"],
        required_observations=received["required_observations"],
        evidence=received["evidence"],
        frozen_index=frozen_index,
    )
    if received != rebuilt:
        if received.get("assessment_hash") != rebuilt["assessment_hash"]:
            raise MissingObservationError("assessment_hash_mismatch")
        raise MissingObservationError("assessment_content_mismatch")
    return received


def missing_observation_assessment_is_caller_independent() -> bool:
    """Expose that callers cannot supply coverage, safety, or probe execution."""
    parameters = inspect.signature(assess_missing_observations).parameters
    return not ({"coverage", "overall_safety", "probe", "execute"} & set(parameters))
