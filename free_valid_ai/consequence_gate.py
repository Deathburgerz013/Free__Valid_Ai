"""Fail-closed consequence eligibility without execution authority."""

from __future__ import annotations

import hashlib
import inspect
import json
from typing import Any, Iterable, Mapping

from .evidence import replay_evidence_references
from .frozen_index import verify_frozen_check_index
from .possibility import verify_possibility_assessment


CONSEQUENCE_DECISIONS = {"ELIGIBLE", "SANDBOX_ONLY", "BLOCKED", "PROHIBITED"}
PEOPLE_SCOPES = {"NONE", "INDIVIDUAL", "GROUP", "PUBLIC"}
SYSTEM_SCOPES = {"LOCAL", "BOUNDED", "EXTERNAL", "UNBOUNDED"}
REVERSIBILITY = {"REVERSIBLE", "COMPENSATABLE", "IRREVERSIBLE", "UNKNOWN"}


class ConsequenceGateError(ValueError):
    """The consequence gate contract is malformed."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ConsequenceGateError("value_not_canonical_json") from exc


def _clone(value: object) -> Any:
    return json.loads(_canonical(value).decode("utf-8"))


def _hash(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _nonempty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConsequenceGateError(f"{label}_must_be_nonempty_string")
    return value


def _unknowns(values: Iterable[str]) -> list[str]:
    if isinstance(values, (str, bytes, Mapping)):
        raise ConsequenceGateError("unknown_consequences_must_be_iterable_of_strings")
    made = list(values)
    for value in made:
        _nonempty(value, "unknown_consequence")
    if len(made) != len(set(made)):
        raise ConsequenceGateError("unknown_consequences_duplicate")
    return sorted(made)


def assess_consequences(
    *,
    action: Mapping[str, Any],
    impact: Mapping[str, Any],
    impact_evidence: Mapping[str, Any],
    evidence: Mapping[str, Mapping[str, Any]],
    unknown_consequences: Iterable[str],
    possibility_assessment: Mapping[str, Any],
    frozen_index: Mapping[str, Any],
) -> dict[str, Any]:
    """Compute eligibility for later authorization; never execute the action."""
    index = verify_frozen_check_index(frozen_index)
    bound_action = _clone(dict(action))
    if set(bound_action) != {"action_id", "description", "environment_id"}:
        raise ConsequenceGateError("action_fields_mismatch")
    for field, value in bound_action.items():
        _nonempty(value, f"action_{field}")

    bound_impact = _clone(dict(impact))
    if set(bound_impact) != {"people_scope", "systems_scope", "reversibility"}:
        raise ConsequenceGateError("impact_fields_mismatch")
    if bound_impact["people_scope"] not in PEOPLE_SCOPES:
        raise ConsequenceGateError("people_scope_invalid")
    if bound_impact["systems_scope"] not in SYSTEM_SCOPES:
        raise ConsequenceGateError("systems_scope_invalid")
    if bound_impact["reversibility"] not in REVERSIBILITY:
        raise ConsequenceGateError("reversibility_invalid")

    bound_impact_evidence = _clone(dict(impact_evidence))
    if set(bound_impact_evidence) != set(bound_impact):
        raise ConsequenceGateError("impact_evidence_fields_mismatch")
    evidence_items = _clone(dict(evidence))
    used: list[str] = []
    impact_unknown: list[str] = []
    for field, value in bound_impact.items():
        results, references = replay_evidence_references(
            bound_impact_evidence[field], evidence_items, frozen_index=index
        )
        used.extend(references)
        if results is None or not all(result == "HELD" for result in results):
            impact_unknown.append(f"impact_evidence_incomplete:{field}")
            continue
        for reference in references:
            check = evidence_items[reference]["claim"]["scope"].get("check")
            if (
                not isinstance(check, Mapping)
                or check.get("type") != "json_pointer_equals"
                or check.get("pointer") != f"/{field}"
                or check.get("expected_value") != value
            ):
                impact_unknown.append(f"impact_evidence_unbound:{field}")
                break
    if set(used) != set(evidence_items):
        impact_unknown.append("impact_evidence_set_not_exact")

    unknowns = _unknowns(unknown_consequences)
    possibility = verify_possibility_assessment(
        possibility_assessment, frozen_index=index
    )
    possibility_scope = possibility["scope"]
    if (
        possibility_scope["proposal"] != bound_action["description"]
        or possibility_scope["environment_id"] != bound_action["environment_id"]
    ):
        raise ConsequenceGateError("possibility_action_binding_mismatch")

    reasons: list[str] = []
    assessment = possibility["assessment"]
    if assessment == "IMPOSSIBLE_UNDER_CONSTRAINTS":
        decision = "PROHIBITED"
        reasons.append("logical_safety_constraint_contradicted")
    elif assessment != "POSSIBLE_WITHIN_CONSTRAINTS":
        decision = "BLOCKED"
        reasons.append(f"possibility_not_established:{assessment}")
    elif impact_unknown:
        decision = "BLOCKED"
        reasons.extend(impact_unknown)
    elif bound_impact["people_scope"] == "PUBLIC":
        decision = "BLOCKED"
        reasons.append("public_impact_not_authorizable_by_this_gate")
    elif bound_impact["systems_scope"] == "UNBOUNDED":
        decision = "BLOCKED"
        reasons.append("unbounded_system_impact")
    elif bound_impact["reversibility"] in {"IRREVERSIBLE", "UNKNOWN"}:
        decision = "BLOCKED"
        reasons.append(f"reversibility_{bound_impact['reversibility'].lower()}")
    elif (
        unknowns
        or bound_impact["people_scope"] == "GROUP"
        or bound_impact["systems_scope"] == "EXTERNAL"
        or bound_impact["reversibility"] == "COMPENSATABLE"
    ):
        decision = "SANDBOX_ONLY"
        if unknowns:
            reasons.append("unresolved_consequences")
        if bound_impact["people_scope"] == "GROUP":
            reasons.append("group_impact_requires_separate_authorization")
        if bound_impact["systems_scope"] == "EXTERNAL":
            reasons.append("external_impact_requires_separate_authorization")
        if bound_impact["reversibility"] == "COMPENSATABLE":
            reasons.append("compensatable_is_not_fully_reversible")
    else:
        decision = "ELIGIBLE"
        reasons.append("bounded_reversible_and_verified")

    body = {
        "type": "free_valid_ai_bounded_consequence_gate",
        "schema_version": 1,
        "action": bound_action,
        "impact": bound_impact,
        "impact_evidence": bound_impact_evidence,
        "evidence": evidence_items,
        "unknown_consequences": unknowns,
        "possibility_assessment": possibility,
        "frozen_index_hash": index["index_hash"],
        "decision": decision,
        "reasons": sorted(reasons),
        "eligible_for": "SEPARATE_AUTHORIZATION_ONLY" if decision == "ELIGIBLE" else "NONE",
        "accepted": False,
        "truth_claimed": False,
        "write_authority": "NONE",
        "execution_authority": "NONE",
        "deletion_authority": "NONE",
    }
    return {**body, "gate_hash": _hash(body)}


def verify_consequence_gate(
    value: Mapping[str, Any],
    *,
    frozen_index: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify the closed gate receipt and recompute its decision."""
    if not isinstance(value, Mapping):
        raise ConsequenceGateError("gate_must_be_object")
    received = _clone(dict(value))
    fields = {
        "type", "schema_version", "action", "impact", "impact_evidence",
        "evidence", "unknown_consequences", "possibility_assessment",
        "frozen_index_hash", "decision", "reasons", "eligible_for",
        "accepted", "truth_claimed", "write_authority", "execution_authority",
        "deletion_authority", "gate_hash",
    }
    if set(received) != fields:
        raise ConsequenceGateError("gate_fields_mismatch")
    if (
        received["type"] != "free_valid_ai_bounded_consequence_gate"
        or received["schema_version"] != 1
    ):
        raise ConsequenceGateError("gate_schema_mismatch")
    rebuilt = assess_consequences(
        action=received["action"],
        impact=received["impact"],
        impact_evidence=received["impact_evidence"],
        evidence=received["evidence"],
        unknown_consequences=received["unknown_consequences"],
        possibility_assessment=received["possibility_assessment"],
        frozen_index=frozen_index,
    )
    if received != rebuilt:
        if received.get("gate_hash") != rebuilt["gate_hash"]:
            raise ConsequenceGateError("gate_hash_mismatch")
        raise ConsequenceGateError("gate_content_mismatch")
    return received


def consequence_gate_is_caller_independent() -> bool:
    """Expose that callers cannot supply a decision or execution callback."""
    parameters = inspect.signature(assess_consequences).parameters
    return not ({"decision", "execute", "invoke"} & set(parameters))
