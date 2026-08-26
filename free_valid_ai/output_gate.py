"""Mandatory checked model-call wrapper with fail-closed output release."""

from __future__ import annotations

import hashlib
import inspect
import json
from typing import Any, Callable, Iterable, Mapping

from .checks import run_json_pointer_check, run_source_sha256_check
from .claims import verify_claim, verify_verification_receipt
from .frozen_index import admitted_check, verify_frozen_check_index


Invoke = Callable[[str, list[dict[str, str]]], str]
_RUNNERS = {
    "source_sha256_equals": run_source_sha256_check,
    "json_pointer_equals": run_json_pointer_check,
}


class OutputGateError(ValueError):
    """The gate contract is malformed before invocation can occur."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise OutputGateError("value_not_canonical_json") from exc


def _clone(value: object) -> Any:
    return json.loads(_canonical(value).decode("utf-8"))


def _hash(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _validate_messages(messages: Iterable[Mapping[str, str]]) -> list[dict[str, str]]:
    if isinstance(messages, (str, bytes, Mapping)):
        raise OutputGateError("messages_must_be_iterable_of_objects")
    made = [_clone(dict(message)) for message in messages]
    if not made:
        raise OutputGateError("messages_must_not_be_empty")
    for message in made:
        if set(message) != {"role", "content"}:
            raise OutputGateError("message_fields_mismatch")
        if message["role"] not in {"system", "user", "assistant"}:
            raise OutputGateError("message_role_invalid")
        if not isinstance(message["content"], str) or not message["content"]:
            raise OutputGateError("message_content_invalid")
    return made


def _prepare_claims(
    claims: Iterable[Mapping[str, Any]], index: Mapping[str, Any]
) -> list[dict[str, Any]]:
    if isinstance(claims, (str, bytes, Mapping)):
        raise OutputGateError("claims_must_be_iterable_of_objects")
    made = [_clone(dict(claim)) for claim in claims]
    if not made:
        raise OutputGateError("claims_must_not_be_empty")
    hashes: set[str] = set()
    for claim in made:
        verify_claim(claim)
        check = claim["scope"].get("check")
        if not isinstance(check, Mapping):
            raise OutputGateError("claim_check_missing")
        check_id, version = check.get("type"), check.get("version")
        admitted = admitted_check(index, check_id, version)
        if admitted is None:
            raise OutputGateError("claim_check_not_admitted")
        if check_id not in _RUNNERS:
            raise OutputGateError("claim_check_not_runnable_by_gate")
        if claim["claim_hash"] in hashes:
            raise OutputGateError("claim_duplicate")
        hashes.add(claim["claim_hash"])
    return sorted(made, key=lambda item: item["claim_hash"])


def run_verified_model_call(
    *,
    model: str,
    messages: Iterable[Mapping[str, str]],
    invoke: Invoke,
    claims: Iterable[Mapping[str, Any]],
    frozen_index: Mapping[str, Any],
    verifier_id: str,
    observed_at: str,
) -> dict[str, Any]:
    """Invoke once and release only after every predeclared claim is replayed."""
    if not isinstance(model, str) or not model.strip():
        raise OutputGateError("model_invalid")
    if not callable(invoke):
        raise OutputGateError("invoke_must_be_callable")
    if not isinstance(verifier_id, str) or not verifier_id.strip():
        raise OutputGateError("verifier_id_invalid")
    if not isinstance(observed_at, str) or not observed_at.strip():
        raise OutputGateError("observed_at_invalid")

    index = verify_frozen_check_index(frozen_index)
    bound_messages = _validate_messages(messages)
    bound_claims = _prepare_claims(claims, index)
    invocation = {
        "model": model,
        "messages": bound_messages,
        "context_sha256": hashlib.sha256(_canonical(bound_messages)).hexdigest(),
        "claim_hashes": [claim["claim_hash"] for claim in bound_claims],
        "frozen_index_hash": index["index_hash"],
    }
    invocation_hash = _hash(invocation)

    draft = invoke(model, _clone(bound_messages))
    if not isinstance(draft, str):
        raise OutputGateError("model_output_must_be_string")
    draft_bytes = draft.encode("utf-8")
    receipts: list[dict[str, Any]] = []
    all_held = bool(draft)
    for claim in bound_claims:
        check = claim["scope"]["check"]
        runner = _RUNNERS[check["type"]]
        receipt = runner(
            claim=claim, verifier_id=verifier_id, observed_at=observed_at,
            observed_bytes=draft_bytes,
        )
        verify_verification_receipt(receipt, claim=claim)
        admitted = admitted_check(index, check["type"], check["version"])
        if (
            receipt["method"]["method_id"] != admitted["procedure_id"]
            or receipt["method"]["procedure_sha256"] != admitted["procedure_sha256"]
        ):
            raise OutputGateError("receipt_procedure_admission_mismatch")
        receipts.append(receipt)
        all_held = all_held and receipt["result"] == "HELD"

    decision = "RELEASE" if all_held else "BLOCK"
    body = {
        "type": "free_valid_ai_verified_model_output_gate",
        "schema_version": 1,
        "invocation_hash": invocation_hash,
        "context_sha256": invocation["context_sha256"],
        "draft_sha256": hashlib.sha256(draft_bytes).hexdigest(),
        "frozen_index_hash": index["index_hash"],
        "receipts": receipts,
        "decision": decision,
        "released": draft if decision == "RELEASE" else None,
        "accepted": False,
        "truth_claimed": False,
        "write_authority": "NONE",
        "execution_authority": "NONE",
        "release_scope": "MODEL_OUTPUT_ONLY",
    }
    return {**body, "gate_hash": _hash(body)}


def gate_is_caller_independent() -> bool:
    """Expose the enforceable API fact for tests and integrations."""
    parameters = inspect.signature(run_verified_model_call).parameters
    return "decision" not in parameters and "released" not in parameters
