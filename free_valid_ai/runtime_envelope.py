"""Canonical, hash-bound facts supplied to a local model call."""

from __future__ import annotations

import hashlib
import json
import secrets
from typing import Any, Mapping

from .semantics import DEFAULT_SEMANTIC_CONTRACT, verify_semantic_contract


ENVELOPE_TYPE = "free_valid_ai_runtime_envelope"
ENVELOPE_VERSION = 1

_BODY_FIELDS = {
    "type", "version", "semantic_contract_version", "semantic_contract_hash",
    "semantic_interpretation_policy", "assistant_identity", "model_carrier",
    "identity_rule", "transport", "transport_endpoint", "transport_scope",
    "execution_selection", "assistant_write_authority",
    "assistant_execution_authority", "user_authority", "cloud_service_claim",
    "instructions",
}
_FIELDS = _BODY_FIELDS | {"envelope_sha256"}


class RuntimeEnvelopeError(ValueError):
    """A runtime envelope is malformed, altered, or rebound."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise RuntimeEnvelopeError("envelope_not_canonical_json") from exc


def _nonempty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RuntimeEnvelopeError(f"{label}_must_be_nonempty_string")
    return value


def build_runtime_envelope(*, model: str, endpoint: str, num_gpu: int) -> str:
    _nonempty(model, "model_carrier")
    _nonempty(endpoint, "transport_endpoint")
    if isinstance(num_gpu, bool) or not isinstance(num_gpu, int) or num_gpu < 0:
        raise RuntimeEnvelopeError("num_gpu_must_be_nonnegative_integer")
    execution = "CPU_ONLY" if num_gpu == 0 else f"GPU_LAYERS_{num_gpu}"
    semantics = verify_semantic_contract(DEFAULT_SEMANTIC_CONTRACT)
    body = {
        "type": ENVELOPE_TYPE,
        "version": ENVELOPE_VERSION,
        "semantic_contract_version": semantics["version"],
        "semantic_contract_hash": semantics["contract_hash"],
        "semantic_interpretation_policy": "EXACT",
        "assistant_identity": "Simulator",
        "model_carrier": model,
        "identity_rule": "The assistant is Simulator; the model carrier is replaceable.",
        "transport": "LOCAL_OLLAMA",
        "transport_endpoint": endpoint,
        "transport_scope": "LOOPBACK_ONLY",
        "execution_selection": execution,
        "assistant_write_authority": "NONE",
        "assistant_execution_authority": "NONE",
        "user_authority": "NOT_ASSESSED",
        "cloud_service_claim": False,
        "instructions": [
            "These facts are supplied by the local program, not inferred by the model.",
            "Speak as Simulator. Use the model name only to identify the carrier.",
            "Do not claim cloud execution or assign assistant restrictions to the user.",
        ],
    }
    digest = hashlib.sha256(_canonical(body)).hexdigest()
    return _canonical({**body, "envelope_sha256": digest}).decode("utf-8")


def verify_runtime_envelope(value: str, *, expected_model: str) -> dict[str, Any]:
    if not isinstance(value, str) or not value.strip():
        raise RuntimeEnvelopeError("runtime_envelope_must_be_nonempty_string")
    _nonempty(expected_model, "expected_model")
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError) as exc:
        raise RuntimeEnvelopeError("runtime_envelope_invalid_json") from exc
    if not isinstance(parsed, Mapping):
        raise RuntimeEnvelopeError("runtime_envelope_must_be_object")
    envelope = dict(parsed)
    if set(envelope) != _FIELDS:
        raise RuntimeEnvelopeError("runtime_envelope_fields_mismatch")
    if value.encode("utf-8") != _canonical(envelope):
        raise RuntimeEnvelopeError("runtime_envelope_not_canonical")
    body = {field: envelope[field] for field in _BODY_FIELDS}
    expected_digest = hashlib.sha256(_canonical(body)).hexdigest()
    digest = envelope["envelope_sha256"]
    if not isinstance(digest, str) or not secrets.compare_digest(digest, expected_digest):
        raise RuntimeEnvelopeError("runtime_envelope_digest_invalid")
    semantics = verify_semantic_contract(DEFAULT_SEMANTIC_CONTRACT)
    exact = {
        "type": ENVELOPE_TYPE,
        "version": ENVELOPE_VERSION,
        "semantic_contract_version": semantics["version"],
        "semantic_contract_hash": semantics["contract_hash"],
        "semantic_interpretation_policy": "EXACT",
        "assistant_identity": "Simulator",
        "identity_rule": "The assistant is Simulator; the model carrier is replaceable.",
        "transport": "LOCAL_OLLAMA",
        "transport_scope": "LOOPBACK_ONLY",
        "assistant_write_authority": "NONE",
        "assistant_execution_authority": "NONE",
        "user_authority": "NOT_ASSESSED",
        "cloud_service_claim": False,
        "instructions": [
            "These facts are supplied by the local program, not inferred by the model.",
            "Speak as Simulator. Use the model name only to identify the carrier.",
            "Do not claim cloud execution or assign assistant restrictions to the user.",
        ],
    }
    for field, expected in exact.items():
        if envelope[field] != expected:
            raise RuntimeEnvelopeError(f"runtime_envelope_{field}_invalid")
    if envelope["model_carrier"] != expected_model:
        raise RuntimeEnvelopeError("runtime_envelope_model_carrier_mismatch")
    _nonempty(envelope["transport_endpoint"], "transport_endpoint")
    execution = envelope["execution_selection"]
    if execution != "CPU_ONLY" and not (
        isinstance(execution, str)
        and execution.startswith("GPU_LAYERS_")
        and execution.removeprefix("GPU_LAYERS_").isdigit()
        and int(execution.removeprefix("GPU_LAYERS_")) > 0
    ):
        raise RuntimeEnvelopeError("runtime_envelope_execution_selection_invalid")
    return envelope
