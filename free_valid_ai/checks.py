"""Deterministic checks that compute their own verification result."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from free_valid_ai.claims import (
    ClaimContractError,
    create_verification_receipt,
    verify_claim,
)


CHECK_TYPE = "source_sha256_equals"
CHECK_VERSION = 1
_CHECK_FIELDS = {"type", "version", "source_id", "expected_sha256"}
JSON_CHECK_TYPE = "json_pointer_equals"
JSON_CHECK_VERSION = 1
_JSON_CHECK_FIELDS = {"type", "version", "source_id", "pointer", "expected_value"}
_PROCEDURE = (
    b"free-valid-ai/source-sha256-equals/v1\n"
    b"verify claim; select declared source; hash presented bytes; "
    b"first compare source identity; then compare expected digest\n"
)
PROCEDURE_SHA256 = hashlib.sha256(_PROCEDURE).hexdigest()
_JSON_PROCEDURE = (
    b"free-valid-ai/json-pointer-equals/v1\n"
    b"verify claim; select declared source; hash and bind presented bytes; "
    b"decode UTF-8 JSON; resolve RFC 6901 pointer; compare canonical JSON values\n"
)
JSON_PROCEDURE_SHA256 = hashlib.sha256(_JSON_PROCEDURE).hexdigest()


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ClaimContractError("json_expected_value_not_canonical") from exc


def _structured_check(claim: Mapping[str, Any]) -> dict[str, Any]:
    scope = claim["scope"]
    check = scope.get("check") if isinstance(scope, Mapping) else None
    if not isinstance(check, Mapping) or set(check) != _CHECK_FIELDS:
        raise ClaimContractError("source_check_fields_mismatch")
    if check["type"] != CHECK_TYPE or check["version"] != CHECK_VERSION:
        raise ClaimContractError("source_check_schema_mismatch")
    if not isinstance(check["source_id"], str) or not check["source_id"].strip():
        raise ClaimContractError("source_check_source_id_invalid")
    expected = check["expected_sha256"]
    if (
        not isinstance(expected, str)
        or len(expected) != 64
        or any(char not in "0123456789abcdef" for char in expected)
    ):
        raise ClaimContractError("source_check_expected_sha256_invalid")
    return dict(check)


def _json_check(claim: Mapping[str, Any]) -> dict[str, Any]:
    scope = claim["scope"]
    check = scope.get("check") if isinstance(scope, Mapping) else None
    if not isinstance(check, Mapping) or set(check) != _JSON_CHECK_FIELDS:
        raise ClaimContractError("json_check_fields_mismatch")
    if check["type"] != JSON_CHECK_TYPE or check["version"] != JSON_CHECK_VERSION:
        raise ClaimContractError("json_check_schema_mismatch")
    if not isinstance(check["source_id"], str) or not check["source_id"].strip():
        raise ClaimContractError("json_check_source_id_invalid")
    pointer = check["pointer"]
    if not isinstance(pointer, str) or (pointer and not pointer.startswith("/")):
        raise ClaimContractError("json_pointer_invalid")
    _pointer_tokens(pointer)
    _canonical(check["expected_value"])
    return dict(check)


def _decode_pointer_token(token: str) -> str:
    output: list[str] = []
    index = 0
    while index < len(token):
        char = token[index]
        if char != "~":
            output.append(char)
            index += 1
            continue
        if index + 1 >= len(token) or token[index + 1] not in "01":
            raise ClaimContractError("json_pointer_escape_invalid")
        output.append("~" if token[index + 1] == "0" else "/")
        index += 2
    return "".join(output)


def _pointer_tokens(pointer: str) -> list[str]:
    if pointer == "":
        return []
    return [_decode_pointer_token(token) for token in pointer[1:].split("/")]


_MISSING = object()


def _resolve_pointer(document: Any, pointer: str) -> Any:
    current = document
    for token in _pointer_tokens(pointer):
        if isinstance(current, dict):
            if token not in current:
                return _MISSING
            current = current[token]
        elif isinstance(current, list):
            if token == "0":
                index = 0
            elif token.isdigit() and not token.startswith("0"):
                index = int(token)
            else:
                return _MISSING
            if index >= len(current):
                return _MISSING
            current = current[index]
        else:
            return _MISSING
    return current


def _load_json_bytes(value: bytes) -> Any:
    try:
        text = value.decode("utf-8")
        return json.loads(
            text,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON constant: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return _MISSING


def _declared_source(claim: Mapping[str, Any], source_id: str) -> dict[str, Any]:
    matches = [source for source in claim["sources"] if source["source_id"] == source_id]
    if len(matches) != 1:
        raise ClaimContractError("source_check_requires_one_declared_source")
    return matches[0]


def run_source_sha256_check(
    *,
    claim: Mapping[str, Any],
    verifier_id: str,
    observed_at: str,
    observed_bytes: bytes | None,
    previous_receipt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Compute a receipt from bytes; callers cannot select the result.

    Missing bytes are BLOCKED. Bytes that do not match the source identity
    bound in the claim are UNKNOWN. Only identity-matching bytes can produce
    HELD or CONTRADICTED against the expected digest.
    """
    verify_claim(claim)
    check = _structured_check(claim)
    source = _declared_source(claim, check["source_id"])
    evidence: list[dict[str, Any]] = []
    limitations: list[str] = []

    if observed_bytes is None:
        result = "BLOCKED"
        limitations.append("source bytes were not presented")
    else:
        if not isinstance(observed_bytes, bytes):
            raise ClaimContractError("observed_bytes_must_be_bytes_or_none")
        observed_hash = _sha256(observed_bytes)
        evidence.append({
            "evidence_id": f"observed-source:{source['source_id']}",
            "locator": source["locator"],
            "content_sha256": observed_hash,
        })
        if observed_hash != source["content_sha256"]:
            result = "UNKNOWN"
            limitations.append(
                "presented bytes did not match the claim-bound source identity"
            )
        elif observed_hash == check["expected_sha256"]:
            result = "HELD"
        else:
            result = "CONTRADICTED"

    return create_verification_receipt(
        claim=claim,
        verifier_id=verifier_id,
        method={
            "method_id": f"{CHECK_TYPE}-v{CHECK_VERSION}",
            "description": (
                "Hash presented source bytes, verify their bound identity, "
                "then compare the expected SHA-256."
            ),
            "procedure_sha256": PROCEDURE_SHA256,
        },
        observed_at=observed_at,
        evidence=evidence,
        result=result,
        limitations=limitations,
        previous_receipt=previous_receipt,
    )


def run_json_pointer_check(
    *,
    claim: Mapping[str, Any],
    verifier_id: str,
    observed_at: str,
    observed_bytes: bytes | None,
    previous_receipt: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Compute a typed JSON Pointer equality result from presented bytes."""
    verify_claim(claim)
    check = _json_check(claim)
    source = _declared_source(claim, check["source_id"])
    evidence: list[dict[str, Any]] = []
    limitations: list[str] = []

    if observed_bytes is None:
        result = "BLOCKED"
        limitations.append("source bytes were not presented")
    else:
        if not isinstance(observed_bytes, bytes):
            raise ClaimContractError("observed_bytes_must_be_bytes_or_none")
        observed_hash = _sha256(observed_bytes)
        evidence.append({
            "evidence_id": f"observed-source:{source['source_id']}",
            "locator": source["locator"],
            "content_sha256": observed_hash,
        })
        if observed_hash != source["content_sha256"]:
            result = "UNKNOWN"
            limitations.append(
                "presented bytes did not match the claim-bound source identity"
            )
        else:
            document = _load_json_bytes(observed_bytes)
            if document is _MISSING:
                result = "BLOCKED"
                limitations.append("bound source bytes were not valid UTF-8 JSON")
            else:
                observed_value = _resolve_pointer(document, check["pointer"])
                if observed_value is _MISSING:
                    result = "CONTRADICTED"
                    limitations.append("declared JSON Pointer was absent")
                elif _canonical(observed_value) == _canonical(check["expected_value"]):
                    result = "HELD"
                else:
                    result = "CONTRADICTED"

    return create_verification_receipt(
        claim=claim,
        verifier_id=verifier_id,
        method={
            "method_id": f"{JSON_CHECK_TYPE}-v{JSON_CHECK_VERSION}",
            "description": (
                "Verify source identity, parse UTF-8 JSON, resolve an RFC 6901 "
                "pointer, and compare canonical typed JSON values."
            ),
            "procedure_sha256": JSON_PROCEDURE_SHA256,
        },
        observed_at=observed_at,
        evidence=evidence,
        result=result,
        limitations=limitations,
        previous_receipt=previous_receipt,
    )
