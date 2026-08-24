"""Structured same-carrier review receipts for intercepted turns."""

from __future__ import annotations

import hashlib
import json
import secrets
from typing import Any, Mapping


REVIEW_TYPE = "free_valid_ai_mirrored_turn_review"
REVIEW_VERSION = 1
ASSESSMENTS = {"CLEAN", "CORRECTION_REQUIRED", "UNKNOWN"}
_FIELDS = {
    "type", "version", "mode", "independence_claimed", "model_carrier",
    "received_turn_hash", "draft_sha256", "assessment", "issues",
    "raw_review_sha256", "accepted", "truth_claimed", "write_authority",
    "execution_authority", "deletion_authority", "review_hash",
}
_AUTHORITY = {
    "accepted": False, "truth_claimed": False, "write_authority": "NONE",
    "execution_authority": "NONE", "deletion_authority": "NONE",
}


class MirroredReviewError(ValueError):
    """The mirror response or receipt is malformed or unsupported."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode()
    except (TypeError, ValueError) as exc:
        raise MirroredReviewError("value_not_canonical_json") from exc


def _hash(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise MirroredReviewError(f"{label}_invalid")
    return value


def parse_mirrored_review(
    raw: str, *, model_carrier: str, received_turn_hash: str, draft_sha256: str
) -> dict[str, Any]:
    """Parse strict mirror JSON and bind it without claiming independence."""
    if not isinstance(raw, str):
        raise MirroredReviewError("review_must_be_text")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise MirroredReviewError("review_json_invalid") from exc
    if not isinstance(payload, dict) or set(payload) != {"assessment", "issues"}:
        raise MirroredReviewError("review_fields_mismatch")
    assessment = payload["assessment"]
    issues = payload["issues"]
    if assessment not in ASSESSMENTS:
        raise MirroredReviewError("review_assessment_invalid")
    if not isinstance(issues, list) or any(not isinstance(x, str) or not x.strip() for x in issues):
        raise MirroredReviewError("review_issues_invalid")
    if assessment == "CLEAN" and issues:
        raise MirroredReviewError("clean_review_cannot_have_issues")
    if assessment == "CORRECTION_REQUIRED" and not issues:
        raise MirroredReviewError("correction_review_requires_issues")
    if not isinstance(model_carrier, str) or not model_carrier.strip():
        raise MirroredReviewError("model_carrier_invalid")
    _sha(received_turn_hash, "received_turn_hash")
    _sha(draft_sha256, "draft_sha256")
    body = {
        "type": REVIEW_TYPE, "version": REVIEW_VERSION, "mode": "MIRRORED",
        "independence_claimed": False, "model_carrier": model_carrier,
        "received_turn_hash": received_turn_hash, "draft_sha256": draft_sha256,
        "assessment": assessment, "issues": issues,
        "raw_review_sha256": hashlib.sha256(raw.encode()).hexdigest(), **_AUTHORITY,
    }
    receipt = {**body, "review_hash": _hash(body)}
    verify_mirrored_review(receipt)
    return receipt


def verify_mirrored_review(value: Mapping[str, Any]) -> bool:
    if not isinstance(value, Mapping):
        raise MirroredReviewError("review_receipt_must_be_object")
    item = json.loads(_canonical(dict(value)))
    if set(item) != _FIELDS:
        raise MirroredReviewError("review_receipt_fields_mismatch")
    if item["type"] != REVIEW_TYPE or item["version"] != REVIEW_VERSION:
        raise MirroredReviewError("review_receipt_schema_mismatch")
    if item["mode"] != "MIRRORED" or item["independence_claimed"] is not False:
        raise MirroredReviewError("review_independence_overclaim")
    if item["assessment"] not in ASSESSMENTS or not isinstance(item["issues"], list):
        raise MirroredReviewError("review_receipt_content_invalid")
    if item["assessment"] == "CLEAN" and item["issues"]:
        raise MirroredReviewError("clean_review_cannot_have_issues")
    if item["assessment"] == "CORRECTION_REQUIRED" and not item["issues"]:
        raise MirroredReviewError("correction_review_requires_issues")
    for field in ("received_turn_hash", "draft_sha256", "raw_review_sha256"):
        _sha(item[field], field)
    for field, expected in _AUTHORITY.items():
        if item[field] != expected:
            raise MirroredReviewError(f"review_{field}_invalid")
    body = {k: item[k] for k in _FIELDS - {"review_hash"}}
    if not secrets.compare_digest(_sha(item["review_hash"], "review_hash"), _hash(body)):
        raise MirroredReviewError("review_hash_mismatch")
    return True
