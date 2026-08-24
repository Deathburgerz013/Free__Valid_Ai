from __future__ import annotations

import copy
import hashlib

import pytest

from free_valid_ai.semantics import DEFAULT_SEMANTIC_CONTRACT
from free_valid_ai.turn_boundary import (
    TurnBoundaryError,
    create_interception,
    create_received_turn,
    verify_interception,
    verify_received_turn,
)

ZERO = "0" * 64


def _check(check_id: str = "bytes", result: str = "PASS") -> dict[str, str]:
    return {
        "check_id": check_id,
        "result": result,
        "evidence_sha256": hashlib.sha256(check_id.encode()).hexdigest(),
    }


def _received(content: bytes = b"  exact\r\nbytes  ") -> dict:
    return create_received_turn(content, role="USER", sequence=0)


def test_receiver_preserves_exact_bytes_and_binds_semantics() -> None:
    raw = b"  exact\r\nbytes\x00  "
    received = _received(raw)
    assert verify_received_turn(received) == raw
    assert received["content_byte_count"] == len(raw)
    assert received["semantic_contract_hash"] == DEFAULT_SEMANTIC_CONTRACT["contract_hash"]
    assert received["write_authority"] == "NONE"
    assert received["truth_claimed"] is False


def test_receiver_requires_bytes_and_valid_chain_position() -> None:
    with pytest.raises(TurnBoundaryError, match="content_must_be_bytes"):
        create_received_turn("text", role="USER", sequence=0)  # type: ignore[arg-type]
    with pytest.raises(TurnBoundaryError, match="initial_turn"):
        create_received_turn(
            b"x", role="USER", sequence=0, previous_received_turn_hash=ZERO
        )
    with pytest.raises(TurnBoundaryError, match="previous_received"):
        create_received_turn(b"x", role="USER", sequence=1)


def test_receiver_tamper_and_unknown_fields_fail() -> None:
    received = _received()
    tampered = copy.deepcopy(received)
    tampered["content_base64"] = "eA=="
    with pytest.raises(TurnBoundaryError):
        verify_received_turn(tampered)
    with pytest.raises(TurnBoundaryError, match="fields_mismatch"):
        verify_received_turn({**received, "silent": True})


def test_receiver_rejects_substituted_semantic_identity() -> None:
    received = _received()
    tampered = copy.deepcopy(received)
    tampered["semantic_contract_hash"] = ZERO
    with pytest.raises(TurnBoundaryError, match="semantic_contract_mismatch"):
        verify_received_turn(tampered)


def test_all_pass_can_release_unchanged() -> None:
    received = _received()
    item = create_interception(received, b"draft", checks=[_check()], released=b"draft")
    assert item["decision"] == "UNCHANGED"
    assert verify_interception(item, received_turn=received) == b"draft"


def test_correction_requires_hash_bound_basis() -> None:
    received = _received()
    with pytest.raises(TurnBoundaryError, match="correction_basis"):
        create_interception(received, b"wrong", checks=[_check()], released=b"correct")
    item = create_interception(
        received,
        b"wrong",
        checks=[_check()],
        released=b"correct",
        correction_basis_sha256=ZERO,
    )
    assert item["decision"] == "CORRECTED"
    assert verify_interception(item, received_turn=received) == b"correct"


@pytest.mark.parametrize(
    ("result", "decision"), (("FAIL", "BLOCKED"), ("UNKNOWN", "UNKNOWN"))
)
def test_failed_or_unknown_check_cannot_release(result: str, decision: str) -> None:
    received = _received()
    item = create_interception(received, b"draft", checks=[_check(result=result)])
    assert item["decision"] == decision
    assert verify_interception(item, received_turn=received) is None
    with pytest.raises(TurnBoundaryError, match="cannot_release"):
        create_interception(
            received, b"draft", checks=[_check(result=result)], released=b"draft"
        )


def test_checks_are_unique_and_sorted() -> None:
    received = _received()
    with pytest.raises(TurnBoundaryError, match="unique_sorted"):
        create_interception(
            received,
            b"draft",
            checks=[_check("z"), _check("a")],
            released=b"draft",
        )


def test_interception_tamper_or_received_substitution_fails() -> None:
    received = _received()
    item = create_interception(received, b"draft", checks=[_check()], released=b"draft")
    tampered = copy.deepcopy(item)
    tampered["decision"] = "CORRECTED"
    with pytest.raises(TurnBoundaryError):
        verify_interception(tampered, received_turn=received)
    with pytest.raises(TurnBoundaryError, match="received_turn_mismatch"):
        verify_interception(item, received_turn=_received(b"other"))


def test_pass_without_release_is_explicitly_blocked() -> None:
    received = _received()
    item = create_interception(received, b"draft", checks=[_check()])
    assert item["decision"] == "BLOCKED"
    assert item["released_base64"] is None
    assert verify_interception(item, received_turn=received) is None
