import copy
import hashlib
import json

import pytest

from free_valid_ai.frozen_index import (
    DEFAULT_FROZEN_CHECK_INDEX,
    FrozenCheckIndexError,
    admitted_check,
    create_admitted_check,
    create_frozen_check_index,
    extend_frozen_check_index,
    verify_admitted_check,
    verify_frozen_check_index,
)


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def entry(
    check_id: str = "alpha",
    *,
    check_version: int = 1,
    active_from: int = 1,
    dependencies=(),
    supersedes=None,
    mode: str = "DETERMINISTIC",
    independence: bool = True,
):
    return create_admitted_check(
        check_id=check_id,
        check_version=check_version,
        procedure_id=f"{check_id}-procedure-v{check_version}",
        procedure_sha256=digest(f"{check_id}:{check_version}"),
        input_scope=["declared bytes"],
        detects=["declared difference"],
        required_evidence=["presented bytes"],
        dependencies=dependencies,
        outcomes=["FAIL", "PASS", "UNKNOWN"],
        failure_behavior="fail closed",
        evaluator_mode=mode,
        independence_claimed=independence,
        active_from_index_version=active_from,
        supersedes=supersedes,
    )


def test_default_index_binds_current_admitted_surfaces() -> None:
    checked = verify_frozen_check_index(DEFAULT_FROZEN_CHECK_INDEX)
    assert checked["index_version"] == 1
    assert [item["check_id"] for item in checked["entries"]] == [
        "claim_contract",
        "interception_receipt",
        "json_pointer_equals",
        "mirrored_review_receipt",
        "received_turn_receipt",
        "semantic_contract",
        "source_sha256_equals",
    ]
    assert checked["admission_authority"] == "INDEX_MEMBERSHIP_ONLY"
    assert checked["truth_claimed"] is False
    assert checked["write_authority"] == "NONE"


def test_mirrored_review_is_admitted_only_as_non_independent_evidence() -> None:
    mirror = admitted_check(DEFAULT_FROZEN_CHECK_INDEX, "mirrored_review_receipt")
    assert mirror is not None
    assert mirror["evaluator_mode"] == "MIRRORED_EVIDENCE_ONLY"
    assert mirror["independence_claimed"] is False
    assert "never infer independent verification" in mirror["failure_behavior"]


def test_entry_is_closed_and_hash_bound_without_rebinding() -> None:
    original = entry()
    assert verify_admitted_check(original) == original
    tampered = copy.deepcopy(original)
    tampered["detects"] = ["something else"]
    with pytest.raises(FrozenCheckIndexError, match="entry_hash_mismatch"):
        verify_admitted_check(tampered)
    with pytest.raises(FrozenCheckIndexError, match="entry_fields_mismatch"):
        verify_admitted_check({**original, "silent_authority": True})


def test_index_is_closed_and_hash_bound_without_rebinding() -> None:
    original = create_frozen_check_index([entry()])
    assert verify_frozen_check_index(original) == original
    tampered = copy.deepcopy(original)
    tampered["admission_authority"] = "GLOBAL"
    with pytest.raises(FrozenCheckIndexError, match="index_admission_authority_invalid"):
        verify_frozen_check_index(tampered)
    changed_hash = copy.deepcopy(original)
    changed_hash["index_hash"] = "0" * 64
    with pytest.raises(FrozenCheckIndexError, match="index_hash_mismatch"):
        verify_frozen_check_index(changed_hash)


def test_lists_are_canonical_sets_not_order_dependent_inputs() -> None:
    made = create_admitted_check(
        check_id="sorted",
        check_version=1,
        procedure_id="sorted-v1",
        procedure_sha256=digest("sorted"),
        input_scope=["z", "a"],
        detects=["z", "a"],
        required_evidence=["z", "a"],
        dependencies=[],
        outcomes=["UNKNOWN", "PASS"],
        failure_behavior="stop",
    )
    assert made["input_scope"] == ["a", "z"]
    assert made["detects"] == ["a", "z"]
    assert made["outcomes"] == ["PASS", "UNKNOWN"]


def test_mirrored_evidence_cannot_claim_independence() -> None:
    with pytest.raises(
        FrozenCheckIndexError, match="mirrored_evidence_cannot_claim_independence"
    ):
        entry(mode="MIRRORED_EVIDENCE_ONLY", independence=True)


def test_dependency_must_already_exist_in_canonical_order() -> None:
    dependent = entry("bravo", dependencies=["alpha@1"])
    index = create_frozen_check_index([entry("alpha"), dependent])
    assert verify_frozen_check_index(index) == index
    with pytest.raises(
        FrozenCheckIndexError, match="entry_dependency_not_previously_admitted"
    ):
        create_frozen_check_index([entry("alpha", dependencies=["missing@1"])])


def test_extension_is_append_only_and_hash_chained() -> None:
    first = create_frozen_check_index([entry("alpha")])
    candidate = entry("bravo", active_from=2, dependencies=["alpha@1"])
    second = extend_frozen_check_index(first, candidate)
    assert second["index_version"] == 2
    assert second["previous_index_hash"] == first["index_hash"]
    assert second["entries"][0] == first["entries"][0]
    assert len(second["entries"]) == 2


def test_extension_requires_exact_next_admission_version() -> None:
    first = create_frozen_check_index([entry("alpha")])
    with pytest.raises(
        FrozenCheckIndexError, match="candidate_admission_version_mismatch"
    ):
        extend_frozen_check_index(first, entry("bravo", active_from=3))


def test_supersession_preserves_old_entry_and_selects_new_version() -> None:
    first = create_frozen_check_index([entry("alpha")])
    replacement = entry(
        "alpha",
        check_version=2,
        active_from=2,
        supersedes="alpha@1",
    )
    second = extend_frozen_check_index(first, replacement)
    assert admitted_check(second, "alpha", 1) == first["entries"][0]
    assert admitted_check(second, "alpha")["check_version"] == 2
    assert second["entries"][0] == first["entries"][0]


def test_cross_check_supersession_is_rejected() -> None:
    first = create_frozen_check_index([entry("alpha")])
    candidate = entry(
        "bravo", check_version=2, active_from=2, supersedes="alpha@1"
    )
    with pytest.raises(FrozenCheckIndexError, match="entry_supersedes_invalid"):
        extend_frozen_check_index(first, candidate)


def test_unknown_check_is_not_admitted() -> None:
    assert admitted_check(DEFAULT_FROZEN_CHECK_INDEX, "not-present") is None


def test_canonical_serialization_is_reproducible() -> None:
    first = json.dumps(DEFAULT_FROZEN_CHECK_INDEX, sort_keys=True, separators=(",", ":"))
    second = json.dumps(
        verify_frozen_check_index(copy.deepcopy(DEFAULT_FROZEN_CHECK_INDEX)),
        sort_keys=True,
        separators=(",", ":"),
    )
    assert first.encode() == second.encode()
