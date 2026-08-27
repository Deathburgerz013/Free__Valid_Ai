"""Open, authority-free claim and verification primitives."""

from free_valid_ai.claims import (
    ClaimContractError,
    assess_claim,
    create_claim,
    create_verification_receipt,
    verify_claim,
    verify_verification_receipt,
)
from free_valid_ai.checks import run_json_pointer_check, run_source_sha256_check
from free_valid_ai.semantics import (
    DEFAULT_SEMANTIC_CONTRACT,
    SemanticContractError,
    create_semantic_contract,
    relation,
    verify_semantic_contract,
)
from free_valid_ai.turn_boundary import (
    TurnBoundaryError,
    create_interception,
    create_received_turn,
    verify_interception,
    verify_received_turn,
)
from free_valid_ai.mirrored_review import (
    MIRRORED_REVIEW_SCHEMA,
    MIRRORED_REVIEW_SCHEMA_SHA256,
    MirroredReviewError,
    parse_mirrored_review,
    verify_mirrored_review,
)
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
from free_valid_ai.directional_comparator import (
    COMPARISONS,
    DirectionalComparatorError,
    compare_directional,
    verify_directional_comparison,
)
from free_valid_ai.output_gate import (
    OutputGateError,
    gate_is_caller_independent,
    run_verified_model_call,
)
from free_valid_ai.possibility import (
    ASSESSMENTS,
    CONSTRAINT_KINDS,
    PossibilityAssessmentError,
    assess_possibility,
    verify_possibility_assessment,
)
from free_valid_ai.consequence_gate import (
    CONSEQUENCE_DECISIONS,
    ConsequenceGateError,
    assess_consequences,
    consequence_gate_is_caller_independent,
    verify_consequence_gate,
)

__all__ = [
    "ClaimContractError",
    "DEFAULT_SEMANTIC_CONTRACT",
    "SemanticContractError",
    "TurnBoundaryError",
    "MirroredReviewError",
    "MIRRORED_REVIEW_SCHEMA",
    "MIRRORED_REVIEW_SCHEMA_SHA256",
    "DEFAULT_FROZEN_CHECK_INDEX",
    "FrozenCheckIndexError",
    "DirectionalComparatorError",
    "COMPARISONS",
    "OutputGateError",
    "PossibilityAssessmentError",
    "ASSESSMENTS",
    "CONSTRAINT_KINDS",
    "ConsequenceGateError",
    "CONSEQUENCE_DECISIONS",
    "admitted_check",
    "assess_claim",
    "assess_possibility",
    "assess_consequences",
    "create_claim",
    "create_semantic_contract",
    "create_interception",
    "create_received_turn",
    "create_verification_receipt",
    "create_admitted_check",
    "create_frozen_check_index",
    "compare_directional",
    "gate_is_caller_independent",
    "consequence_gate_is_caller_independent",
    "verify_consequence_gate",
    "verify_directional_comparison",
    "run_verified_model_call",
    "extend_frozen_check_index",
    "relation",
    "parse_mirrored_review",
    "run_source_sha256_check",
    "run_json_pointer_check",
    "verify_claim",
    "verify_semantic_contract",
    "verify_interception",
    "verify_received_turn",
    "verify_mirrored_review",
    "verify_verification_receipt",
    "verify_possibility_assessment",
    "verify_admitted_check",
    "verify_frozen_check_index",
]
