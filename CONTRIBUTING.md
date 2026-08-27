# Contributing to Free Valid AI

Free Valid AI is open to corrections, contradictions, new checks, and bounded
capability proposals. Contributions are evaluated by their declared scope,
reproducible evidence, and tests—not by the contributor's identity, reputation,
model, or hardware.

The project does not require contributors to be infallible. It requires every
meaningful claim to remain inspectable, challengeable, and correctable.

## Before opening a pull request

Open an issue or pull request that states:

1. **The exact claim or proposed capability.** Avoid universal language when
   the result is only established for one environment or constraint set.
2. **The declared scope.** Identify the task, environment, inputs, versions,
   constraints, and authority boundary.
3. **What is already verified.** Reference exact source bytes, hashes,
   deterministic receipts, tests, or reproducible observations.
4. **What remains unknown.** Missing evidence must remain `UNKNOWN`; it must not
   be promoted to success, failure, or impossibility.
5. **What would contradict the proposal.** Name the negative evidence or
   failure case that would require correction.
6. **What would require reassessment.** State which environmental, resource,
   scope, or logical constraint changes could invalidate the result.
7. **The smallest failing test.** New behavior should begin with a concrete,
   falsifiable failure rather than a broad cleanup claim.
8. **Attribution and usage terms.** Identify the creators and sources of
   contributed material and preserve their declared terms.

## Evidence requirements

Evidence used by runtime decisions must be admitted by the frozen check index
and replayable from the exact presented bytes. A self-declared `PASS`, result
label, receipt digest, citation, or model agreement is not verification.

When independent evidence is unavailable, say so. Mirrored model review may be
useful evidence, but it must not be represented as independent confirmation.

The expected stopping results are explicit:

- `HELD` — the admitted procedure established the bounded claim.
- `CONTRADICTED` — the admitted procedure established a bounded conflict.
- `BLOCKED` — required evidence or execution conditions were unavailable.
- `UNKNOWN` — the available evidence did not establish a supported result.

For possibility assessments, preserve the distinction between:

- `POSSIBLE_WITHIN_CONSTRAINTS`
- `IMPOSSIBLE_UNDER_CONSTRAINTS`
- `CURRENTLY_INFEASIBLE`
- `OUT_OF_SCOPE`
- `UNKNOWN`

`IMPOSSIBLE_UNDER_CONSTRAINTS` is never a universal or permanent impossibility
claim. It applies only to the declared logical requirements and named
environment. Constraint changes require reassessment.

## Pull request requirements

A pull request should:

- make one smallest supported change;
- identify the exact files and functions involved;
- include focused tests for success, contradiction, missing evidence, tampering,
  and caller attempts to supply computed outcomes when applicable;
- run the complete test suite;
- preserve closed schemas and deterministic canonical serialization;
- fail closed when evidence is incomplete, malformed, unadmitted, altered,
  rebound, or extra;
- keep verification, classification, acceptance, release, and execution
  authority separate;
- update documentation only when the implementation actually supports the
  documented behavior.

Do not combine unrelated cleanup with a functional correction. If no concrete
failure can be reproduced, document the uncertainty instead of changing code.

## Authority boundaries

Unless a contract explicitly and narrowly says otherwise, contributed records
must preserve:

```text
accepted: false
truth_claimed: false
write_authority: NONE
execution_authority: NONE
deletion_authority: NONE
```

A verifier may establish a bounded result. It does not automatically gain
permission to accept, publish, overwrite, delete, execute, or restore anything.

## Local verification

From the repository root:

```console
python -m pytest -q
```

Include focused-test and full-suite results in the pull request description.
Platform timing by itself is not evidence of a production performance defect;
use the smallest reproducible measurement that distinguishes code behavior from
ordinary environmental variance.

## Corrections are contributions

Evidence-backed disagreement is welcome. If an existing claim, test, receipt,
constraint, or implementation is wrong, preserve the prior trail, identify the
smallest mismatch, and submit the correction with the evidence that exposed it.

The goal is not consensus or endless iteration. The goal is a public process
that can learn, stop when nothing is established, and resume when the
environment supplies genuinely new evidence.
