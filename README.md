# Free__Valid_Ai

An open, attributable knowledge commons where claims are scoped, source-bound,
independently checked, and corrected without rewriting history. Models remain
replaceable and hold no authority.

## First invariant

A claim cannot grade itself.

This initial contract separates claims from verification receipts. Claims begin
`UNVERIFIED`. Every source must carry attribution, integrity, explicit usage
decisions, compensation terms, and a consent receipt. A declared verifier must
differ from the claim author. Receipts form a hash-bound append-only chain.

The contract verifies record integrity and declared boundaries. It does not
claim that recording a check proves timeless truth.

## First deterministic check

`run_source_sha256_check()` computes its own result from directly presented
bytes. The caller cannot choose the result. It first verifies that the bytes
match the source identity bound by the claim, then compares the scoped expected
digest. Missing bytes are `BLOCKED`; identity mismatch is `UNKNOWN`; only
identity-matching bytes can produce `HELD` or `CONTRADICTED`.

All records retain:

```text
accepted=false
truth_claimed=false
write_authority=NONE
execution_authority=NONE
deletion_authority=NONE
```

## Development

```bash
python -m pip install -e ".[dev]"
python -m pytest -q
```
