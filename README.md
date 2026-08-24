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

`run_json_pointer_check()` performs the first deterministic structured claim
check. After source-identity verification, it parses UTF-8 JSON, resolves an
RFC 6901 JSON Pointer, and compares canonical typed values. Missing paths and
different values are `CONTRADICTED`; malformed bound JSON is `BLOCKED`; changed
source identity remains `UNKNOWN`.

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
## Local terminal chat

Talk to an Ollama model running on your own computer:

```bash
python -m pip install -e ".[dev]"
free-valid-ai chat --model llama3.2
```

The initial chat surface accepts only an HTTP loopback Ollama endpoint. It has
no cloud fallback, API-key path, telemetry, persistence, file access, command
execution, write authority, or claim-verification authority. Conversation
history exists only in memory until the process exits.

CPU-only execution is the default (`--num-gpu 0`) so Ollama hardware
autodetection cannot silently select a GPU. A user may explicitly choose a
non-negative GPU-layer count.

The command supplies a program-generated `RUNTIME_ENVELOPE_V1` system message
on every turn. It identifies the selected model, local loopback transport,
explicit compute selection, and absent write/execution authority. These are
external runtime facts; model prose is not the authority for them.

The user-facing assistant identity is **Simulator**. The selected local model
is its replaceable language carrier, not the assistant's identity. Runtime
authority fields explicitly bind restrictions to Simulator and do not infer or
limit the user's authority.

## Semantic runtime contract

Simulator binds a closed, versioned semantic contract into every runtime
envelope. `HOLO`, `SIMULATOR`, `MODEL_CARRIER`, `PROJECTION`, and `HOLOGRAM`
have exact, non-equivalent meanings. The contract is SHA-256 bound, rejects
unknown fields and asymmetric relationships, grants no authority, and remains
independently verifiable before use.

## Received and intercepted turns

`free_valid_ai.turn_boundary` binds exact incoming bytes before interpretation
and holds proposed output before presentation. Release is limited to the
explicit decisions `UNCHANGED`, `CORRECTED`, `BLOCKED`, and `UNKNOWN`. A
correction must name a hash-bound basis; failed or unknown checks cannot release
output. This boundary calls no model and grants no truth, acceptance, write,
execution, or deletion authority.
