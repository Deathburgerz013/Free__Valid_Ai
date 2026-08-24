"""Interactive terminal conversation with a replaceable local model."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from typing import Callable

from .local_model import ChatTransport, LocalModelError
from .mirrored_review import (
    MIRRORED_REVIEW_SCHEMA,
    MirroredReviewError,
    parse_mirrored_review,
)
from .turn_boundary import create_interception, create_received_turn


Input = Callable[[str], str]
Output = Callable[[str], None]


@dataclass
class ChatSession:
    model: str
    transport: ChatTransport
    assistant_name: str = "Simulator"
    runtime_envelope: str | None = None
    mirrored_review: bool = False
    messages: list[dict[str, str]] = field(default_factory=list)
    previous_received_turn_hash: str | None = None
    turn_sequence: int = 0
    last_turn_audit: dict | None = None

    def ask(self, text: str) -> str:
        if not text.strip():
            raise ValueError("message must not be empty")
        received = create_received_turn(
            text.encode("utf-8"), role="USER", sequence=self.turn_sequence,
            previous_received_turn_hash=self.previous_received_turn_hash,
        )
        proposed: list[dict[str, str]] = []
        if self.runtime_envelope is not None:
            proposed.append({"role": "system", "content": self.runtime_envelope})
        proposed.extend(self.messages)
        proposed.append({"role": "user", "content": text})
        draft = self.transport.chat(self.model, proposed)
        if not self.mirrored_review:
            answer = draft
            self.last_turn_audit = None
        else:
            answer = self._review(received, text, draft)
        self.messages.extend(
            ({"role": "user", "content": text}, {"role": "assistant", "content": answer})
        )
        self.previous_received_turn_hash = received["received_turn_hash"]
        self.turn_sequence += 1
        return answer

    def _review(self, received: dict, question: str, draft: str) -> str:
        draft_hash = hashlib.sha256(draft.encode()).hexdigest()
        review_prompt = json.dumps(
            {"received_turn_hash": received["received_turn_hash"],
             "question": question, "draft": draft}, sort_keys=True)
        review_messages = []
        if self.runtime_envelope is not None:
            review_messages.append({"role": "system", "content": self.runtime_envelope})
        review_messages.extend([
            {"role": "system", "content": (
                "MIRRORED_REVIEW_V1. You are the same model carrier, not an independent "
                "verifier. Inspect the draft for contradiction, unsupported runtime claims, "
                "or missed uncertainty. Return only JSON with exactly assessment and issues. "
                "assessment is CLEAN, CORRECTION_REQUIRED, or UNKNOWN; issues is a string list."
            )},
            {"role": "user", "content": review_prompt},
        ])
        structured = getattr(self.transport, "chat_structured", None)
        raw = (
            structured(self.model, review_messages, MIRRORED_REVIEW_SCHEMA)
            if callable(structured)
            else self.transport.chat(self.model, review_messages)
        )
        try:
            review = parse_mirrored_review(
                raw, model_carrier=self.model,
                received_turn_hash=received["received_turn_hash"],
                draft_sha256=draft_hash,
            )
        except MirroredReviewError as exc:
            check = {"check_id": "mirror_review_schema", "result": "UNKNOWN",
                     "evidence_sha256": hashlib.sha256(raw.encode()).hexdigest()}
            interception = create_interception(received, draft.encode(), checks=[check])
            self.last_turn_audit = {"received": received, "review": None,
                                    "interception": interception}
            raise LocalModelError(f"mirrored review UNKNOWN: {exc}") from exc
        checks = [{"check_id": "mirror_review_schema", "result": "PASS",
                   "evidence_sha256": review["review_hash"]}]
        assessment = review["assessment"]
        if assessment == "UNKNOWN":
            checks[0]["result"] = "UNKNOWN"
            interception = create_interception(received, draft.encode(), checks=checks)
            self.last_turn_audit = {"received": received, "review": review,
                                    "interception": interception}
            raise LocalModelError("mirrored review returned UNKNOWN")
        if assessment == "CLEAN":
            final = draft
            interception = create_interception(
                received, draft.encode(), checks=checks, released=final.encode())
        else:
            correction_prompt = json.dumps(
                {"question": question, "draft": draft, "review": review}, sort_keys=True)
            correction_messages = []
            if self.runtime_envelope is not None:
                correction_messages.append(
                    {"role": "system", "content": self.runtime_envelope}
                )
            correction_messages.extend([
                {"role": "system", "content": (
                    "BOUNDED_CORRECTION_V1. Apply only the listed issues. Return only the "
                    "corrected answer. Do not claim the mirrored review was independent."
                )}, {"role": "user", "content": correction_prompt},
            ])
            final = self.transport.chat(self.model, correction_messages)
            if not final.strip() or final == draft:
                checks.append({"check_id": "correction_changed_nonempty", "result": "FAIL",
                               "evidence_sha256": hashlib.sha256(final.encode()).hexdigest()})
                checks.sort(key=lambda item: item["check_id"])
                interception = create_interception(received, draft.encode(), checks=checks)
                self.last_turn_audit = {"received": received, "review": review,
                                        "interception": interception}
                raise LocalModelError("bounded correction failed deterministic checks")
            interception = create_interception(
                received, draft.encode(), checks=checks, released=final.encode(),
                correction_basis_sha256=review["review_hash"],
            )
        self.last_turn_audit = {"received": received, "review": review,
                                "interception": interception}
        return final


def run_chat(
    session: ChatSession,
    *,
    input_fn: Input = input,
    output_fn: Output = print,
) -> int:
    output_fn("Free__Valid_Ai")
    output_fn(f"Assistant: {session.assistant_name}")
    output_fn(f"Model: {session.model}")
    output_fn("Transport: local Ollama (loopback only)")
    output_fn("Assistant write authority: NONE")
    output_fn("Assistant execution authority: NONE")
    output_fn("User authority: NOT_ASSESSED")
    output_fn(f"Mirrored review: {'ENABLED' if session.mirrored_review else 'DISABLED'}")
    output_fn("Type /exit to stop. Conversation is not saved.\n")
    while True:
        try:
            message = input_fn("You> ")
        except (EOFError, KeyboardInterrupt):
            output_fn("")
            return 0
        command = message.strip().lower()
        if command in {"/exit", "/quit"}:
            return 0
        if not command:
            continue
        try:
            output_fn(f"AI> {session.ask(message)}\n")
        except (LocalModelError, ValueError) as exc:
            output_fn(f"ERROR: {exc}")
            return 1
