"""Command-line surface for Free__Valid_Ai."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from .chat import ChatSession, run_chat
from .local_model import OllamaTransport


def build_runtime_envelope(*, model: str, endpoint: str, num_gpu: int) -> str:
    execution = "CPU_ONLY" if num_gpu == 0 else f"GPU_LAYERS_{num_gpu}"
    return "\n".join(
        (
            "RUNTIME_ENVELOPE_V1",
            "These facts are supplied by the local program, not inferred by the model.",
            "assistant_identity=Simulator",
            f"model_carrier={model}",
            "identity_rule=The assistant is Simulator; the model carrier is replaceable.",
            "transport=LOCAL_OLLAMA",
            f"transport_endpoint={endpoint}",
            "transport_scope=LOOPBACK_ONLY",
            f"execution_selection={execution}",
            "assistant_write_authority=NONE",
            "assistant_execution_authority=NONE",
            "user_authority=NOT_ASSESSED",
            "cloud_service_claim=FALSE_FOR_THIS_RUNTIME",
            "Speak as Simulator. Use the model name only to identify the carrier.",
            "Do not claim cloud execution or assign assistant restrictions to the user.",
        )
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="free-valid-ai")
    subcommands = parser.add_subparsers(dest="command", required=True)
    chat = subcommands.add_parser("chat", help="talk to a local Ollama model")
    chat.add_argument("--model", default="llama3.2", help="installed Ollama model name")
    chat.add_argument(
        "--endpoint",
        default="http://127.0.0.1:11434/api/chat",
        help="loopback Ollama /api/chat endpoint",
    )
    chat.add_argument(
        "--num-gpu",
        type=int,
        default=0,
        help="GPU layers for Ollama; defaults to 0 for CPU-only execution",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "chat":
        transport = OllamaTransport(endpoint=args.endpoint, num_gpu=args.num_gpu)
        envelope = build_runtime_envelope(
            model=args.model, endpoint=args.endpoint, num_gpu=args.num_gpu
        )
        return run_chat(
            ChatSession(
                model=args.model,
                transport=transport,
                assistant_name="Simulator",
                runtime_envelope=envelope,
            )
        )
    raise AssertionError("unreachable command")


if __name__ == "__main__":
    raise SystemExit(main())
