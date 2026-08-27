"""Command-line surface for Free__Valid_Ai."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from .chat import ChatSession, run_chat
from .local_model import OllamaTransport
from .runtime_envelope import build_runtime_envelope


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
        "--no-mirror-review", action="store_false", dest="mirror_review",
        help="disable the default same-carrier mirrored review",
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
                mirrored_review=args.mirror_review,
            )
        )
    raise AssertionError("unreachable command")


if __name__ == "__main__":
    raise SystemExit(main())
