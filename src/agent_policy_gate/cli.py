"""Command-line interface for Agent Policy Gate."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional

from .engine import evaluate_trace, load_events, load_policy
from .render import render_html, render_json, render_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apg",
        description="Evaluate AI agent tool execution traces against security policies.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    evaluate_parser = subparsers.add_parser("evaluate", help="Evaluate a trace.")
    evaluate_parser.add_argument("--policy", required=True, help="Path to policy JSON.")
    evaluate_parser.add_argument("--trace", required=True, help="Path to trace JSON.")
    evaluate_parser.add_argument(
        "--format",
        choices=("text", "json", "html"),
        default="text",
        help="Output format.",
    )
    evaluate_parser.add_argument("--output", help="Write rendered output to a file.")

    return parser


def _render(result, output_format: str) -> str:
    if output_format == "json":
        return render_json(result)
    if output_format == "html":
        return render_html(result)
    return render_text(result)


def _write_output(output: Optional[str], content: str) -> None:
    if output:
        Path(output).write_text(content, encoding="utf-8")
    else:
        print(content)


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "evaluate":
        policy = load_policy(args.policy)
        events = load_events(args.trace)
        result = evaluate_trace(policy, events)
        _write_output(args.output, _render(result, args.format))
        return 0

    parser.error("Unsupported command.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

