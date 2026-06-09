"""Command-line interface for Agent Policy Gate."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional

from .engine import evaluate_trace, load_events, load_policy, validate_policy
from .render import (
    render_html,
    render_json,
    render_sarif,
    render_text,
    render_validation_json,
    render_validation_text,
)


def _risk_threshold_value(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("risk threshold must be an integer.") from exc
    if not 0 <= value <= 100:
        raise argparse.ArgumentTypeError("risk threshold must be between 0 and 100.")
    return value


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
        choices=("text", "json", "html", "sarif"),
        default="text",
        help="Output format.",
    )
    evaluate_parser.add_argument("--output", help="Write rendered output to a file.")
    evaluate_parser.add_argument(
        "--fail-on",
        choices=("deny", "review"),
        help="Return a non-zero exit code when findings meet or exceed the selected decision.",
    )
    evaluate_parser.add_argument(
        "--risk-threshold",
        type=_risk_threshold_value,
        help="Return a non-zero exit code when the highest derived risk score meets or exceeds this threshold.",
    )

    validate_parser = subparsers.add_parser("validate", help="Validate a policy document.")
    validate_parser.add_argument("--policy", required=True, help="Path to policy JSON.")
    validate_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Validation output format.",
    )
    validate_parser.add_argument("--output", help="Write rendered output to a file.")

    return parser


def _render(result, output_format: str) -> str:
    if output_format == "json":
        return render_json(result)
    if output_format == "sarif":
        return render_sarif(result)
    if output_format == "html":
        return render_html(result)
    return render_text(result)


def _render_validation(issues, output_format: str) -> str:
    if output_format == "json":
        return render_validation_json(issues)
    return render_validation_text(issues)


def _write_output(output: Optional[str], content: str) -> None:
    if output:
        Path(output).write_text(content, encoding="utf-8")
    else:
        print(content)


def _should_fail(result, fail_on: Optional[str], risk_threshold: Optional[int]) -> bool:
    if risk_threshold is not None and result.summary.highest_risk_score >= risk_threshold:
        return True
    if fail_on == "deny" and result.summary.denied > 0:
        return True
    if fail_on == "review" and (result.summary.denied > 0 or result.summary.review > 0):
        return True
    return False


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "evaluate":
        policy = load_policy(args.policy)
        issues = [issue for issue in validate_policy(policy) if issue.severity == "error"]
        if issues:
            _write_output(args.output, _render_validation(issues, "text"))
            return 1
        events = load_events(args.trace)
        result = evaluate_trace(policy, events)
        _write_output(args.output, _render(result, args.format))
        return 3 if _should_fail(result, args.fail_on, args.risk_threshold) else 0

    if args.command == "validate":
        policy = load_policy(args.policy)
        issues = validate_policy(policy)
        _write_output(args.output, _render_validation(issues, args.format))
        has_errors = any(issue.severity == "error" for issue in issues)
        return 1 if has_errors else 0

    parser.error("Unsupported command.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
