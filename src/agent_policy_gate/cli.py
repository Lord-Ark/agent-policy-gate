"""Command-line interface for Agent Policy Gate."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

from . import __version__
from .engine import InputLoadError, evaluate_trace, load_events, load_policy, validate_policy
from .models import ValidationIssue
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


class OutputWriteError(OSError):
    """Raised when rendered CLI output cannot be written."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apg",
        description="Evaluate AI agent tool execution traces against security policies.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
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
    evaluate_parser.add_argument("--output", help="Write rendered output to a file. Use - for stdout.")
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
    validate_parser.add_argument("--output", help="Write rendered output to a file. Use - for stdout.")

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


def _validation_format_for_evaluate(output_format: str) -> str:
    return "json" if output_format == "json" else "text"


def _write_output(output: Optional[str], content: str) -> None:
    if output and output != "-":
        output_path = Path(output)
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(content, encoding="utf-8")
        except OSError as exc:
            raise OutputWriteError(
                f"Unable to write output file '{output_path}': {exc.strerror or exc}."
            ) from exc
    else:
        print(content)


def _should_fail(result, fail_on: Optional[str], risk_threshold: Optional[int]) -> bool:
    if (
        risk_threshold is not None
        and result.summary.total_events > 0
        and result.summary.highest_risk_score >= risk_threshold
    ):
        return True
    if fail_on == "deny" and result.summary.denied > 0:
        return True
    if fail_on == "review" and (result.summary.denied > 0 or result.summary.review > 0):
        return True
    return False


def _validate_stdin_sources(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.command == "evaluate" and args.policy == "-" and args.trace == "-":
        parser.error("Only one of --policy or --trace may read from stdin during evaluation.")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    _validate_stdin_sources(parser, args)

    try:
        if args.command == "evaluate":
            validation_format = _validation_format_for_evaluate(args.format)
            try:
                policy = load_policy(args.policy)
            except InputLoadError as exc:
                _write_output(
                    args.output,
                    _render_validation(
                        [ValidationIssue(path=exc.kind, message=exc.message)],
                        validation_format,
                    ),
                )
                return 1
            issues = [issue for issue in validate_policy(policy) if issue.severity == "error"]
            if issues:
                _write_output(args.output, _render_validation(issues, validation_format))
                return 1
            try:
                events = load_events(args.trace)
            except InputLoadError as exc:
                _write_output(
                    args.output,
                    _render_validation(
                        [ValidationIssue(path=exc.kind, message=exc.message)],
                        validation_format,
                    ),
                )
                return 1
            result = evaluate_trace(policy, events)
            _write_output(args.output, _render(result, args.format))
            return 3 if _should_fail(result, args.fail_on, args.risk_threshold) else 0

        if args.command == "validate":
            try:
                policy = load_policy(args.policy)
            except InputLoadError as exc:
                _write_output(
                    args.output,
                    _render_validation(
                        [ValidationIssue(path=exc.kind, message=exc.message)],
                        args.format,
                    ),
                )
                return 1
            issues = validate_policy(policy)
            _write_output(args.output, _render_validation(issues, args.format))
            has_errors = any(issue.severity == "error" for issue in issues)
            return 1 if has_errors else 0

        parser.error("Unsupported command.")
        return 2
    except OutputWriteError as exc:
        print(exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
