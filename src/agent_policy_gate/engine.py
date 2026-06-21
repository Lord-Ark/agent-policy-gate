"""Policy engine for evaluating agent tool traces."""

from __future__ import annotations

import fnmatch
import json
from pathlib import Path
from typing import Any, Iterable, List
from urllib.parse import urlparse

from .models import (
    EvaluationResult,
    EvaluationSummary,
    Event,
    Finding,
    Policy,
    Rule,
    ValidationIssue,
)


RISK_HINTS = {
    "read": 15,
    "write": 45,
    "delete": 85,
    "execute": 90,
    "network": 75,
    "secrets": 95,
}

VALID_DECISIONS = {"allow", "review", "deny"}
VALID_SEVERITIES = {"low", "medium", "high", "critical", "info"}


def _metadata_list(value: object) -> List[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return [str(value)]


def load_policy(path: str) -> Policy:
    return Policy.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def _event_payload_items(payload: Any) -> List[object]:
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, (list, tuple)):
        return list(payload)
    return []


def load_events(path: str) -> List[Event]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return [Event.from_dict(item) for item in _event_payload_items(payload)]


def validate_policy(policy: Policy) -> List[ValidationIssue]:
    issues: List[ValidationIssue] = []

    if not policy.name.strip():
        issues.append(ValidationIssue(path="name", message="Policy name must not be empty."))
    if not policy.version.strip():
        issues.append(ValidationIssue(path="version", message="Policy version must not be empty."))
    if policy.default_action not in VALID_DECISIONS:
        issues.append(
            ValidationIssue(
                path="default_action",
                message="default_action must be one of allow, review, or deny.",
            )
        )

    seen_rule_ids = set()
    for index, rule in enumerate(policy.rules):
        path = f"rules[{index}]"
        if not rule.rule_id.strip():
            issues.append(ValidationIssue(path=f"{path}.id", message="Rule id must not be empty."))
        elif rule.rule_id in seen_rule_ids:
            issues.append(
                ValidationIssue(path=f"{path}.id", message=f"Duplicate rule id '{rule.rule_id}'.")
            )
        else:
            seen_rule_ids.add(rule.rule_id)

        if not rule.description.strip():
            issues.append(
                ValidationIssue(
                    path=f"{path}.description",
                    message="Rule description must not be empty.",
                )
            )
        if rule.effect not in VALID_DECISIONS:
            issues.append(
                ValidationIssue(
                    path=f"{path}.effect",
                    message="Rule effect must be one of allow, review, or deny.",
                )
            )
        if rule.severity not in VALID_SEVERITIES:
            issues.append(
                ValidationIssue(
                    path=f"{path}.severity",
                    message="Rule severity must be one of info, low, medium, high, or critical.",
                )
            )
        if rule.risk_threshold is not None:
            try:
                risk_threshold = int(rule.risk_threshold)
            except (TypeError, ValueError):
                issues.append(
                    ValidationIssue(
                        path=f"{path}.risk_threshold",
                        message="risk_threshold must be an integer between 0 and 100.",
                    )
                )
            else:
                if not 0 <= risk_threshold <= 100:
                    issues.append(
                        ValidationIssue(
                            path=f"{path}.risk_threshold",
                            message="risk_threshold must be between 0 and 100.",
                        )
                    )
        if not any(
            [
                rule.actions,
                rule.tools,
                rule.resource_prefixes,
                rule.command_patterns,
                rule.domains,
                rule.env_var_patterns,
                rule.risk_threshold is not None,
            ]
        ):
            issues.append(
                ValidationIssue(
                    path=path,
                    message="Rule must define at least one matcher or risk threshold.",
                    severity="warning",
                )
            )

    return issues


def _derive_risk_score(event: Event) -> int:
    action = event.action.lower()
    score = RISK_HINTS.get(action, 20)
    metadata = event.metadata

    command = str(metadata.get("command", ""))
    if "rm -rf" in command or "sudo" in command:
        score = max(score, 95)
    if metadata.get("requires_approval"):
        score = max(score, 65)
    if metadata.get("writes_outside_workspace"):
        score = max(score, 90)
    if metadata.get("accesses_secrets"):
        score = max(score, 95)
    domain = _event_domain(event)
    if domain and not domain.endswith(".internal"):
        score = max(score, 70)
    return min(score, 100)


def _event_domain(event: Event) -> str:
    domain = str(event.metadata.get("domain", "")).strip().lower()
    if domain:
        return domain

    parsed = urlparse(event.resource)
    return (parsed.hostname or "").lower()


def _matches(rule: Rule, event: Event, risk_score: int) -> bool:
    if rule.actions and event.action not in rule.actions:
        return False
    if rule.tools and event.tool_name not in rule.tools:
        return False
    if rule.resource_prefixes and not any(
        event.resource.startswith(prefix) for prefix in rule.resource_prefixes
    ):
        return False
    command = str(event.metadata.get("command", ""))
    if rule.command_patterns and not any(
        fnmatch.fnmatch(command, pattern) for pattern in rule.command_patterns
    ):
        return False
    domain = _event_domain(event)
    if rule.domains and domain not in rule.domains:
        return False
    env_vars = _metadata_list(event.metadata.get("env_vars"))
    if rule.env_var_patterns and not any(
        fnmatch.filter(env_vars, pattern) for pattern in rule.env_var_patterns
    ):
        return False
    if rule.risk_threshold is not None and risk_score < rule.risk_threshold:
        return False
    return True


def evaluate_trace(policy: Policy, events: Iterable[Event]) -> EvaluationResult:
    findings: List[Finding] = []
    summary = EvaluationSummary()

    for index, event in enumerate(events):
        risk_score = _derive_risk_score(event)
        matched_rules = [rule for rule in policy.rules if _matches(rule, event, risk_score)]
        summary.total_events += 1
        summary.highest_risk_score = max(summary.highest_risk_score, risk_score)

        if matched_rules:
            for rule in matched_rules:
                finding = Finding(
                    event_index=index,
                    decision=rule.effect,
                    severity=rule.severity,
                    reason=rule.description,
                    rule_id=rule.rule_id,
                    event=event,
                    risk_score=risk_score,
                )
                findings.append(finding)
                _increment_summary(summary, rule.effect)
        else:
            finding = Finding(
                event_index=index,
                decision=policy.default_action,
                severity="info",
                reason="No explicit rule matched; default policy applied.",
                event=event,
                risk_score=risk_score,
            )
            findings.append(finding)
            _increment_summary(summary, policy.default_action)

    return EvaluationResult(
        policy_name=policy.name,
        policy_version=policy.version,
        summary=summary,
        findings=findings,
    )


def _increment_summary(summary: EvaluationSummary, decision: str) -> None:
    if decision == "allow":
        summary.allowed += 1
    elif decision == "deny":
        summary.denied += 1
    else:
        summary.review += 1
