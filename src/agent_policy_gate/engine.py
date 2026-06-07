"""Policy engine for evaluating agent tool traces."""

from __future__ import annotations

import fnmatch
import json
from pathlib import Path
from typing import Iterable, List

from .models import EvaluationResult, EvaluationSummary, Event, Finding, Policy, Rule


RISK_HINTS = {
    "read": 15,
    "write": 45,
    "delete": 85,
    "execute": 90,
    "network": 75,
    "secrets": 95,
}


def load_policy(path: str) -> Policy:
    return Policy.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def load_events(path: str) -> List[Event]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return [Event.from_dict(item) for item in payload]


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
    if metadata.get("domain") and not str(metadata.get("domain", "")).endswith(".internal"):
        score = max(score, 70)
    return min(score, 100)


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
    domain = str(event.metadata.get("domain", ""))
    if rule.domains and domain not in rule.domains:
        return False
    env_vars = [str(item) for item in event.metadata.get("env_vars", [])]
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

