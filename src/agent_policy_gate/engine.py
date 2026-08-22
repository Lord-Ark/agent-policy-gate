"""Policy engine for evaluating agent tool traces."""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import re
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
    "network": 35,
    "secrets": 95,
}

VALID_DECISIONS = {"allow", "review", "deny"}
VALID_SEVERITIES = {"low", "medium", "high", "critical", "info"}
DECISION_PRIORITY = {"allow": 0, "review": 1, "deny": 2}
HOSTNAME_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class InputLoadError(ValueError):
    """Raised when a policy or trace file cannot be loaded into JSON."""

    def __init__(self, kind: str, path: str, message: str):
        super().__init__(message)
        self.kind = kind
        self.path = path
        self.message = message


def _append_blank_matcher_issues(
    issues: List[ValidationIssue], path: str, field_name: str, values: List[str]
) -> None:
    for item_index, value in enumerate(values):
        if str(value).strip():
            continue
        issues.append(
            ValidationIssue(
                path=f"{path}.{field_name}[{item_index}]",
                message=f"{field_name} entries must not be empty.",
            )
        )


def _append_invalid_domain_issues(
    issues: List[ValidationIssue], path: str, values: List[str]
) -> None:
    for item_index, value in enumerate(values):
        if not str(value).strip():
            continue
        if _normalize_domain(value):
            continue
        issues.append(
            ValidationIssue(
                path=f"{path}.domains[{item_index}]",
                message="domains entries must include a hostname or IP address.",
            )
        )


def _metadata_list(value: object) -> List[str]:
    if value is None:
        return []
    if isinstance(value, dict):
        return [str(item) for item in value.keys()]
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return [str(value)]


def _is_valid_hostname(hostname: str) -> bool:
    if not hostname or len(hostname) > 253:
        return False
    return all(HOSTNAME_LABEL_RE.fullmatch(label) for label in hostname.split("."))


def _normalize_domain(value: object) -> str:
    text = str(value).strip().lower().rstrip(".")
    if not text:
        return ""

    bracketless = text[1:-1] if text.startswith("[") and text.endswith("]") else text
    try:
        return str(ipaddress.ip_address(bracketless))
    except ValueError:
        pass

    parsed = urlparse(text if "://" in text else f"//{text}")
    if parsed.hostname:
        hostname = parsed.hostname.rstrip(".").lower()
        try:
            return str(ipaddress.ip_address(hostname))
        except ValueError:
            return hostname if _is_valid_hostname(hostname) else ""
    if "://" in text or text.startswith("//"):
        return ""

    candidate = text.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].split(":", 1)[0]
    return candidate if _is_valid_hostname(candidate) else ""


def _policy_payload_dict(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("Policy file must contain a JSON object.")
    return payload


def _policy_rule_items(payload: dict[str, Any]) -> List[dict[str, Any]]:
    if "rules" not in payload:
        return []

    rules = payload.get("rules")
    if not isinstance(rules, (list, tuple)):
        raise ValueError("Policy file 'rules' must contain an array of rule objects.")

    normalized_rules: List[dict[str, Any]] = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise ValueError(f"Policy rule at index {index} must be an object.")
        normalized_rules.append(rule)
    return normalized_rules


def load_policy(path: str) -> Policy:
    payload = _load_json_file(path, kind="policy")
    try:
        policy_payload = _policy_payload_dict(payload)
        _policy_rule_items(policy_payload)
    except ValueError as exc:
        raise InputLoadError("policy", path, str(exc)) from exc
    return Policy.from_dict(policy_payload)


def _event_payload_items(payload: Any) -> List[object]:
    if isinstance(payload, dict):
        if "events" in payload:
            wrapped_events = payload.get("events")
            if isinstance(wrapped_events, (dict, list, tuple)):
                return _event_payload_items(wrapped_events)
            raise ValueError(
                "Trace file 'events' must contain an event object or an array of events."
            )
        return [payload]
    if isinstance(payload, (list, tuple)):
        return list(payload)
    raise ValueError(
        "Trace file must contain an event object, an array of events, or an object with an 'events' field."
    )


def load_events(path: str) -> List[Event]:
    payload = _load_json_file(path, kind="trace")
    try:
        items = _event_payload_items(payload)
    except ValueError as exc:
        raise InputLoadError("trace", path, str(exc)) from exc
    for index, item in enumerate(items):
        if isinstance(item, dict):
            continue
        raise InputLoadError("trace", path, f"Trace event at index {index} must be an object.")
    return [Event.from_dict(item) for item in items]


def _load_json_file(path: str, *, kind: str) -> Any:
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise InputLoadError(kind, path, f"Unable to read {kind} file: {exc.strerror or exc}.") from exc

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InputLoadError(
            kind,
            path,
            f"Invalid JSON in {kind} file at line {exc.lineno}, column {exc.colno}: {exc.msg}.",
        ) from exc


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
        _append_blank_matcher_issues(issues, path, "actions", rule.actions)
        _append_blank_matcher_issues(issues, path, "tools", rule.tools)
        _append_blank_matcher_issues(issues, path, "resource_prefixes", rule.resource_prefixes)
        _append_blank_matcher_issues(issues, path, "command_patterns", rule.command_patterns)
        _append_blank_matcher_issues(issues, path, "domains", rule.domains)
        _append_invalid_domain_issues(issues, path, rule.domains)
        _append_blank_matcher_issues(issues, path, "env_var_patterns", rule.env_var_patterns)
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
    domain = _event_domain(event) if action == "network" else ""
    if domain and not _is_internal_domain(domain):
        score = max(score, 75)
    return min(score, 100)


def _event_domain(event: Event) -> str:
    domain = _normalize_domain(event.metadata.get("domain", ""))
    if domain:
        return domain

    return _resource_domain(event.resource)


def _resource_domain(resource: str) -> str:
    text = str(resource).strip()
    if not text:
        return ""
    if "://" in text or text.startswith("//"):
        return _normalize_domain(text)

    candidate = _normalize_domain(text)
    if not candidate:
        return ""
    if candidate == "localhost" or candidate.endswith(".localhost") or candidate.endswith(".internal"):
        return candidate
    if "." in candidate:
        return candidate

    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return ""

    return candidate


def _is_internal_domain(domain: str) -> bool:
    normalized = _normalize_domain(domain)
    if not normalized:
        return False
    if normalized == "localhost" or normalized.endswith(".localhost"):
        return True
    if normalized.endswith(".internal"):
        return True

    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return False

    return address.is_private or address.is_loopback or address.is_link_local


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
    rule_domains = [_normalize_domain(candidate) for candidate in rule.domains]
    if rule.domains and domain not in rule_domains:
        return False
    env_vars = _metadata_list(event.metadata.get("env_vars"))
    if rule.env_var_patterns and not any(
        fnmatch.filter(env_vars, pattern) for pattern in rule.env_var_patterns
    ):
        return False
    if rule.risk_threshold is not None:
        try:
            risk_threshold = int(rule.risk_threshold)
        except (TypeError, ValueError):
            return False
        if risk_score < risk_threshold:
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
            _increment_summary(
                summary,
                max((rule.effect for rule in matched_rules), key=DECISION_PRIORITY.__getitem__),
            )
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
