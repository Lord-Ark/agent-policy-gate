"""Core data models for policy evaluation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


def _as_string(value: Any, *, lower: bool = False) -> str:
    text = str(value).strip()
    return text.lower() if lower else text


def _as_dict(payload: Any) -> Dict[str, Any]:
    if isinstance(payload, dict):
        return payload
    return {}


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _coerce_optional_int(value: Any) -> Any:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return value


@dataclass
class Event:
    """A normalized tool execution event emitted by an agent runtime."""

    timestamp: str
    actor: str
    tool_name: str
    action: str
    resource: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "Event":
        payload = _as_dict(payload)
        metadata = payload.get("metadata", {})
        return cls(
            timestamp=_as_string(payload.get("timestamp", "")),
            actor=_as_string(payload.get("actor", "unknown")),
            tool_name=_as_string(payload.get("tool_name", "unknown"), lower=True),
            action=_as_string(payload.get("action", "unknown"), lower=True),
            resource=_as_string(payload.get("resource", "")),
            metadata=dict(metadata) if isinstance(metadata, dict) else {},
        )


@dataclass
class Rule:
    """A single policy rule used to match tool execution events."""

    rule_id: str
    description: str
    effect: str
    actions: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)
    resource_prefixes: List[str] = field(default_factory=list)
    command_patterns: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    env_var_patterns: List[str] = field(default_factory=list)
    risk_threshold: Optional[int] = None
    severity: str = "medium"

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "Rule":
        payload = _as_dict(payload)
        return cls(
            rule_id=_as_string(payload.get("id", "")),
            description=_as_string(payload.get("description", "")),
            effect=_as_string(payload.get("effect", ""), lower=True),
            actions=[
                _as_string(action, lower=True) for action in _as_list(payload.get("actions", []))
            ],
            tools=[_as_string(tool, lower=True) for tool in _as_list(payload.get("tools", []))],
            resource_prefixes=[
                _as_string(prefix) for prefix in _as_list(payload.get("resource_prefixes", []))
            ],
            command_patterns=[
                _as_string(pattern) for pattern in _as_list(payload.get("command_patterns", []))
            ],
            domains=[_as_string(domain, lower=True) for domain in _as_list(payload.get("domains", []))],
            env_var_patterns=[
                _as_string(pattern) for pattern in _as_list(payload.get("env_var_patterns", []))
            ],
            risk_threshold=_coerce_optional_int(payload.get("risk_threshold")),
            severity=_as_string(payload.get("severity", "medium"), lower=True),
        )


@dataclass
class Policy:
    """Top-level policy document."""

    name: str
    version: str
    default_action: str
    rules: List[Rule]

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "Policy":
        payload = _as_dict(payload)
        return cls(
            name=_as_string(payload.get("name", "unnamed-policy")),
            version=_as_string(payload.get("version", "0.0.0")),
            default_action=_as_string(payload.get("default_action", "allow"), lower=True),
            rules=[Rule.from_dict(rule) for rule in _as_list(payload.get("rules", []))],
        )


@dataclass
class ValidationIssue:
    """A policy validation issue."""

    path: str
    message: str
    severity: str = "error"

    def to_dict(self) -> Dict[str, str]:
        return {
            "path": self.path,
            "message": self.message,
            "severity": self.severity,
        }


@dataclass
class Finding:
    """A rule hit or heuristic escalation for a single event."""

    event_index: int
    decision: str
    severity: str
    reason: str
    rule_id: Optional[str] = None
    event: Optional[Event] = None
    risk_score: int = 0

    def to_dict(self) -> Dict[str, Any]:
        payload = {
            "event_index": self.event_index,
            "decision": self.decision,
            "severity": self.severity,
            "reason": self.reason,
            "rule_id": self.rule_id,
            "risk_score": self.risk_score,
        }
        if self.event is not None:
            payload["event"] = {
                "timestamp": self.event.timestamp,
                "actor": self.event.actor,
                "tool_name": self.event.tool_name,
                "action": self.event.action,
                "resource": self.event.resource,
                "metadata": self.event.metadata,
            }
        return payload


@dataclass
class EvaluationSummary:
    """Summary counts and overall posture for the analyzed trace."""

    allowed: int = 0
    denied: int = 0
    review: int = 0
    total_events: int = 0
    highest_risk_score: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "denied": self.denied,
            "review": self.review,
            "total_events": self.total_events,
            "highest_risk_score": self.highest_risk_score,
        }


@dataclass
class EvaluationResult:
    """Complete evaluation response."""

    policy_name: str
    policy_version: str
    summary: EvaluationSummary
    findings: List[Finding]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_name": self.policy_name,
            "policy_version": self.policy_version,
            "summary": self.summary.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
        }
