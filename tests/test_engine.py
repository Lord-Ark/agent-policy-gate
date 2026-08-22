import unittest
import json
import tempfile
from pathlib import Path

from agent_policy_gate.engine import (
    InputLoadError,
    _event_payload_items,
    evaluate_trace,
    load_events,
    load_policy,
    validate_policy,
)
from agent_policy_gate.models import Event, Policy


class EngineTestCase(unittest.TestCase):
    def setUp(self):
        self.policy = Policy.from_dict(
            {
                "name": "test-policy",
                "version": "1.0.0",
                "default_action": "review",
                "rules": [
                    {
                        "id": "deny-shell",
                        "description": "deny destructive commands",
                        "effect": "deny",
                        "actions": ["execute"],
                        "command_patterns": ["*rm -rf*"],
                    },
                    {
                        "id": "allow-docs",
                        "description": "allow docs",
                        "effect": "allow",
                        "resource_prefixes": ["docs/"],
                    },
                ],
            }
        )

    def test_denies_destructive_command(self):
        events = [
            Event.from_dict(
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "actor": "agent",
                    "tool_name": "shell",
                    "action": "execute",
                    "resource": "/workspace",
                    "metadata": {"command": "rm -rf ."},
                }
            )
        ]
        result = evaluate_trace(self.policy, events)
        self.assertEqual(result.summary.denied, 1)
        self.assertEqual(result.findings[0].rule_id, "deny-shell")

    def test_defaults_when_no_rule_matches(self):
        events = [
            Event.from_dict(
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "actor": "agent",
                    "tool_name": "api",
                    "action": "network",
                    "resource": "https://example.com",
                    "metadata": {"domain": "example.com"},
                }
            )
        ]
        result = evaluate_trace(self.policy, events)
        self.assertEqual(result.summary.review, 1)
        self.assertIn("default policy", result.findings[0].reason)

    def test_allows_docs_access(self):
        events = [
            Event.from_dict(
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "actor": "agent",
                    "tool_name": "fs",
                    "action": "write",
                    "resource": "docs/readme.md",
                    "metadata": {},
                }
            )
        ]
        result = evaluate_trace(self.policy, events)
        self.assertEqual(result.summary.allowed, 1)

    def test_matches_actions_and_tools_case_insensitively(self):
        policy = Policy.from_dict(
            {
                "name": "mixed-case-policy",
                "version": "1.0.0",
                "default_action": "review",
                "rules": [
                    {
                        "id": "deny-shell",
                        "description": "deny destructive commands",
                        "effect": "deny",
                        "actions": ["EXECUTE"],
                        "tools": ["Shell"],
                        "command_patterns": ["*rm -rf*"],
                    }
                ],
            }
        )
        events = [
            Event.from_dict(
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "actor": "agent",
                    "tool_name": "SHELL",
                    "action": "Execute",
                    "resource": "/workspace",
                    "metadata": {"command": "rm -rf ."},
                }
            )
        ]

        result = evaluate_trace(policy, events)

        self.assertEqual(result.summary.denied, 1)
        self.assertEqual(result.findings[0].rule_id, "deny-shell")

    def test_trims_whitespace_around_normalized_match_fields(self):
        policy = Policy.from_dict(
            {
                "name": "trimmed-policy",
                "version": "1.0.0",
                "default_action": " allow ",
                "rules": [
                    {
                        "id": "deny-shell",
                        "description": "deny destructive commands",
                        "effect": " deny ",
                        "severity": " high ",
                        "actions": ["execute"],
                        "tools": ["shell"],
                        "command_patterns": ["*rm -rf*"],
                    }
                ],
            }
        )
        events = [
            Event.from_dict(
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "actor": "agent",
                    "tool_name": " SHELL ",
                    "action": " Execute ",
                    "resource": "/workspace",
                    "metadata": {"command": "rm -rf ."},
                }
            )
        ]

        issues = validate_policy(policy)
        result = evaluate_trace(policy, events)

        self.assertFalse(issues)
        self.assertEqual(result.summary.denied, 1)
        self.assertEqual(result.summary.review, 0)
        self.assertEqual(result.findings[0].decision, "deny")
        self.assertEqual(result.findings[0].severity, "high")

    def test_summary_uses_most_restrictive_decision_per_event(self):
        policy = Policy.from_dict(
            {
                "name": "overlap-policy",
                "version": "1.0.0",
                "default_action": "allow",
                "rules": [
                    {
                        "id": "review-execute",
                        "description": "review all execute actions",
                        "effect": "review",
                        "actions": ["execute"],
                    },
                    {
                        "id": "deny-shell",
                        "description": "deny shell execution",
                        "effect": "deny",
                        "tools": ["shell"],
                    },
                ],
            }
        )
        events = [
            Event.from_dict(
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "actor": "agent",
                    "tool_name": "shell",
                    "action": "execute",
                    "resource": "/workspace",
                    "metadata": {},
                }
            )
        ]

        result = evaluate_trace(policy, events)

        self.assertEqual(result.summary.total_events, 1)
        self.assertEqual(result.summary.review, 0)
        self.assertEqual(result.summary.denied, 1)
        self.assertEqual(
            [(finding.rule_id, finding.decision) for finding in result.findings],
            [("review-execute", "review"), ("deny-shell", "deny")],
        )

    def test_matches_domains_case_insensitively(self):
        policy = Policy.from_dict(
            {
                "name": "domain-policy",
                "version": "1.0.0",
                "default_action": "allow",
                "rules": [
                    {
                        "id": "review-egress",
                        "description": "review github api access",
                        "effect": "review",
                        "actions": ["network"],
                        "domains": ["API.GITHUB.COM"],
                    }
                ],
            }
        )
        events = [
            Event.from_dict(
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "actor": "agent",
                    "tool_name": "net",
                    "action": "network",
                    "resource": "https://api.github.com",
                    "metadata": {"domain": "api.github.com"},
                }
            )
        ]

        result = evaluate_trace(policy, events)

        self.assertEqual(result.summary.review, 1)
        self.assertEqual(result.findings[0].rule_id, "review-egress")

    def test_matches_domains_from_resource_url_when_metadata_domain_is_missing(self):
        policy = Policy.from_dict(
            {
                "name": "domain-policy",
                "version": "1.0.0",
                "default_action": "allow",
                "rules": [
                    {
                        "id": "review-egress",
                        "description": "review github api access",
                        "effect": "review",
                        "actions": ["network"],
                        "domains": ["api.github.com"],
                    }
                ],
            }
        )
        events = [
            Event.from_dict(
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "actor": "agent",
                    "tool_name": "net",
                    "action": "network",
                    "resource": "https://API.GitHub.com/repos/example/project",
                    "metadata": {},
                }
            )
        ]

        result = evaluate_trace(policy, events)

        self.assertEqual(result.summary.review, 1)
        self.assertEqual(result.findings[0].rule_id, "review-egress")

    def test_matches_domains_when_metadata_domain_contains_url(self):
        policy = Policy.from_dict(
            {
                "name": "domain-policy",
                "version": "1.0.0",
                "default_action": "allow",
                "rules": [
                    {
                        "id": "review-egress",
                        "description": "review github api access",
                        "effect": "review",
                        "actions": ["network"],
                        "domains": ["api.github.com"],
                    }
                ],
            }
        )
        events = [
            Event.from_dict(
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "actor": "agent",
                    "tool_name": "net",
                    "action": "network",
                    "resource": "https://example.com",
                    "metadata": {"domain": "https://API.GitHub.com/repos/example/project"},
                }
            )
        ]

        result = evaluate_trace(policy, events)

        self.assertEqual(result.summary.review, 1)
        self.assertEqual(result.findings[0].rule_id, "review-egress")

    def test_matches_domains_when_metadata_domain_contains_port(self):
        policy = Policy.from_dict(
            {
                "name": "domain-policy",
                "version": "1.0.0",
                "default_action": "allow",
                "rules": [
                    {
                        "id": "review-egress",
                        "description": "review github api access",
                        "effect": "review",
                        "actions": ["network"],
                        "domains": ["api.github.com"],
                    }
                ],
            }
        )
        events = [
            Event.from_dict(
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "actor": "agent",
                    "tool_name": "net",
                    "action": "network",
                    "resource": "https://example.com",
                    "metadata": {"domain": "API.GitHub.com:443"},
                }
            )
        ]

        result = evaluate_trace(policy, events)

        self.assertEqual(result.summary.review, 1)
        self.assertEqual(result.findings[0].rule_id, "review-egress")

    def test_matches_domains_when_policy_domain_contains_url_and_port(self):
        policy = Policy.from_dict(
            {
                "name": "domain-policy",
                "version": "1.0.0",
                "default_action": "allow",
                "rules": [
                    {
                        "id": "review-egress",
                        "description": "review github api access",
                        "effect": "review",
                        "actions": ["network"],
                        "domains": ["https://API.GitHub.com:443/repos/example/project"],
                    }
                ],
            }
        )
        events = [
            Event.from_dict(
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "actor": "agent",
                    "tool_name": "net",
                    "action": "network",
                    "resource": "https://api.github.com/repos/example/project",
                    "metadata": {},
                }
            )
        ]

        result = evaluate_trace(policy, events)

        self.assertEqual(result.summary.review, 1)
        self.assertEqual(result.findings[0].rule_id, "review-egress")

    def test_matches_domains_for_raw_ipv6_literals(self):
        policy = Policy.from_dict(
            {
                "name": "ipv6-domain-policy",
                "version": "1.0.0",
                "default_action": "allow",
                "rules": [
                    {
                        "id": "review-ipv6-egress",
                        "description": "review raw ipv6 egress",
                        "effect": "review",
                        "actions": ["network"],
                        "domains": ["2001:4860:4860::8888"],
                    }
                ],
            }
        )
        events = [
            Event.from_dict(
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "actor": "agent",
                    "tool_name": "net",
                    "action": "network",
                    "resource": "2001:4860:4860::8888",
                    "metadata": {},
                }
            )
        ]

        result = evaluate_trace(policy, events)

        self.assertEqual(result.summary.review, 1)
        self.assertEqual(result.findings[0].rule_id, "review-ipv6-egress")

    def test_matches_domains_for_bracketed_ipv6_urls(self):
        policy = Policy.from_dict(
            {
                "name": "ipv6-url-policy",
                "version": "1.0.0",
                "default_action": "allow",
                "rules": [
                    {
                        "id": "review-ipv6-egress",
                        "description": "review ipv6 url egress",
                        "effect": "review",
                        "actions": ["network"],
                        "domains": ["http://[2001:4860:4860::8888]:443/path"],
                    }
                ],
            }
        )
        events = [
            Event.from_dict(
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "actor": "agent",
                    "tool_name": "net",
                    "action": "network",
                    "resource": "http://[2001:4860:4860::8888]:443/path",
                    "metadata": {},
                }
            )
        ]

        self.assertFalse(validate_policy(policy))

        result = evaluate_trace(policy, events)

        self.assertEqual(result.summary.review, 1)
        self.assertEqual(result.findings[0].rule_id, "review-ipv6-egress")

    def test_network_url_without_metadata_domain_still_contributes_egress_risk(self):
        events = [
            Event.from_dict(
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "actor": "agent",
                    "tool_name": "net",
                    "action": "network",
                    "resource": "https://example.com/api",
                    "metadata": {},
                }
            )
        ]

        result = evaluate_trace(self.policy, events)

        self.assertEqual(result.summary.highest_risk_score, 75)

    def test_bracketed_public_ipv6_url_without_metadata_domain_still_contributes_egress_risk(self):
        events = [
            Event.from_dict(
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "actor": "agent",
                    "tool_name": "net",
                    "action": "network",
                    "resource": "http://[2001:4860:4860::8888]:443/dns-query",
                    "metadata": {},
                }
            )
        ]

        result = evaluate_trace(self.policy, events)

        self.assertEqual(result.summary.highest_risk_score, 75)

    def test_raw_public_ipv6_without_metadata_domain_still_contributes_egress_risk(self):
        events = [
            Event.from_dict(
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "actor": "agent",
                    "tool_name": "net",
                    "action": "network",
                    "resource": "2001:4860:4860::8888",
                    "metadata": {},
                }
            )
        ]

        result = evaluate_trace(self.policy, events)

        self.assertEqual(result.summary.highest_risk_score, 75)

    def test_non_network_resource_does_not_contribute_egress_risk(self):
        events = [
            Event.from_dict(
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "actor": "agent",
                    "tool_name": "fs",
                    "action": "read",
                    "resource": "docs/readme.md",
                    "metadata": {},
                }
            )
        ]

        result = evaluate_trace(self.policy, events)

        self.assertEqual(result.summary.highest_risk_score, 15)

    def test_dotted_file_path_does_not_receive_external_egress_risk(self):
        events = [
            Event.from_dict(
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "actor": "agent",
                    "tool_name": "fs",
                    "action": "write",
                    "resource": "release.v1/notes.txt",
                    "metadata": {},
                }
            )
        ]

        result = evaluate_trace(self.policy, events)

        self.assertEqual(result.summary.highest_risk_score, 45)

    def test_localhost_network_does_not_receive_external_egress_risk(self):
        events = [
            Event.from_dict(
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "actor": "agent",
                    "tool_name": "net",
                    "action": "network",
                    "resource": "http://localhost:3000/health",
                    "metadata": {},
                }
            )
        ]

        result = evaluate_trace(self.policy, events)

        self.assertEqual(result.summary.highest_risk_score, 35)

    def test_private_network_ip_does_not_receive_external_egress_risk(self):
        events = [
            Event.from_dict(
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "actor": "agent",
                    "tool_name": "net",
                    "action": "network",
                    "resource": "http://10.0.0.8:8080/health",
                    "metadata": {},
                }
            )
        ]

        result = evaluate_trace(self.policy, events)

        self.assertEqual(result.summary.highest_risk_score, 35)

    def test_validate_policy_rejects_domain_entries_without_host_or_ip(self):
        policy = Policy.from_dict(
            {
                "name": "invalid-domain-policy",
                "version": "1.0.0",
                "default_action": "allow",
                "rules": [
                    {
                        "id": "review-egress",
                        "description": "review outbound traffic",
                        "effect": "review",
                        "domains": ["https://", "//", "   "],
                    }
                ],
            }
        )

        issues = validate_policy(policy)

        self.assertEqual(
            [(issue.path, issue.message) for issue in issues],
            [
                ("rules[0].domains[2]", "domains entries must not be empty."),
                (
                    "rules[0].domains[0]",
                    "domains entries must include a hostname or IP address.",
                ),
                (
                    "rules[0].domains[1]",
                    "domains entries must include a hostname or IP address.",
                ),
            ],
        )

    def test_validate_policy_rejects_domain_entries_with_invalid_hostname_characters(self):
        policy = Policy.from_dict(
            {
                "name": "invalid-hostname-policy",
                "version": "1.0.0",
                "default_action": "allow",
                "rules": [
                    {
                        "id": "review-egress",
                        "description": "review outbound traffic",
                        "effect": "review",
                        "domains": ["bad host", "exa_mple.com", "good-host.local"],
                    }
                ],
            }
        )

        issues = validate_policy(policy)

        self.assertEqual(
            [(issue.path, issue.message) for issue in issues],
            [
                (
                    "rules[0].domains[0]",
                    "domains entries must include a hostname or IP address.",
                ),
                (
                    "rules[0].domains[1]",
                    "domains entries must include a hostname or IP address.",
                ),
            ],
        )

    def test_raw_private_ipv6_does_not_receive_external_egress_risk(self):
        events = [
            Event.from_dict(
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "actor": "agent",
                    "tool_name": "net",
                    "action": "network",
                    "resource": "fd00::1234",
                    "metadata": {},
                }
            )
        ]

        result = evaluate_trace(self.policy, events)

        self.assertEqual(result.summary.highest_risk_score, 35)

    def test_matches_env_var_patterns_when_metadata_uses_single_string(self):
        policy = Policy.from_dict(
            {
                "name": "env-var-policy",
                "version": "1.0.0",
                "default_action": "allow",
                "rules": [
                    {
                        "id": "review-secrets",
                        "description": "review secret env var usage",
                        "effect": "review",
                        "env_var_patterns": ["OPENAI_*"],
                    }
                ],
            }
        )
        events = [
            Event.from_dict(
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "actor": "agent",
                    "tool_name": "shell",
                    "action": "execute",
                    "resource": "/workspace",
                    "metadata": {"env_vars": "OPENAI_API_KEY"},
                }
            )
        ]

        result = evaluate_trace(policy, events)

        self.assertEqual(result.summary.review, 1)
        self.assertEqual(result.findings[0].rule_id, "review-secrets")

    def test_matches_env_var_patterns_when_metadata_uses_tuple(self):
        policy = Policy.from_dict(
            {
                "name": "env-var-policy",
                "version": "1.0.0",
                "default_action": "allow",
                "rules": [
                    {
                        "id": "review-secrets",
                        "description": "review secret env var usage",
                        "effect": "review",
                        "env_var_patterns": ["AWS_*"],
                    }
                ],
            }
        )
        events = [
            Event.from_dict(
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "actor": "agent",
                    "tool_name": "shell",
                    "action": "execute",
                    "resource": "/workspace",
                    "metadata": {"env_vars": ("PATH", "AWS_SECRET_ACCESS_KEY")},
                }
            )
        ]

        result = evaluate_trace(policy, events)

        self.assertEqual(result.summary.review, 1)
        self.assertEqual(result.findings[0].rule_id, "review-secrets")

    def test_matches_env_var_patterns_when_metadata_uses_object_keys(self):
        policy = Policy.from_dict(
            {
                "name": "env-var-policy",
                "version": "1.0.0",
                "default_action": "allow",
                "rules": [
                    {
                        "id": "review-secrets",
                        "description": "review secret env var usage",
                        "effect": "review",
                        "env_var_patterns": ["OPENAI_*"],
                    }
                ],
            }
        )
        events = [
            Event.from_dict(
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "actor": "agent",
                    "tool_name": "shell",
                    "action": "execute",
                    "resource": "/workspace",
                    "metadata": {"env_vars": {"PATH": "/usr/bin", "OPENAI_API_KEY": "set"}},
                }
            )
        ]

        result = evaluate_trace(policy, events)

        self.assertEqual(result.summary.review, 1)
        self.assertEqual(result.findings[0].rule_id, "review-secrets")

    def test_matches_string_risk_threshold_without_crashing(self):
        policy = Policy.from_dict(
            {
                "name": "risk-threshold-policy",
                "version": "1.0.0",
                "default_action": "allow",
                "rules": [
                    {
                        "id": "review-high-risk",
                        "description": "review risky execution",
                        "effect": "review",
                        "risk_threshold": "90",
                    }
                ],
            }
        )
        events = [
            Event.from_dict(
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "actor": "agent",
                    "tool_name": "shell",
                    "action": "execute",
                    "resource": "/workspace",
                    "metadata": {"command": "sudo rm -rf /tmp/build-cache"},
                }
            )
        ]

        result = evaluate_trace(policy, events)

        self.assertEqual(result.summary.review, 1)
        self.assertEqual(result.findings[0].rule_id, "review-high-risk")

    def test_invalid_string_risk_threshold_does_not_crash_direct_evaluation(self):
        policy = Policy.from_dict(
            {
                "name": "bad-policy",
                "version": "1.0.0",
                "default_action": "allow",
                "rules": [
                    {
                        "id": "bad-threshold",
                        "description": "broken threshold",
                        "effect": "review",
                        "risk_threshold": "not-a-number",
                    }
                ],
            }
        )
        events = [
            Event.from_dict(
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "actor": "agent",
                    "tool_name": "shell",
                    "action": "execute",
                    "resource": "/workspace",
                }
            )
        ]

        result = evaluate_trace(policy, events)

        self.assertEqual(result.summary.allowed, 1)
        self.assertEqual(result.findings[0].decision, "allow")
        self.assertIsNone(result.findings[0].rule_id)

    def test_event_with_non_mapping_metadata_does_not_crash(self):
        events = [
            Event.from_dict(
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "actor": "agent",
                    "tool_name": "net",
                    "action": "network",
                    "resource": "https://example.com/api",
                    "metadata": "unexpected",
                }
            )
        ]

        result = evaluate_trace(self.policy, events)

        self.assertEqual(result.summary.review, 1)
        self.assertEqual(result.findings[0].event.metadata, {})

    def test_event_payload_items_supports_wrapped_event_lists(self):
        payload = {
            "events": [
                {
                    "timestamp": "2026-01-01T00:00:00Z",
                    "actor": "agent",
                    "tool_name": "shell",
                    "action": "execute",
                    "resource": "/workspace",
                }
            ]
        }

        items = _event_payload_items(payload)

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["tool_name"], "shell")

    def test_event_payload_items_supports_wrapped_single_event_objects(self):
        payload = {
            "events": {
                "timestamp": "2026-01-01T00:00:00Z",
                "actor": "agent",
                "tool_name": "shell",
                "action": "execute",
                "resource": "/workspace",
            }
        }

        items = _event_payload_items(payload)

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["action"], "execute")

    def test_load_events_rejects_scalar_top_level_trace_payload(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            trace_path = Path(tmp_dir) / "trace.json"
            trace_path.write_text(json.dumps("not-an-event-list"), encoding="utf-8")

            with self.assertRaises(InputLoadError) as ctx:
                load_events(str(trace_path))

        self.assertIn("Trace file must contain an event object", ctx.exception.message)

    def test_load_events_rejects_scalar_wrapped_events_payload(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            trace_path = Path(tmp_dir) / "trace.json"
            trace_path.write_text(json.dumps({"events": "not-an-event-list"}), encoding="utf-8")

            with self.assertRaises(InputLoadError) as ctx:
                load_events(str(trace_path))

        self.assertIn("Trace file 'events' must contain an event object", ctx.exception.message)

    def test_load_events_rejects_scalar_items_inside_event_lists(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            trace_path = Path(tmp_dir) / "trace.json"
            trace_path.write_text(json.dumps([{"tool_name": "shell"}, "not-an-event"]), encoding="utf-8")

            with self.assertRaises(InputLoadError) as ctx:
                load_events(str(trace_path))

        self.assertEqual(ctx.exception.kind, "trace")
        self.assertIn("Trace event at index 1 must be an object.", ctx.exception.message)

    def test_load_policy_rejects_scalar_top_level_payload(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            policy_path = Path(tmp_dir) / "policy.json"
            policy_path.write_text(json.dumps(["not-a-policy-object"]), encoding="utf-8")

            with self.assertRaises(InputLoadError) as ctx:
                load_policy(str(policy_path))

        self.assertEqual(ctx.exception.kind, "policy")
        self.assertIn("Policy file must contain a JSON object.", ctx.exception.message)

    def test_load_policy_rejects_non_array_rules_field(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            policy_path = Path(tmp_dir) / "policy.json"
            policy_path.write_text(
                json.dumps(
                    {
                        "name": "bad-policy",
                        "version": "1.0.0",
                        "default_action": "allow",
                        "rules": {"id": "rule-1"},
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaises(InputLoadError) as ctx:
                load_policy(str(policy_path))

        self.assertEqual(ctx.exception.kind, "policy")
        self.assertIn("Policy file 'rules' must contain an array of rule objects.", ctx.exception.message)

    def test_load_policy_rejects_non_object_rule_entries(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            policy_path = Path(tmp_dir) / "policy.json"
            policy_path.write_text(
                json.dumps(
                    {
                        "name": "bad-policy",
                        "version": "1.0.0",
                        "default_action": "allow",
                        "rules": [{"id": "rule-1", "description": "ok", "effect": "allow"}, "bad-rule"],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaises(InputLoadError) as ctx:
                load_policy(str(policy_path))

        self.assertEqual(ctx.exception.kind, "policy")
        self.assertIn("Policy rule at index 1 must be an object.", ctx.exception.message)

    def test_validation_rejects_duplicate_rule_ids(self):
        policy = Policy.from_dict(
            {
                "name": "bad-policy",
                "version": "1.0.0",
                "default_action": "review",
                "rules": [
                    {
                        "id": "duplicate",
                        "description": "first",
                        "effect": "allow",
                        "actions": ["read"],
                    },
                    {
                        "id": "duplicate",
                        "description": "second",
                        "effect": "deny",
                        "actions": ["write"],
                    },
                ],
            }
        )

        issues = validate_policy(policy)

        self.assertTrue(any("Duplicate rule id" in issue.message for issue in issues))

    def test_validation_warns_on_matchless_rule(self):
        policy = Policy.from_dict(
            {
                "name": "warn-policy",
                "version": "1.0.0",
                "default_action": "allow",
                "rules": [
                    {
                        "id": "empty-rule",
                        "description": "matches everything unintentionally",
                        "effect": "review",
                    }
                ],
            }
        )

        issues = validate_policy(policy)

        self.assertTrue(any(issue.severity == "warning" for issue in issues))

    def test_validation_reports_missing_rule_fields_instead_of_crashing(self):
        policy = Policy.from_dict(
            {
                "name": "bad-policy",
                "version": "1.0.0",
                "default_action": "allow",
                "rules": [{}],
            }
        )

        issues = validate_policy(policy)

        self.assertTrue(any(issue.path == "rules[0].id" for issue in issues))
        self.assertTrue(any(issue.path == "rules[0].description" for issue in issues))
        self.assertTrue(any(issue.path == "rules[0].effect" for issue in issues))

    def test_validation_reports_single_rule_object_instead_of_crashing(self):
        policy = Policy.from_dict(
            {
                "name": "bad-policy",
                "version": "1.0.0",
                "default_action": "allow",
                "rules": {
                    "id": "singleton-rule",
                },
            }
        )

        issues = validate_policy(policy)

        self.assertTrue(any(issue.path == "rules[0].description" for issue in issues))
        self.assertTrue(any(issue.path == "rules[0].effect" for issue in issues))

    def test_validation_rejects_blank_matcher_entries(self):
        policy = Policy.from_dict(
            {
                "name": "bad-policy",
                "version": "1.0.0",
                "default_action": "allow",
                "rules": [
                    {
                        "id": "blank-matchers",
                        "description": "contains blank matcher values",
                        "effect": "review",
                        "actions": ["read", " "],
                        "tools": ["shell", "\t"],
                        "resource_prefixes": ["docs/", ""],
                        "command_patterns": ["rm *", "   "],
                        "domains": ["api.github.com", " "],
                        "env_var_patterns": ["OPENAI_*", ""],
                    }
                ],
            }
        )

        issues = validate_policy(policy)

        self.assertEqual(
            [issue.path for issue in issues],
            [
                "rules[0].actions[1]",
                "rules[0].tools[1]",
                "rules[0].resource_prefixes[1]",
                "rules[0].command_patterns[1]",
                "rules[0].domains[1]",
                "rules[0].env_var_patterns[1]",
            ],
        )


if __name__ == "__main__":
    unittest.main()
