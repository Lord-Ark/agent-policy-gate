import unittest

from agent_policy_gate.engine import _event_payload_items, evaluate_trace, validate_policy
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


if __name__ == "__main__":
    unittest.main()
