import unittest

from agent_policy_gate.engine import evaluate_trace
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


if __name__ == "__main__":
    unittest.main()

