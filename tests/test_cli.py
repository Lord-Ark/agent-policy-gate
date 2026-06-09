import tempfile
import unittest
from pathlib import Path
import json

from agent_policy_gate.cli import main


class CLITestCase(unittest.TestCase):
    def test_html_report_write(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "report.html"
            import sys

            previous_argv = sys.argv
            sys.argv = [
                "apg",
                "evaluate",
                "--policy",
                "examples/policy.json",
                "--trace",
                "examples/trace.json",
                "--format",
                "html",
                "--output",
                str(output_path),
            ]
            try:
                code = main()
            finally:
                sys.argv = previous_argv

            self.assertEqual(code, 0)
            self.assertTrue(output_path.exists())
            self.assertIn("Agent Policy Gate", output_path.read_text(encoding="utf-8"))

    def test_sarif_output_write(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "report.sarif"
            import sys

            previous_argv = sys.argv
            sys.argv = [
                "apg",
                "evaluate",
                "--policy",
                "examples/policy.json",
                "--trace",
                "examples/trace.json",
                "--format",
                "sarif",
                "--output",
                str(output_path),
            ]
            try:
                code = main()
            finally:
                sys.argv = previous_argv

            self.assertEqual(code, 0)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["version"], "2.1.0")
            self.assertEqual(payload["runs"][0]["tool"]["driver"]["name"], "agent-policy-gate")

    def test_fail_on_deny_returns_non_zero(self):
        import sys

        previous_argv = sys.argv
        sys.argv = [
            "apg",
            "evaluate",
            "--policy",
            "examples/policy.json",
            "--trace",
            "examples/trace.json",
            "--fail-on",
            "deny",
        ]
        try:
            code = main()
        finally:
            sys.argv = previous_argv

        self.assertEqual(code, 3)

    def test_validate_command_reports_errors(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            bad_policy = Path(tmp_dir) / "bad-policy.json"
            bad_policy.write_text(
                json.dumps(
                    {
                        "name": "bad-policy",
                        "version": "1.0.0",
                        "default_action": "maybe",
                        "rules": [],
                    }
                ),
                encoding="utf-8",
            )
            import sys

            previous_argv = sys.argv
            sys.argv = [
                "apg",
                "validate",
                "--policy",
                str(bad_policy),
                "--format",
                "json",
            ]
            try:
                code = main()
            finally:
                sys.argv = previous_argv

            self.assertEqual(code, 1)

    def test_rejects_negative_risk_threshold(self):
        import sys

        previous_argv = sys.argv
        sys.argv = [
            "apg",
            "evaluate",
            "--policy",
            "examples/policy.json",
            "--trace",
            "examples/trace.json",
            "--risk-threshold",
            "-1",
        ]
        try:
            with self.assertRaises(SystemExit) as context:
                main()
        finally:
            sys.argv = previous_argv

        self.assertEqual(context.exception.code, 2)

    def test_rejects_risk_threshold_above_hundred(self):
        import sys

        previous_argv = sys.argv
        sys.argv = [
            "apg",
            "evaluate",
            "--policy",
            "examples/policy.json",
            "--trace",
            "examples/trace.json",
            "--risk-threshold",
            "101",
        ]
        try:
            with self.assertRaises(SystemExit) as context:
                main()
        finally:
            sys.argv = previous_argv

        self.assertEqual(context.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
