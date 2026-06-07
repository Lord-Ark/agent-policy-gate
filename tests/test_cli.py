import tempfile
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()

