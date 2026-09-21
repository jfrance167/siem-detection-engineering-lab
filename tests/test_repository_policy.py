import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class RepositoryPolicyTests(unittest.TestCase):
    def test_security_notice_is_present(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        policy = (ROOT / "SECURITY.md").read_text(encoding="utf-8")

        for text in (readme, policy):
            self.assertIn("educational", text.lower())
            self.assertIn("production", text.lower())
        self.assertIn("Report a vulnerability", policy)

    def test_workflow_uses_read_only_token_and_pinned_actions(self):
        workflow = (ROOT / ".github" / "workflows" / "tests.yml").read_text(
            encoding="utf-8"
        )
        self.assertRegex(workflow, r"(?m)^permissions:\s*\n\s+contents: read$")

        action_references = re.findall(
            r"(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)", workflow
        )
        self.assertGreaterEqual(len(action_references), 3)
        for reference in action_references:
            self.assertRegex(
                reference,
                r"^(?:[^@]+@[0-9a-f]{40}|docker://[^@]+@sha256:[0-9a-f]{64})$",
            )


if __name__ == "__main__":
    unittest.main()
