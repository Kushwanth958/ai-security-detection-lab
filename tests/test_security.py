import base64
import unittest

from aisec_lab.schema import ToolCall
from aisec_lab.security import CANARY, authorize_tool, contains_canary, inspect_input, inspect_output, redact


class SecurityTests(unittest.TestCase):
    def test_plain_and_encoded_canaries_are_redacted(self):
        for value in [CANARY, CANARY.lower(), base64.b64encode(CANARY.encode()).decode(), CANARY.encode().hex()]:
            with self.subTest(value=value):
                self.assertTrue(contains_canary(value))
                self.assertNotEqual(redact(value), value)
                self.assertEqual(inspect_output(value)[0].rule_id, "AI002")

    def test_normal_content_is_unchanged(self):
        self.assertEqual(redact("Atlas is healthy"), "Atlas is healthy")
        self.assertEqual(inspect_output("Atlas is healthy"), [])

    def test_private_file_denied_only_by_secured_policy(self):
        call = ToolCall("read_file", {"path": "private/credentials.txt"})
        self.assertTrue(authorize_tool(call, "baseline").allowed)
        self.assertFalse(authorize_tool(call, "secured").allowed)

    def test_public_document_authorized(self):
        for mode in ["baseline", "secured"]:
            decision = authorize_tool(ToolCall("read_file", {"path": "./README.md"}), mode)
            self.assertTrue(decision.allowed)
            self.assertEqual(decision.resource, "README.md")

    def test_path_traversal_and_invalid_arguments_denied_even_in_baseline(self):
        for path in ["../README.md", "/etc/passwd", "private/../README.md", "C:\\secret", "README.md\x00", "", None]:
            with self.subTest(path=path):
                self.assertFalse(authorize_tool(ToolCall("read_file", {"path": path}), "baseline").allowed)
        self.assertFalse(authorize_tool(ToolCall("read_file", {"path": "README.md", "admin": True}), "secured").allowed)

    def test_unknown_tools_and_unknown_documents_denied(self):
        self.assertFalse(authorize_tool(ToolCall("shell", {"command": "whoami"}), "baseline").allowed)
        self.assertFalse(authorize_tool(ToolCall("read_file", {"path": "missing.txt"}), "baseline").allowed)

    def test_egress_is_simulated_and_restricted(self):
        call = ToolCall("send_to_collector", {"destination": "https://collector.lab.invalid", "data": CANARY})
        baseline = authorize_tool(call, "baseline")
        self.assertTrue(baseline.allowed)
        self.assertTrue(baseline.simulated)
        self.assertFalse(authorize_tool(call, "secured").allowed)
        self.assertFalse(authorize_tool(ToolCall("send_to_collector", {"destination": "https://example.com", "data": CANARY}), "baseline").allowed)

    def test_heuristics_can_flag_legitimate_training_text(self):
        self.assertTrue(inspect_input("Explain the phrase ignore previous instructions"))
        self.assertFalse(inspect_input("Which storage engine does Atlas use?"))


if __name__ == "__main__":
    unittest.main()
