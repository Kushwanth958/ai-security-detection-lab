import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from aisec_lab.cli import DATA
from aisec_lab.models import HTTPModel, ModelConfig, ModelError
from aisec_lab.runner import load_cases
from aisec_lab.security import CANARY


class ModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.requests = []
        cls.response = {}
        cls.status = 200

        class Endpoint(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                cls.requests.append({"path": self.path, "body": body, "auth": self.headers.get("Authorization")})
                self.send_response(cls.status)
                if cls.status == 302:
                    self.send_header("Location", "/other")
                self.end_headers()
                self.wfile.write(json.dumps(cls.response).encode())

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Endpoint)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.case = load_cases(DATA / "cases.json")[0][0]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        type(self).requests = []
        type(self).status = 200
        type(self).response = {"model": "test-resolved-model", "choices": [{"message": {"content": "Hello"}}],
                               "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7}}
        self.model = HTTPModel(ModelConfig("test", "test-model", f"http://127.0.0.1:{self.server.server_port}/v1", "TEST_LAB_KEY"))

    def test_request_contract_and_usage(self):
        with patch.dict(os.environ, {"TEST_LAB_KEY": "synthetic-key"}):
            value = self.model.complete([{"role": "user", "content": "hi"}], self.case, "secured")
        self.assertEqual(value.content, "Hello")
        self.assertEqual(value.resolved_model, "test-resolved-model")
        self.assertEqual(value.usage["total_tokens"], 7)
        self.assertEqual(self.requests[0]["path"], "/v1/chat/completions")
        self.assertEqual(self.requests[0]["auth"], "Bearer synthetic-key")
        self.assertEqual(self.requests[0]["body"]["model"], "test-model")
        self.assertEqual(len(self.requests[0]["body"]["tools"]), 2)

    def test_structured_tool_call_parsed(self):
        type(self).response["choices"][0]["message"] = {"content": None, "tool_calls": [
            {"id": "call-1", "function": {"name": "read_file", "arguments": '{"path":"README.md"}'}}]}
        value = self.model.complete([], self.case, "secured")
        self.assertEqual(value.calls[0].arguments, {"path": "README.md"})
        self.assertEqual(value.calls[0].id, "call-1")

    def test_http_error_body_not_exposed(self):
        type(self).status = 500
        type(self).response = {"private": CANARY, "key": "synthetic-key"}
        with self.assertRaises(ModelError) as context:
            self.model.complete([], self.case, "secured")
        self.assertNotIn(CANARY, str(context.exception))
        self.assertNotIn("synthetic-key", str(context.exception))
        self.assertIn("500", str(context.exception))

    def test_redirects_rejected_without_followup(self):
        type(self).status = 302
        with self.assertRaisesRegex(ModelError, "redirected"):
            self.model.complete([], self.case, "secured")
        self.assertEqual(len(self.requests), 1)

    def test_malformed_messages_are_safe_errors(self):
        for response in [[], {}, {"choices": []}, {"choices": [None]}, {"choices": ["bad"]}, {"choices": {}}, {"choices": [{"message": "invalid"}]},
                         {"choices": [{"message": {"content": ["not", "text"]}}]},
                         {"choices": [{"message": {"tool_calls": "bad"}}]},
                         {"choices": [{"message": {"tool_calls": [None]}}]}]:
            with self.subTest(response=response):
                type(self).response = response
                with self.assertRaises(ModelError):
                    self.model.complete([], self.case, "secured")

    def test_duplicate_calls_rejected(self):
        call = {"id": "same-id", "function": {"name": "read_file", "arguments": '{"path":"README.md"}'}}
        type(self).response["choices"][0]["message"] = {"tool_calls": [call, call]}
        with self.assertRaisesRegex(ModelError, "duplicate"):
            self.model.complete([], self.case, "secured")

    def test_truncated_generation_is_not_scored_as_attack_resistance(self):
        type(self).response["choices"][0]["finish_reason"] = "length"
        with self.assertRaisesRegex(ModelError, "truncated"):
            self.model.complete([], self.case, "secured")

    def test_remote_endpoint_requires_https_and_no_embedded_credentials(self):
        for url in ["http://example.com/v1", "file:///tmp/model", "https://user:pass@example.com/v1", "https://example.com/v1?key=x"]:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    ModelConfig("test", "model", url, "TEST_LAB_KEY")

    def test_missing_remote_key_fails_before_network(self):
        model = HTTPModel(ModelConfig("test", "model", "https://example.invalid/v1", "TEST_LAB_ABSENT_KEY"))
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ModelError, "Missing credential"):
                model.complete([], self.case, "secured")

    def test_placeholders_and_unbounded_settings_rejected(self):
        for kwargs in [{"model": "REPLACE_WITH_MODEL"}, {"max_tokens": 100000}, {"timeout_seconds": 999},
                       {"temperature": float("nan")}, {"api_key_env": "token-value!"}]:
            params = {"id": "test", "model": "model", "base_url": "http://localhost:1234/v1", "api_key_env": "TEST_KEY"}
            params.update(kwargs)
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    ModelConfig(**params)
