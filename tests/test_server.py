import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from aisec_lab.server import handler_factory
from aisec_lab.store import Store


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.db = str(Path(self.directory.name) / "lab.db")
        with Store(self.db) as store:
            store.add_run("run", "now", {"warning": "fixture", "case_count": 0})
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler_factory(self.db, "missing-soc.json"))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.directory.cleanup()

    def test_dashboard_headers_and_assets(self):
        for path in ["/", "/app.js", "/style.css"]:
            with urllib.request.urlopen(self.url + path) as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
                self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])

    def test_run_api_and_unknown_run(self):
        with urllib.request.urlopen(self.url + "/api/run?id=run") as response:
            self.assertEqual(json.load(response)["trials"], [])
        with self.assertRaises(urllib.error.HTTPError) as context:
            urllib.request.urlopen(self.url + "/api/run?id=missing")
        self.assertEqual(context.exception.code, 404)

    def test_path_traversal_does_not_read_files(self):
        with self.assertRaises(urllib.error.HTTPError) as context:
            urllib.request.urlopen(self.url + "/../pyproject.toml")
        self.assertEqual(context.exception.code, 404)

    def test_untrusted_host_rejected(self):
        request = urllib.request.Request(self.url + "/api/runs", headers={"Host": "attacker.invalid"})
        with self.assertRaises(urllib.error.HTTPError) as context:
            urllib.request.urlopen(request)
        self.assertEqual(context.exception.code, 403)

    def test_soc_empty_state(self):
        with urllib.request.urlopen(self.url + "/api/soc") as response:
            self.assertEqual(json.load(response)["alerts"], [])
