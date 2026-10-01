"""Loopback-only, read-only dashboard with a small fixed route surface."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .reporting import summarize
from .store import Store

STATIC = Path(__file__).parent / "static"


def handler_factory(db: str, soc_report: str):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def respond(self, status: int, body: bytes, content_type: str):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; "
                             "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
            self.end_headers()
            self.wfile.write(body)

        def send_json(self, value, status=200):
            self.respond(status, json.dumps(value).encode(), "application/json; charset=utf-8")

        def do_GET(self):
            hostname = urlparse("http://" + self.headers.get("Host", "")).hostname
            if hostname not in {"localhost", "127.0.0.1"}:
                self.send_json({"error": "Invalid local host"}, 403)
                return
            parsed = urlparse(self.path)
            routes = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"),
                      "/style.css": ("style.css", "text/css")}
            if parsed.path in routes:
                filename, content_type = routes[parsed.path]
                self.respond(200, (STATIC / filename).read_bytes(), content_type + "; charset=utf-8")
                return
            if parsed.path == "/api/soc":
                try:
                    self.send_json(json.loads(Path(soc_report).read_text(encoding="utf-8")))
                except (OSError, ValueError):
                    self.send_json({"alerts": [], "warning": "Run the soc command to populate this view."})
                return
            if parsed.path not in {"/api/runs", "/api/run"}:
                self.send_json({"error": "Not found"}, 404)
                return
            if not Path(db).is_file():
                self.send_json([] if parsed.path == "/api/runs" else {"error": "Run the demo first"},
                               200 if parsed.path == "/api/runs" else 404)
                return
            with Store(db) as store:
                runs = store.runs()
                if parsed.path == "/api/runs":
                    self.send_json(runs)
                    return
                query = parse_qs(parsed.query)
                run_id = query.get("id", [""])[0]
                run = next((r for r in runs if r["id"] == run_id), None)
                if not run:
                    self.send_json({"error": "Unknown run"}, 404)
                    return
                records = store.records(run_id)
                self.send_json({"summary": summarize(run, records), "trials": records})

    return Handler


def serve(db: str, port: int, soc_report: str):
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535")
    server = ThreadingHTTPServer(("127.0.0.1", port), handler_factory(db, soc_report))
    print(f"Read-only dashboard: http://127.0.0.1:{port}", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
