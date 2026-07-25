"""Deterministic loopback lab target for Autopilot golden/integration tests.

Listens only on 127.0.0.1. Never requires internet. Fixture labels stay outside
this process in evaluator_labels.json.
"""

from __future__ import annotations

import json
import threading
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


FIXTURE_DIR = Path(__file__).resolve().parent


def load_lab_manifest() -> dict[str, Any]:
    return json.loads((FIXTURE_DIR / "lab_target.json").read_text(encoding="utf-8"))


class LabTargetHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def _send(self, status: int, payload: dict[str, Any], *, headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _record_request(self, path: str) -> None:
        lock = getattr(self.server, "_lab_request_lock", None)
        counts = getattr(self.server, "_lab_request_counts", None)
        if lock is None or not isinstance(counts, dict):
            return
        with lock:
            counts[path] = int(counts.get(path, 0)) + 1

    def _session_alias(self) -> str | None:
        cookie_header = self.headers.get("Cookie")
        if not cookie_header:
            return "account_a"
        cookie = SimpleCookie()
        cookie.load(cookie_header)
        morsel = cookie.get("session")
        if morsel is None:
            return "account_a"
        alias = morsel.value
        if alias in {"account_a", "account_b"}:
            return alias
        return None

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        self._record_request(path)
        if path == "/public/health":
            self._send(200, {"ok": True, "public": True})
            return
        if path == "/api/me/profile":
            self._send(200, {"alias": "account_self", "role": "owner"})
            return
        if path in {"/api/docs/1", "/api/docs/2"}:
            viewer = self._session_alias()
            if viewer is None:
                self._send(401, {"error": "session_invalid"})
                return
            owner = "account_a" if path.endswith("/1") else "account_b"
            self._send(
                200,
                {
                    "doc_id": path.rsplit("/", 1)[-1],
                    "owner": owner,
                    "viewer": viewer,
                    "cross_account": viewer != owner,
                },
            )
            return
        if path == "/api/admin/status":
            self._send(403, {"error": "middleware_protected"})
            return
        if path == "/api/sensitive":
            self._send(429, {"error": "waf_captcha"}, headers={"X-WAF": "captcha"})
            return
        if path == "/cdn/tracker.js":
            self._send(
                200,
                {
                    "vendor": "third_party_tracker",
                    "note": "third_party_noise",
                },
            )
            return
        if path == "/graphql":
            self._send(200, {"data": {"viewer": {"id": "self"}}})
            return
        self._send(404, {"error": "not_found", "path": path})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        self._record_request(path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            body = {}
        if path in {"/api/profile", "/api/legacy/profile"}:
            filtered = path == "/api/profile"
            accepted = {k: v for k, v in body.items() if k in {"display_name"}}
            if not filtered:
                accepted = dict(body)
            self._send(200, {"updated": accepted, "filtered": filtered})
            return
        if path in {"/api/orders/1/transition", "/api/legacy/orders/1/transition"}:
            guarded = path.startswith("/api/orders/")
            if guarded and body.get("to") not in {"paid", "cancelled"}:
                self._send(409, {"error": "workflow_guarded"})
                return
            self._send(200, {"to": body.get("to"), "guarded": guarded})
            return
        if path == "/graphql":
            self._send(200, {"data": {"node": None}, "errors": [{"message": "authz"}]})
            return
        self._send(404, {"error": "not_found"})


class LabTargetServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        if host not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("loopback_only")
        self._httpd = ThreadingHTTPServer((host, port), LabTargetHandler)
        self._httpd._lab_request_lock = threading.Lock()
        self._httpd._lab_request_counts = {}
        self.host, self.port = self._httpd.server_address[0], self._httpd.server_address[1]
        self.base_url = f"http://{self.host}:{self.port}"
        self._thread: threading.Thread | None = None

    def start(self) -> "LabTargetServer":
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def request_count(self, path: str) -> int:
        with self._httpd._lab_request_lock:
            return int(self._httpd._lab_request_counts.get(path, 0))


def start_lab_target(port: int = 0) -> LabTargetServer:
    return LabTargetServer(port=port).start()


__all__ = [
    "LabTargetServer",
    "load_lab_manifest",
    "start_lab_target",
]
