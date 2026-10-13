"""Minimal stdlib HTTP server.

    POST /v1/complete   {"user": "...", "feature": "...", "messages": [...] | "prompt": "...",
                         "system": "...", "max_tokens": 512}
    GET  /v1/usage?period=YYYY-MM
    GET  /healthz

Auth: ``Authorization: Bearer <key>`` (or ``X-API-Key``). The key identifies the org;
the body cannot choose the org. Put TLS in front (reverse proxy) for anything non-local.
"""

from __future__ import annotations

import hmac
import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .config import hash_key
from .errors import AuthError, GatewayError, InvalidRequest, RateLimited
from .gateway import Gateway
from .logging_utils import log_event
from .types import CompletionRequest

MAX_BODY_BYTES = 1_000_000


def resolve_org(api_key_hashes: dict[str, set[str]], presented: str | None) -> str:
    if not presented:
        raise AuthError("missing API key")
    digest = hash_key(presented)
    match = None
    for org_id, digests in api_key_hashes.items():
        for d in digests:
            if hmac.compare_digest(d, digest):  # constant-time per comparison
                match = org_id
    if match is None:
        raise AuthError("invalid API key")
    return match


def make_handler(gateway: Gateway):
    class Handler(BaseHTTPRequestHandler):
        server_version = "llm-gateway"
        sys_version = ""

        def log_message(self, fmt, *args):  # route access logs through JSON logger, no query strings
            pass

        def _send(self, status: int, payload: dict, headers: dict | None = None) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _error(self, exc: GatewayError) -> None:
            headers = {}
            if isinstance(exc, RateLimited):
                headers["Retry-After"] = str(max(1, int(exc.retry_after + 0.999)))
            if isinstance(exc, AuthError):
                headers["WWW-Authenticate"] = "Bearer"
            self._send(exc.http_status, {"error": exc.to_dict()}, headers)

        def _org(self) -> str:
            auth = self.headers.get("Authorization", "")
            key = auth[7:].strip() if auth.lower().startswith("bearer ") else self.headers.get("X-API-Key")
            return resolve_org(gateway.config.api_key_hashes, key)

        def _guard(self, fn):
            path = urlparse(self.path).path
            try:
                fn()
            except GatewayError as exc:
                self._error(exc)
            except Exception as exc:  # never leak internals
                log_event("http_internal_error", logging.ERROR, path=path, exc_type=type(exc).__name__)
                self._send(500, {"error": {"type": "internal_error", "message": "internal error"}})

        def do_GET(self):
            url = urlparse(self.path)
            if url.path == "/healthz":
                return self._send(200, {"ok": True, "provider": gateway.provider.name})

            def run():
                if url.path != "/v1/usage":
                    return self._send(404, {"error": {"type": "not_found", "message": "not found"}})
                org = self._org()
                period = (parse_qs(url.query).get("period") or [None])[0]
                try:
                    report = gateway.usage_report(org, period)
                except ValueError as exc:
                    raise InvalidRequest(str(exc)) from None
                self._send(200, report)

            self._guard(run)

        def do_POST(self):
            def run():
                if urlparse(self.path).path != "/v1/complete":
                    return self._send(404, {"error": {"type": "not_found", "message": "not found"}})
                org = self._org()
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    raise InvalidRequest("bad Content-Length") from None
                if length <= 0 or length > MAX_BODY_BYTES:
                    raise InvalidRequest(f"body must be 1..{MAX_BODY_BYTES} bytes")
                try:
                    body = json.loads(self.rfile.read(length))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    raise InvalidRequest("body must be JSON") from None
                if not isinstance(body, dict):
                    raise InvalidRequest("body must be a JSON object")
                messages = body.get("messages")
                if messages is None and isinstance(body.get("prompt"), str):
                    messages = [{"role": "user", "content": body["prompt"]}]
                req = CompletionRequest(org_id=org, user_id=str(body.get("user", "")),
                                        feature=str(body.get("feature", "default")), messages=messages,
                                        system=body.get("system"), max_tokens=body.get("max_tokens"))
                self._send(200, gateway.complete(req).to_dict())

            self._guard(run)

    return Handler


def serve(gateway: Gateway, host: str = "127.0.0.1", port: int = 8080) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((host, port), make_handler(gateway))
    httpd.daemon_threads = True
    return httpd
