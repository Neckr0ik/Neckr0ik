"""Command line: ``llm-gateway serve | complete | usage | hash-key``."""

from __future__ import annotations

import argparse
import getpass
import json
import sys

from .config import GatewayConfig, hash_key
from .errors import GatewayError
from .gateway import Gateway
from .logging_utils import configure_logging, log_event
from .periods import validate_period
from .types import CompletionRequest


def _period(value: str) -> str:
    try:
        return validate_period(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _gateway(args) -> Gateway:
    cfg = GatewayConfig.from_env()
    if getattr(args, "provider", None):
        cfg.provider = args.provider
    if getattr(args, "db", None):
        cfg.db_path = args.db
    configure_logging(cfg.log_level)
    return Gateway(cfg)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="llm-gateway", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("serve", "complete", "usage"):
        sp = sub.add_parser(name)
        sp.add_argument("--provider", choices=["mock", "anthropic", "bedrock", "vertex"])
        sp.add_argument("--db", help="SQLite path or postgresql:// URL (default: $LLMGW_DB_PATH)")
        if name == "serve":
            sp.add_argument("--host", default="127.0.0.1")
            sp.add_argument("--port", type=int, default=8080)
            sp.add_argument("--max-concurrency", type=int, default=64,
                            help="requests handled at once; extra connections get 503 (default 64)")
            sp.add_argument("--request-timeout", type=float, default=30.0,
                            help="socket timeout in seconds for reading a request (default 30)")
        if name in ("complete", "usage"):
            sp.add_argument("--org", required=True)
        if name == "complete":
            sp.add_argument("--user", required=True)
            sp.add_argument("--feature", default="default")
            sp.add_argument("--prompt", required=True)
            sp.add_argument("--system")
            sp.add_argument("--max-tokens", type=int)
        if name == "usage":
            sp.add_argument("--period", type=_period, help="YYYY-MM (default: current UTC month)")
    sub.add_parser("hash-key", help="read a key from stdin/prompt and print its sha256 for LLMGW_API_KEY_SHA256")
    args = p.parse_args(argv)

    if args.cmd == "hash-key":
        key = sys.stdin.readline().strip() if not sys.stdin.isatty() else getpass.getpass("API key: ")
        print(hash_key(key))
        return 0

    try:
        gw = _gateway(args)
    except ValueError as exc:  # bad configuration: say so without a traceback
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    try:
        if args.cmd == "serve":
            from .server import serve

            if not gw.config.api_key_hashes:
                print("refusing to serve: no API keys configured (LLMGW_API_KEYS or LLMGW_API_KEY_SHA256)",
                      file=sys.stderr)
                return 2
            httpd = serve(gw, args.host, args.port, max_concurrency=args.max_concurrency,
                          request_timeout_s=args.request_timeout)
            log_event("server_started", host=args.host, port=httpd.server_address[1], provider=gw.provider.name,
                      orgs=len(gw.config.api_key_hashes))
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                httpd.server_close()
            return 0
        if args.cmd == "complete":
            req = CompletionRequest(org_id=args.org, user_id=args.user, feature=args.feature,
                                    messages=[{"role": "user", "content": args.prompt}], system=args.system,
                                    max_tokens=args.max_tokens)
            print(json.dumps(gw.complete(req).to_dict(), indent=2))
            return 0
        if args.cmd == "usage":
            print(json.dumps(gw.usage_report(args.org, args.period), indent=2))
            return 0
    except GatewayError as exc:
        print(json.dumps({"error": exc.to_dict()}, indent=2))
        return 1
    finally:
        gw.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
