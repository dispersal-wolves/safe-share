"""Serve a file or directory temporarily with token access and limits."""

from __future__ import annotations

import argparse
import hmac
import json
import mimetypes
import secrets
import ssl
import sys
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit


class AccessPolicy:
    def __init__(self, token: str, expires_seconds: int, max_downloads: int):
        self.token = token
        self.deadline = time.monotonic() + expires_seconds
        self.remaining = max_downloads
        self._lock = threading.Lock()

    def valid_token(self, candidate: str) -> bool:
        return hmac.compare_digest(self.token.encode(), candidate.encode())

    def reserve_download(self) -> tuple[bool, str]:
        with self._lock:
            if time.monotonic() >= self.deadline:
                return False, "share expired"
            if self.remaining == 0:
                return False, "download limit reached"
            if self.remaining > 0:
                self.remaining -= 1
            return True, "ok"

    def available(self) -> tuple[bool, str]:
        with self._lock:
            if time.monotonic() >= self.deadline:
                return False, "share expired"
            if self.remaining == 0:
                return False, "download limit reached"
            return True, "ok"


def safe_resolve(root: Path, requested: str) -> Path | None:
    root = root.resolve()
    candidate = (root / unquote(requested).lstrip("/")).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate


def make_handler(root: Path, policy: AccessPolicy):
    class ShareHandler(BaseHTTPRequestHandler):
        server_version = "DispersalSafeShare/0.1"

        def log_message(self, format: str, *args: object) -> None:
            sanitized_path = self.path.replace(policy.token, "[TOKEN]")
            sys.stderr.write(f"{self.client_address[0]} {self.command} {sanitized_path}\n")

        def send_error_text(self, status: HTTPStatus, message: str) -> None:
            body = (message + "\n").encode()
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_HEAD(self) -> None:
            self.handle_request(send_body=False)

        def do_GET(self) -> None:
            self.handle_request(send_body=True)

        def handle_request(self, send_body: bool) -> None:
            components = urlsplit(self.path).path.lstrip("/").split("/", 1)
            if not components or not policy.valid_token(components[0]):
                self.send_error_text(HTTPStatus.NOT_FOUND, "not found")
                return
            requested = components[1] if len(components) == 2 else ""
            base = root.parent if root.is_file() else root
            target = root if root.is_file() and requested in ("", root.name) else safe_resolve(base, requested)
            if target is None or not target.exists():
                self.send_error_text(HTTPStatus.NOT_FOUND, "not found")
                return
            if target.is_dir():
                entries = [{"name": child.name, "type": "directory" if child.is_dir() else "file"} for child in sorted(target.iterdir(), key=lambda item: item.name.lower())]
                body = json.dumps({"entries": entries}, indent=2).encode()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                if send_body:
                    self.wfile.write(body)
                return
            permitted, reason = policy.reserve_download() if send_body else policy.available()
            if not permitted:
                self.send_error_text(HTTPStatus.GONE, reason)
                return
            size = target.stat().st_size
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", mimetypes.guess_type(target.name)[0] or "application/octet-stream")
            self.send_header("Content-Length", str(size))
            self.send_header("Content-Disposition", f"attachment; filename*=UTF-8''{quote(target.name)}")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'")
            self.end_headers()
            if send_body:
                with target.open("rb") as handle:
                    while chunk := handle.read(1024 * 1024):
                        self.wfile.write(chunk)

    return ShareHandler


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--expires", type=int, default=30, metavar="MINUTES")
    parser.add_argument("--max-downloads", type=int, default=1, help="Use -1 for unlimited until expiry")
    parser.add_argument("--token", help="Supply a token instead of generating one")
    parser.add_argument("--cert", type=Path)
    parser.add_argument("--key", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    path = args.path.resolve()
    if not path.exists():
        print(f"Path does not exist: {path}", file=sys.stderr)
        return 2
    if not 1 <= args.port <= 65535 or args.expires <= 0 or args.max_downloads == 0 or args.max_downloads < -1:
        print("Invalid port, expiry, or download limit", file=sys.stderr)
        return 2
    if bool(args.cert) != bool(args.key):
        print("--cert and --key must be supplied together", file=sys.stderr)
        return 2
    if args.host not in ("127.0.0.1", "::1", "localhost") and not args.cert:
        print("Refusing non-loopback exposure without --cert and --key", file=sys.stderr)
        return 2
    token = args.token or secrets.token_urlsafe(24)
    if len(token) < 16:
        print("Token must be at least 16 characters", file=sys.stderr)
        return 2
    policy = AccessPolicy(token, args.expires * 60, args.max_downloads)
    server = ThreadingHTTPServer((args.host, args.port), make_handler(path, policy))
    scheme = "http"
    if args.cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(args.cert, args.key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        scheme = "https"
    suffix = quote(path.name) if path.is_file() else ""
    print(f"Share URL: {scheme}://{args.host}:{server.server_port}/{token}/{suffix}")
    print(f"Expires in {args.expires} minute(s); press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
