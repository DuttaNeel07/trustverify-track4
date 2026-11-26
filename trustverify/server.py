"""Loopback-only organizer mock services. No deployment or external targets."""

import json
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import unquote

from cryptography.exceptions import InvalidSignature

from .authority import Authority, Denied, NODES
from .crypto import canonical

MAX_BODY = 64 * 1024


def serve(directory, operator, node, port):
    if node not in NODES or not (port == 0 or 1024 <= port <= 65535):
        raise ValueError("invalid node or port")
    authority = Authority(directory, operator)
    authority.recover()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def log_message(self, *_):
            pass

        def respond(self, status, value):
            body = canonical(value)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def handle_api(self):
            if self.command == "GET" and self.path == "/health":
                return {"node": node, "service": NODES[node], "status": "running"}
            if self.command == "GET" and self.path == "/challenge":
                return {"nonce": authority.challenge(node)}
            if self.command == "GET" and self.path.startswith("/directory/"):
                return authority.directory_entry(unquote(self.path[len("/directory/"):]))
            if self.command != "POST" or self.path != "/request":
                raise Denied("unknown endpoint", 404)
            if self.headers.get("Transfer-Encoding"):
                raise Denied("chunked HTTP requests are unsupported", 400)
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1:
                raise Denied("one Content-Length is required", 400)
            length = int(lengths[0])
            if not 0 < length <= MAX_BODY:
                raise Denied("request exceeds sandbox limit", 413)
            if self.headers.get_content_type() != "application/json":
                raise Denied("application/json required", 415)
            body = self.rfile.read(length)
            if len(body) != length:
                raise Denied("truncated request", 400)
            # Duplicate JSON names create interpretation differences between consumers.
            def unique_pairs(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError("duplicate JSON field")
                    result[key] = value
                return result
            request = json.loads(body, object_pairs_hook=unique_pairs,
                                 parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid number")))
            return authority.execute(node, request)

        def do_GET(self):
            try:
                self.respond(200, self.handle_api())
            except Denied as exc:
                self.respond(exc.status, {"error": str(exc)})
            except (ValueError, TypeError, KeyError, InvalidSignature, RecursionError):
                self.respond(400, {"error": "invalid request or integrity check"})
            except (sqlite3.Error, OSError):
                self.respond(503, {"error": "authority unavailable; access denied"})

        do_POST = do_GET

    with HTTPServer(("127.0.0.1", port), Handler) as server:
        print(json.dumps({"node": node, "url": f"http://127.0.0.1:{server.server_address[1]}"}), flush=True)
        server.serve_forever(poll_interval=0.1)
