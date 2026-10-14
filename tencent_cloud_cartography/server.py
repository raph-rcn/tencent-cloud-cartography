"""Loopback-only HTTP UI; snapshots are read-only and no API accepts cloud commands."""

import json
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .drawio import export
from .paths import DIST
from .repository import SnapshotRepository, SourceError
from .topology import topology


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, repository, **kwargs):
        self.repository = repository
        super().__init__(*args, directory=str(DIST), **kwargs)

    def allowed(self):
        host = self.headers.get("Host", "")
        allowed = {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}
        origin = self.headers.get("Origin")
        return host in allowed and (not origin or origin in {"http://" + h for h in allowed})

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def respond(self, body, content_type="application/json", status=200):
        if content_type == "application/json":
            body = json.dumps(body, allow_nan=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self.allowed():
            return self.respond({"message": "Invalid local origin"}, status=403)
        path = urlparse(self.path)
        if path.path not in {
            "/api/health",
            "/api/accounts",
            "/api/coverage",
            "/api/topology",
            "/api/projects",
        }:
            if path.path.startswith("/api/"):
                return self.respond({"message": "Not found"}, status=404)
            return super().do_GET()
        try:
            if path.path == "/api/projects":
                return self.respond(
                    dict(
                        projects=self.repository.projects()
                        if hasattr(self.repository, "projects")
                        else []
                    )
                )
            selected = parse_qs(path.query, keep_blank_values=True).get("project", [None])[0]
            if selected is not None and not hasattr(self.repository, "read_project"):
                return self.respond(
                    {"message": "This viewer uses a fixed snapshot or database."}, status=400
                )
            data = (
                self.repository.read_project(selected)
                if hasattr(self.repository, "read_project")
                else self.repository.read_snapshot()
            )
        except SourceError as exc:
            return self.respond({"message": str(exc)}, status=503)
        if path.path == "/api/health":
            return self.respond(
                dict(
                    backend=self.repository.backend,
                    status=data["status"],
                    mode=data["mode"],
                    created_at=data["created_at"],
                    accounts=len(data["accounts"]),
                    resources=len(data["nodes"]),
                    unresolved=data["unresolved"],
                    regions=sorted({n["region"] for n in data["nodes"]}),
                    project=data.get("project"),
                )
            )
        if path.path == "/api/accounts":
            return self.respond(dict(accounts=data["accounts"]))
        if path.path == "/api/coverage":
            return self.respond(
                dict(
                    coverage=data["coverage"], status=data["status"], unresolved=data["unresolved"]
                )
            )
        if path.path == "/api/topology":
            query = {k: v[0] for k, v in parse_qs(path.query).items()}
            try:
                limit = min(10000, max(1, int(query.get("limit", "2500"))))
                view = query.get("view", "architecture")
                if view not in {"full", "architecture"}:
                    raise ValueError("Invalid view")
                return self.respond(
                    topology(
                        data,
                        query.get("account", ""),
                        query.get("region", ""),
                        view,
                        limit,
                        query.get("include_inventory", "0") == "1",
                    )
                )
            except ValueError:
                return self.respond({"message": "Invalid topology parameters"}, status=400)
        if path.path.startswith("/api/"):
            return self.respond({"message": "Not found"}, status=404)
        return super().do_GET()

    def do_POST(self):
        if not self.allowed():
            return self.respond({"message": "Invalid local origin"}, status=403)
        if self.path != "/api/export/drawio":
            return self.respond({"message": "Not found"}, status=404)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 8_000_000:
                return self.respond({"message": "Invalid body size"}, status=413)
            payload = json.loads(self.rfile.read(length))
            body = export(payload)
        except (ValueError, KeyError, TypeError, AttributeError):
            return self.respond({"message": "Invalid diagram"}, status=400)
        return self.respond(body, "application/xml")

    def log_message(self, fmt, *args):
        # Paths and request data are deliberately omitted from server logs.
        pass


def create_server(snapshot=None, port=8787, *, repository=None):
    repository = repository if repository is not None else SnapshotRepository(snapshot)
    server = ThreadingHTTPServer(("127.0.0.1", port), partial(Handler, repository=repository))
    server.daemon_threads = True
    return server


def serve(snapshot=None, port=8787, *, repository=None):
    if not (DIST / "index.html").exists():
        raise ValueError("Build the UI first: cd landscape/web && npm ci && npm run build")
    repository = repository if repository is not None else SnapshotRepository(snapshot)
    initial = repository.read_snapshot()
    with create_server(port=port, repository=repository) as server:
        print(
            f"Tencent Cloud Cartography: http://127.0.0.1:{server.server_port} ({repository.backend}, {initial['mode']}, {initial['status']})",
            flush=True,
        )
        server.serve_forever()
