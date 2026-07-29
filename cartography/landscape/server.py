from __future__ import annotations

import argparse
import json
import os
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs
from urllib.parse import urlparse

from neo4j import GraphDatabase

from cartography.landscape.drawio import export_drawio
from cartography.landscape.topology import build_topology

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DIST = REPOSITORY_ROOT / "landscape" / "web" / "dist"


class LandscapeRepository:
    def __init__(
        self,
        uri: str,
        user: str | None,
        password: str | None,
        database: str | None,
    ) -> None:
        auth = (user, password) if user else None
        self.driver = GraphDatabase.driver(uri, auth=auth)
        self.database = database

    def close(self) -> None:
        self.driver.close()

    def health(self) -> dict[str, Any]:
        self.driver.verify_connectivity()
        with self.driver.session(database=self.database) as session:
            record = session.run(
                "MATCH (a:AWSAccount)-[:RESOURCE]->(n) "
                "WHERE a.name IS NOT NULL "
                "RETURN count(DISTINCT a) AS accounts, "
                "count(DISTINCT n) AS resources"
            ).single()
        return {
            "status": "ok",
            "accounts": record["accounts"],
            "resources": record["resources"],
            "mode": "local-read-only",
        }

    def accounts(self) -> list[dict[str, str]]:
        with self.driver.session(database=self.database) as session:
            records = session.run(
                "MATCH (a:AWSAccount)-[:RESOURCE]->() "
                "WHERE a.name IS NOT NULL "
                "RETURN DISTINCT a.id AS id, "
                "coalesce(a.name, 'AWS account') AS name "
                "ORDER BY name, id"
            )
            return [
                {
                    "id": str(record["id"]),
                    "name": str(record["name"]),
                    "display": f"{record['name']} · {str(record['id'])[-4:]}",
                }
                for record in records
            ]

    def topology(
        self,
        account_id: str | None,
        limit: int,
        *,
        include_details: bool,
    ) -> dict[str, Any]:
        with self.driver.session(database=self.database) as session:
            records = session.run(
                """
                MATCH (a:AWSAccount)-[:RESOURCE]->(n)
                WHERE a.name IS NOT NULL
                  AND ($account_id IS NULL OR a.id = $account_id)
                  AND NOT n:AWSAccount
                RETURN a.id AS account_id,
                       coalesce(a.name, 'AWS account') AS account_name,
                       elementId(n) AS element_id,
                       labels(n) AS labels,
                       properties(n) AS properties
                ORDER BY a.id, elementId(n)
                LIMIT $limit
                """,
                account_id=account_id,
                limit=limit,
            )
            raw_nodes = [dict(record) for record in records]
            element_ids = [node["element_id"] for node in raw_nodes]
            raw_edges: list[dict[str, Any]] = []
            if element_ids:
                edge_records = session.run(
                    """
                    MATCH (source)-[relationship]->(target)
                    WHERE elementId(source) IN $element_ids
                      AND elementId(target) IN $element_ids
                    RETURN elementId(source) AS source,
                           elementId(target) AS target,
                           type(relationship) AS type
                    LIMIT $edge_limit
                    """,
                    element_ids=element_ids,
                    edge_limit=max(limit * 5, 1000),
                )
                raw_edges = [dict(record) for record in edge_records]
        result = build_topology(
            raw_nodes,
            raw_edges,
            include_details=include_details,
        )
        result["truncated"] = len(raw_nodes) == limit
        result["limit"] = limit
        return result


class LandscapeHandler(SimpleHTTPRequestHandler):
    repository: LandscapeRepository

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(DIST), **kwargs)

    def _send_json(self, payload: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.end_headers()
        self.wfile.write(body)

    def _send_error_json(self, error: Exception) -> None:
        self._send_json(
            {"error": type(error).__name__, "message": str(error)},
            HTTPStatus.INTERNAL_SERVER_ERROR,
        )

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/api/health":
                self._send_json(self.repository.health())
                return
            if parsed.path == "/api/accounts":
                self._send_json({"accounts": self.repository.accounts()})
                return
            if parsed.path == "/api/topology":
                query = parse_qs(parsed.query)
                account_id = query.get("account", [None])[0] or None
                limit = min(max(int(query.get("limit", ["1500"])[0]), 1), 5000)
                include_details = query.get("view", ["architecture"])[0] == "full"
                self._send_json(
                    self.repository.topology(
                        account_id,
                        limit,
                        include_details=include_details,
                    )
                )
                return
            if parsed.path.startswith("/api/"):
                self._send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)
                return
            if parsed.path != "/" and not (DIST / parsed.path.lstrip("/")).exists():
                self.path = "/"
            super().do_GET()
        except Exception as error:
            self._send_error_json(error)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/api/export/drawio":
            self._send_json({"error": "not_found"}, HTTPStatus.NOT_FOUND)
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length > 10_000_000:
                self._send_json(
                    {"error": "payload_too_large"},
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                )
                return
            payload = json.loads(self.rfile.read(content_length))
            body = export_drawio(payload.get("nodes", []), payload.get("edges", []))
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/vnd.jgraph.mxfile")
            self.send_header(
                "Content-Disposition",
                'attachment; filename="cartography-aws-landscape.drawio"',
            )
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)
        except Exception as error:
            self._send_error_json(error)

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[landscape] {self.address_string()} {format % args}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Cartography Landscape local UI")
    parser.add_argument(
        "--neo4j-uri",
        default=os.getenv("NEO4J_URI", "bolt://127.0.0.1:7687"),
    )
    parser.add_argument("--neo4j-user", default=os.getenv("NEO4J_USER"))
    parser.add_argument(
        "--neo4j-password-env",
        default="NEO4J_PASSWORD",
        help="Environment variable containing the Neo4j password.",
    )
    parser.add_argument("--neo4j-database", default=os.getenv("NEO4J_DATABASE"))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not DIST.exists():
        raise SystemExit(
            "Landscape web build missing. Run `npm run build` in landscape/web."
        )
    password = os.getenv(args.neo4j_password_env) if args.neo4j_user else None
    repository = LandscapeRepository(
        args.neo4j_uri,
        args.neo4j_user,
        password,
        args.neo4j_database,
    )
    LandscapeHandler.repository = repository
    server = ThreadingHTTPServer((args.host, args.port), LandscapeHandler)
    print(f"Cartography Landscape: http://{args.host}:{args.port}")
    print("Neo4j access: read queries only; HTTP bound to the requested local address.")
    try:
        server.serve_forever()
    finally:
        repository.close()


if __name__ == "__main__":
    main()
