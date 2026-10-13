"""Atomic private snapshots and an optional isolated Neo4j mirror."""

import json
import os
import tempfile
from pathlib import Path
from urllib.parse import urlparse


def save(snapshot, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=".snapshot-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(snapshot, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load(path):
    path = Path(path)
    if path.stat().st_size > 100_000_000:
        raise ValueError("Snapshot exceeds 100 MB")
    data = json.loads(path.read_text())
    if data.get("schema_version") != 1 or not all(
        isinstance(data.get(k), list) for k in ("nodes", "edges", "accounts", "coverage")
    ):
        raise ValueError("Unsupported snapshot schema")
    ids = [n["id"] for n in data["nodes"]]
    id_set = set(ids)
    if len(ids) != len(id_set) or any(
        e["source"] not in id_set or e["target"] not in id_set for e in data["edges"]
    ):
        raise ValueError("Invalid graph endpoints")
    return data


def mirror(snapshot, uri):
    from neo4j import GraphDatabase

    if urlparse(uri).hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("Neo4j must be on loopback")

    # One transaction replaces only nodes belonging to this application. AWS
    # Cartography labels and other graph data are never selected for deletion.
    def write(tx):
        tx.run("MATCH (n:TencentCartography) DETACH DELETE n").consume()
        nodes = [{**n, "properties_json": json.dumps(n["properties"])} for n in snapshot["nodes"]]
        tx.run(
            "UNWIND $nodes AS n CREATE (r:TencentCartography:TencentResource {id:n.id, account:n.account, region:n.region, kind:n.kind, resource_id:n.resource_id, name:n.name, status:n.status, properties_json:n.properties_json, sources:n.sources})",
            nodes=nodes,
        ).consume()
        tx.run(
            "UNWIND $edges AS e MATCH (a:TencentResource {id:e.source}), (b:TencentResource {id:e.target}) CREATE (a)-[:TENCENT_RELATIONSHIP {id:e.id, kind:e.relationship, provenance:e.provenance}]->(b)",
            edges=snapshot["edges"],
        ).consume()
        tx.run(
            "CREATE (:TencentCartography:TencentScan {created_at:$time, status:$status, coverage_json:$coverage})",
            time=snapshot["created_at"],
            status=snapshot["status"],
            coverage=json.dumps(snapshot["coverage"]),
        ).consume()

    with GraphDatabase.driver(uri, auth=None) as driver:
        driver.verify_connectivity()
        with driver.session() as session:
            session.execute_write(write)
