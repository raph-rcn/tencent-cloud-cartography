"""Direct, loopback Neo4j persistence and read-only viewer queries."""

import hashlib
import json
from urllib.parse import urlparse

from neo4j import READ_ACCESS, GraphDatabase
from neo4j.exceptions import DriverError, Neo4jError

from .repository import SourceError
from .storage import validate

FORMAT_VERSION = 2
ACTIVE_SCAN = """
MATCH (state:TencentCartographyState {id:'active'})
MATCH (scan:TencentCartography:TencentScan {scan_id:state.scan_id})
RETURN properties(scan) AS metadata
"""
READ_NODES = """
MATCH (n:TencentCartography:TencentResource {scan_id:$scan_id})
RETURN n.id AS id, n.account AS account, n.region AS region, n.kind AS kind,
       n.resource_id AS resource_id, n.name AS name, n.status AS status,
       n.properties_json AS properties_json, n.sources AS sources
"""
READ_EDGES = """
MATCH (a:TencentCartography:TencentResource {scan_id:$scan_id})
      -[r:TENCENT_RELATIONSHIP {scan_id:$scan_id}]->
      (b:TencentCartography:TencentResource {scan_id:$scan_id})
RETURN r.id AS id, a.id AS source, b.id AS target,
       r.kind AS relationship, r.provenance AS provenance
"""


def fingerprint(snapshot):
    """Ordering of database query results must not affect generation identity."""
    canonical = {**snapshot}
    for key in ("nodes", "edges", "accounts"):
        canonical[key] = sorted(snapshot[key], key=lambda row: row["id"])
    return hashlib.sha256(
        json.dumps(
            canonical, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":")
        ).encode()
    ).hexdigest()


def check_uri(uri):
    parsed = urlparse(uri)
    if parsed.scheme not in {"bolt", "bolt+s", "bolt+ssc"} or parsed.hostname not in {
        "localhost",
        "127.0.0.1",
        "::1",
    }:
        raise ValueError("Use a direct loopback Bolt URI, e.g. bolt://127.0.0.1:7688")
    if (
        parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError(
            "Neo4j URI must not contain credentials, query parameters or a database path"
        )
    _ = parsed.port  # Validate malformed ports before driver setup.


def connect(uri, user=None, password=None):
    check_uri(uri)
    if bool(user) != bool(password):
        raise ValueError(
            "Provide both --neo4j-user and a password through its selected environment variable"
        )
    return GraphDatabase.driver(
        uri,
        auth=(user, password) if user else None,
        connection_timeout=5,
        connection_acquisition_timeout=10,
        max_transaction_retry_time=10,
    )


class GenerationChanged(Exception):
    pass


class Neo4jRepository:
    backend = "neo4j"

    def __init__(self, uri, user=None, password=None, database=None):
        self.driver = connect(uri, user, password)
        self.database = database

    def close(self):
        self.driver.close()

    def _read_generation(self, tx, metadata):
        if metadata.get("format_version") != FORMAT_VERSION:
            raise SourceError("Unsupported Neo4j graph format; re-sync or import a saved snapshot.")
        scan_id = metadata["scan_id"]
        snapshot = json.loads(metadata["metadata_json"])
        nodes = []
        for row in tx.run(READ_NODES, scan_id=scan_id):
            node = dict(row)
            node["properties"] = json.loads(node.pop("properties_json"))
            nodes.append(node)
        snapshot["nodes"] = nodes
        snapshot["edges"] = [dict(row) for row in tx.run(READ_EDGES, scan_id=scan_id)]
        # Neo4j uses read-committed isolation: a writer may replace data between
        # these reads. Never serve a mixed or emptied generation as a valid scan.
        current = tx.run(ACTIVE_SCAN).single()
        if not current or current["metadata"]["scan_id"] != scan_id:
            raise GenerationChanged()
        if len(nodes) != metadata["node_count"] or len(snapshot["edges"]) != metadata["edge_count"]:
            raise GenerationChanged()
        validate(snapshot)
        if fingerprint(snapshot) != scan_id:
            raise GenerationChanged()
        return snapshot

    def _read(self, tx):
        record = tx.run(ACTIVE_SCAN).single()
        if not record:
            raise SourceError("No published Tencent graph; sync or import a saved snapshot first.")
        return self._read_generation(tx, record["metadata"])

    def read_snapshot(self):
        try:
            for _ in range(3):
                try:
                    with self.driver.session(
                        database=self.database, default_access_mode=READ_ACCESS
                    ) as session:
                        return session.execute_read(self._read)
                except GenerationChanged:
                    continue
            raise SourceError(
                "Neo4j scan changed during reading or failed integrity checks; retry after sync completes."
            )
        except (DriverError, Neo4jError) as exc:
            raise SourceError(
                "Neo4j unavailable; check the local server, database and authentication."
            ) from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise SourceError(
                "Neo4j graph metadata is invalid; re-sync or import a validated snapshot."
            ) from exc


def _write(tx, snapshot, scan_id):
    # The property dependency obtains a write lock, serializing our publishers.
    tx.run(
        "MERGE (s:TencentCartographyState {id:'active'}) SET s.sequence=coalesce(s.sequence,0)+1"
    ).consume()
    tx.run("MATCH (n:TencentCartography) DETACH DELETE n").consume()
    nodes = [
        {**n, "properties_json": json.dumps(n["properties"], ensure_ascii=False, allow_nan=False)}
        for n in snapshot["nodes"]
    ]
    tx.run(
        """UNWIND $nodes AS n
              CREATE (:TencentCartography:TencentResource {
                  scan_id:$scan_id, id:n.id, account:n.account, region:n.region,
                  kind:n.kind, resource_id:n.resource_id, name:n.name,
                  status:n.status, properties_json:n.properties_json, sources:n.sources})""",
        nodes=nodes,
        scan_id=scan_id,
    ).consume()
    tx.run(
        """UNWIND $edges AS e
              MATCH (a:TencentCartography:TencentResource {scan_id:$scan_id, id:e.source}),
                    (b:TencentCartography:TencentResource {scan_id:$scan_id, id:e.target})
              CREATE (a)-[:TENCENT_RELATIONSHIP {scan_id:$scan_id, id:e.id,
                  kind:e.relationship, provenance:e.provenance}]->(b)""",
        edges=snapshot["edges"],
        scan_id=scan_id,
    ).consume()
    metadata = {k: v for k, v in snapshot.items() if k not in {"nodes", "edges"}}
    tx.run(
        """CREATE (:TencentCartography:TencentScan {scan_id:$scan_id,
                  format_version:$version, metadata_json:$metadata,
                  node_count:$nodes, edge_count:$edges, created_at:$created_at,
                  status:$status})
              WITH 1 AS ignored MATCH (s:TencentCartographyState {id:'active'})
              SET s.scan_id=$scan_id""",
        scan_id=scan_id,
        version=FORMAT_VERSION,
        metadata=json.dumps(metadata, ensure_ascii=False, allow_nan=False),
        nodes=len(snapshot["nodes"]),
        edges=len(snapshot["edges"]),
        created_at=snapshot["created_at"],
        status=snapshot["status"],
    ).consume()


def mirror(snapshot, uri, user=None, password=None, database=None):
    validate(snapshot)
    scan_id = fingerprint(snapshot)
    try:
        with connect(uri, user, password) as driver:
            driver.verify_connectivity()
            with driver.session(database=database) as session:
                session.run("""CREATE CONSTRAINT tencent_cartography_state_id IF NOT EXISTS
                               FOR (s:TencentCartographyState) REQUIRE s.id IS UNIQUE""").consume()
                session.execute_write(_write, snapshot, scan_id)
    except (DriverError, Neo4jError) as exc:
        raise SourceError(
            "Neo4j publication could not be confirmed. Check the local server, database and authentication before retrying."
        ) from exc
