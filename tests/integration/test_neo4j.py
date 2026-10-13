"""Real Neo4j tests. Opt-in only; refuse to run against a nonempty database."""

import http.client
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from neo4j import GraphDatabase

from tencent_cloud_cartography import neo4j as backend
from tencent_cloud_cartography.demo import demo
from tencent_cloud_cartography.neo4j import Neo4jRepository, fingerprint, mirror
from tencent_cloud_cartography.repository import SourceError
from tencent_cloud_cartography.server import create_server


@pytest.fixture
def database():
    uri = os.environ.get("TEST_TENCENT_NEO4J_URI")
    if not uri:
        pytest.skip("Set TEST_TENCENT_NEO4J_URI to an empty disposable Neo4j database")
    options = dict(
        user=os.environ.get("TEST_TENCENT_NEO4J_USER"),
        password=os.environ.get("TEST_TENCENT_NEO4J_PASSWORD"),
        database=os.environ.get("TEST_TENCENT_NEO4J_DATABASE", "neo4j"),
    )
    auth = (options["user"], options["password"]) if options["user"] else None
    driver = GraphDatabase.driver(uri, auth=auth)
    driver.verify_connectivity()
    with driver.session(database=options["database"]) as session:
        count = session.run("MATCH (n) RETURN count(n) AS count").single()["count"]
        if count:
            driver.close()
            pytest.fail(
                "Integration tests require an EMPTY disposable database; no data was modified"
            )
    try:
        yield uri, options, driver
    finally:
        with driver.session(database=options["database"]) as session:
            session.run(
                "MATCH (n) WHERE n:TencentCartography OR n:TencentCartographyState OR n:ParityTestOther DETACH DELETE n"
            ).consume()
        driver.close()


def test_real_roundtrip_preserves_accounts_coverage_and_isolates_other_graphs(database):
    uri, options, driver = database
    original = demo()
    with driver.session(database=options["database"]) as session:
        session.run(
            'CREATE (:ParityTestOther:AWSAccount:TencentResource {id:$id, name:"Leave me intact"})',
            id=original["nodes"][0]["id"],
        ).consume()
    mirror(original, uri, **options)
    repository = Neo4jRepository(uri, **options)
    try:
        read = repository.read_snapshot()
        assert fingerprint(read) == fingerprint(original)
        assert read["accounts"] == original["accounts"]
        assert read["coverage"] == original["coverage"]
        assert read["mode"] == "demo"
        # Replacing twice must not duplicate nodes or match the foreign same-ID node.
        mirror(original, uri, **options)
        assert fingerprint(repository.read_snapshot()) == fingerprint(original)
        with driver.session(database=options["database"]) as session:
            assert (
                session.run("MATCH (n:ParityTestOther) RETURN n.name AS name").single()["name"]
                == "Leave me intact"
            )
            assert (
                session.run("MATCH (:ParityTestOther)-[r]-() RETURN count(r) AS count").single()[
                    "count"
                ]
                == 0
            )
            assert session.run(
                "MATCH (n:TencentCartography:TencentResource) RETURN count(n) AS count"
            ).single()["count"] == len(original["nodes"])
    finally:
        repository.close()


def test_real_failed_publication_rolls_back_entire_generation(database, monkeypatch):
    uri, options, _ = database
    original = demo()
    mirror(original, uri, **options)
    replacement = demo()
    replacement["accounts"][0]["display"] = "Replacement that must roll back"
    real_write = backend._write

    def fail_after_writes(tx, snapshot, scan_id):
        real_write(tx, snapshot, scan_id)
        raise ValueError("Synthetic failure after graph and pointer writes")

    monkeypatch.setattr(backend, "_write", fail_after_writes)
    with pytest.raises(ValueError, match="Synthetic failure"):
        mirror(replacement, uri, **options)
    repository = Neo4jRepository(uri, **options)
    try:
        assert fingerprint(repository.read_snapshot()) == fingerprint(original)
    finally:
        repository.close()


def test_real_concurrent_replacement_retries_without_mixing_scans(database, monkeypatch):
    uri, options, _ = database
    first, second = demo(), demo()
    second["accounts"][0]["display"] = "Concurrent replacement"
    mirror(first, uri, **options)
    repository = Neo4jRepository(uri, **options)
    entered, release = threading.Event(), threading.Event()
    original_read = repository._read_generation
    reads = []

    def interleaved(tx, metadata):
        reads.append(metadata["scan_id"])
        if len(reads) == 1:
            entered.set()
            assert release.wait(15), "Writer did not release the first reader"
        return original_read(tx, metadata)

    monkeypatch.setattr(repository, "_read_generation", interleaved)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(repository.read_snapshot)
            try:
                assert entered.wait(15), "Reader did not reach the generation boundary"
                mirror(second, uri, **options)
            finally:
                release.set()
            result = future.result(timeout=15)
        assert fingerprint(result) == fingerprint(second)
        assert len(reads) >= 2
    finally:
        repository.close()


def test_real_reader_uses_only_fixed_read_queries_and_detects_corruption(database, monkeypatch):
    uri, options, driver = database
    mirror(demo(), uri, **options)
    repository = Neo4jRepository(uri, **options)
    read = repository._read
    queries = []

    class Guard:
        def __init__(self, tx):
            self.tx = tx

        def run(self, query, **params):
            assert query in {backend.ACTIVE_SCAN, backend.READ_NODES, backend.READ_EDGES}
            queries.append(query)
            return self.tx.run(query, **params)

    monkeypatch.setattr(repository, "_read", lambda tx: read(Guard(tx)))
    try:
        assert repository.read_snapshot()["nodes"]
        assert set(queries) == {backend.ACTIVE_SCAN, backend.READ_NODES, backend.READ_EDGES}
        with driver.session(database=options["database"]) as session:
            session.run(
                'MATCH (n:TencentCartography:TencentResource) SET n.name="Tampered"'
            ).consume()
        with pytest.raises(SourceError, match="integrity"):
            repository.read_snapshot()
    finally:
        repository.close()


def test_real_http_neo4j_refresh_and_missing_graph(database):
    uri, options, _ = database
    repository = Neo4jRepository(uri, **options)
    server = create_server(port=0, repository=repository)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def get(path):
        conn = http.client.HTTPConnection("127.0.0.1", server.server_port)
        conn.request("GET", path)
        response = conn.getresponse()
        value = response.status, json.loads(response.read())
        conn.close()
        return value

    try:
        assert get("/api/health")[0] == 503
        first = demo()
        mirror(first, uri, **options)
        status, health = get("/api/health")
        assert status == 200 and health["backend"] == "neo4j"
        status, graph = get("/api/topology?view=full&include_inventory=1")
        assert status == 200 and graph["stats"]["relationships"] == len(first["edges"])
        second = demo()
        second["accounts"][0]["display"] = "Refreshed in database"
        mirror(second, uri, **options)
        assert get("/api/accounts")[1]["accounts"][0]["display"] == "Refreshed in database"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
        repository.close()
