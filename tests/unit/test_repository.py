import json

import pytest

from tencent_cloud_cartography.cli import main
from tencent_cloud_cartography.demo import demo
from tencent_cloud_cartography.neo4j import check_uri, fingerprint
from tencent_cloud_cartography.repository import FileRepository, SourceError
from tencent_cloud_cartography.storage import save, validate


def test_file_repository_reads_atomic_replacement_without_restarting(tmp_path):
    path = tmp_path / "snapshot.json"
    first = demo()
    save(first, path)
    source = FileRepository(path)
    assert source.read_snapshot()["created_at"] == first["created_at"]
    second = demo()
    second["accounts"][0]["display"] = "Changed synthetic name"
    save(second, path)
    assert source.read_snapshot()["accounts"][0]["display"] == "Changed synthetic name"
    path.write_text("{invalid")
    with pytest.raises(SourceError, match="unavailable"):
        source.read_snapshot()


def test_generation_fingerprint_ignores_query_order_but_detects_properties():
    snapshot = demo()
    other = json.loads(json.dumps(snapshot))
    other["nodes"].reverse()
    other["edges"].reverse()
    other["accounts"].reverse()
    assert fingerprint(snapshot) == fingerprint(other)
    other["nodes"][0]["properties"]["changed"] = True
    assert fingerprint(snapshot) != fingerprint(other)


@pytest.mark.parametrize(
    "uri",
    [
        "bolt://remote.example:7687",
        "neo4j://127.0.0.1:7687",
        "bolt://user:password@localhost:7687",
        "http://127.0.0.1:7474",
        "bolt://localhost:7687/database",
        "bolt://localhost:7687?routing=remote",
    ],
)
def test_database_uri_rejects_remote_routing_and_embedded_credentials(uri):
    with pytest.raises(ValueError):
        check_uri(uri)


@pytest.mark.parametrize(
    "uri", ["bolt://127.0.0.1:7688", "bolt+s://localhost:7687", "bolt://[::1]:7687"]
)
def test_direct_loopback_uris(uri):
    check_uri(uri)


def test_snapshot_rejects_duplicate_edges_before_database_publication():
    snapshot = demo()
    snapshot["edges"].append(snapshot["edges"][0])
    with pytest.raises(ValueError, match="relationship"):
        validate(snapshot)


def test_cli_auth_uses_selected_environment_and_database(monkeypatch, tmp_path):
    from tencent_cloud_cartography import cli

    snapshot = demo()
    path = tmp_path / "demo.json"
    save(snapshot, path)
    calls = []
    monkeypatch.setenv("TEST_TENCENT_PASSWORD", "synthetic-password")
    monkeypatch.setattr(cli, "mirror", lambda *args, **kwargs: calls.append((args, kwargs)))
    result = main(
        [
            "import",
            "--input",
            str(path),
            "--neo4j-uri",
            "bolt://127.0.0.1:7688",
            "--neo4j-user",
            "reader",
            "--neo4j-password-env",
            "TEST_TENCENT_PASSWORD",
            "--neo4j-database",
            "inventory",
        ]
    )
    assert result == 0
    assert calls[0][1] == dict(user="reader", password="synthetic-password", database="inventory")
    assert calls[0][0][0] == snapshot


def test_cli_closes_database_reader_on_server_failure(monkeypatch):
    from tencent_cloud_cartography import cli

    closed = []

    class Repository:
        def __init__(self, *args, **kwargs):
            pass

        def close(self):
            closed.append(True)

    monkeypatch.setattr(cli, "Neo4jRepository", Repository)
    monkeypatch.setattr(
        cli, "serve", lambda **kwargs: (_ for _ in ()).throw(SourceError("Test source failure"))
    )
    assert main(["serve", "--neo4j-uri", "bolt://127.0.0.1:7688"]) == 1
    assert closed == [True]


def test_cli_does_not_accept_conflicting_sources():
    with pytest.raises(SystemExit) as exc:
        main(["serve", "--input", "file.json", "--neo4j-uri", "bolt://localhost:7688"])
    assert exc.value.code == 2
