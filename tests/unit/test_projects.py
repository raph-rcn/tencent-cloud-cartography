import http.client
import json
import threading

import pytest

from tencent_cloud_cartography.cli import main
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.projects import ProjectRepository, ProjectStore
from tencent_cloud_cartography.repository import SourceError
from tencent_cloud_cartography.server import create_server
from tencent_cloud_cartography.storage import save


def test_project_settings_are_private_nonsecret_and_isolated(tmp_path):
    store = ProjectStore(tmp_path / "projects")
    store.create("production", ["prod"], ["eu-frankfurt"])
    store.create("development", ["dev", "testing"], ["ap-singapore"], ["vpc", "cvm"])
    assert store.read("production")["profiles"] == ["prod"]
    assert store.read("development")["profiles"] == ["dev", "testing"]
    assert store.snapshot_path("production") != store.snapshot_path("development")
    assert store.directory("production").joinpath("project.json").stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError):
        store.create("production", ["other"], ["eu-frankfurt"])
    raw = json.loads((store.directory("development") / "project.json").read_text())
    raw["SecretKey"] = "NEVER_READ"
    (store.directory("development") / "project.json").write_text(json.dumps(raw))
    assert [p["id"] for p in store.list()] == ["production"]


@pytest.mark.parametrize("name", ["../other", "/tmp/other", "a/b", "..", "bad name", "bad?param"])
def test_project_ids_reject_path_and_query_injection(tmp_path, name):
    with pytest.raises(ValueError):
        ProjectStore(tmp_path).directory(name)


def test_symlink_project_and_snapshot_are_rejected(tmp_path):
    root = tmp_path / "projects"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "escape").symlink_to(outside, target_is_directory=True)
    store = ProjectStore(root)
    with pytest.raises(ValueError):
        store.directory("escape")
    store.create("safe", ["default"], ["eu-frankfurt"])
    store.directory("safe").joinpath("inventory.json").symlink_to(outside / "secrets.json")
    with pytest.raises(ValueError):
        store.snapshot_path("safe")


def test_project_viewer_empty_setup_and_refresh_without_cloud_calls(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "tencent_cloud_cartography.transport.TccliTransport.call",
        lambda *a, **k: pytest.fail("Viewer must not call cloud"),
    )
    store = ProjectStore(tmp_path / "projects")
    store.create("my-environment", ["default"], ["eu-frankfurt"])
    source = ProjectRepository(store, "my-environment", tmp_path / "uncollected.json")
    assert source.read_snapshot()["mode"] == "setup"
    assert not source.read_snapshot()["nodes"]
    g = Graph()
    g.accounts = {"100": dict(id="100", display="Fixture", name="Fixture")}
    save(g.snapshot(), store.snapshot_path("my-environment"))
    assert (
        source.read_snapshot()["mode"] == "live"
        and source.read_snapshot()["project"]["id"] == "my-environment"
    )
    assert source.read_project()["accounts"][0]["id"] == "100"
    with pytest.raises(SourceError):
        source.read_project("../escape")


def test_default_and_project_viewer_do_not_silently_use_demo(tmp_path):
    path = tmp_path / "inventory.json"
    save(Graph(mode="demo").snapshot(), path)
    with pytest.raises(SourceError):
        ProjectRepository(default_path=path).read_snapshot()


def test_cli_project_defaults_select_profiles_regions_and_output(tmp_path, monkeypatch):
    root = tmp_path / "projects"
    assert (
        main(
            [
                "projects",
                "--projects-dir",
                str(root),
                "init",
                "alpha",
                "--profile",
                "one",
                "--profile",
                "two",
                "--regions",
                "eu-frankfurt,ap-singapore",
                "--services",
                "cvm,vpc",
            ]
        )
        == 0
    )
    calls = []

    def collect(profiles, regions, services, tccli, **kwargs):
        calls.append((profiles, regions, services))
        return Graph().snapshot()

    monkeypatch.setattr("tencent_cloud_cartography.cli.collect", collect)
    assert main(["sync", "--project", "alpha", "--projects-dir", str(root)]) == 0
    assert calls == [(["one", "two"], ["eu-frankfurt", "ap-singapore"], {"cvm", "vpc"})]
    assert ProjectStore(root).snapshot_path("alpha").exists()
    monkeypatch.chdir(tmp_path)
    seen = []
    monkeypatch.setattr(
        "tencent_cloud_cartography.cli.serve",
        lambda **kwargs: seen.append(kwargs["repository"].read_snapshot()),
    )
    assert main(["serve", "--projects-dir", str(root)]) == 0
    assert seen[0]["mode"] == "setup"


def test_project_http_selection_keeps_accounts_and_coverage_separate(tmp_path):
    store = ProjectStore(tmp_path / "projects")
    for name, account in [("alpha", "100"), ("beta", "200")]:
        store.create(name, [name], ["eu-frankfurt"])
        graph = Graph()
        graph.accounts = {account: dict(id=account, name=name, display=name)}
        graph.add(account, "eu-frankfurt", "cvm.instance", "ins-" + name)
        graph.coverage = [
            dict(
                account=account,
                region="eu-frankfurt",
                service="fixture",
                action="unit-test",
                status="complete",
                count=1,
                request_ids=[],
            )
        ]
        save(graph.snapshot(), store.snapshot_path(name))
    source = ProjectRepository(store, default_path=tmp_path / "missing.json")
    server = create_server(port=0, repository=source)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def request(path, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", server.server_port)
        conn.request("GET", path, headers=headers or {})
        response = conn.getresponse()
        data = json.loads(response.read())
        conn.close()
        return response.status, data

    try:
        assert request("/api/health")[1]["mode"] == "setup"
        assert request("/api/health?project=")[1]["mode"] == "setup"
        assert {p["id"] for p in request("/api/projects")[1]["projects"]} == {"alpha", "beta"}
        assert request("/api/accounts?project=alpha")[1]["accounts"][0]["id"] == "100"
        assert request("/api/accounts?project=beta")[1]["accounts"][0]["id"] == "200"
        assert request("/api/coverage?project=alpha")[1]["coverage"][0]["account"] == "100"
        assert request("/api/health?project=../escape")[0] == 503
        assert request("/api/projects", {"Origin": "https://foreign.example"})[0] == 403
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_empty_setup_cannot_replace_database_inventory(monkeypatch):
    from tencent_cloud_cartography.neo4j import mirror
    from tencent_cloud_cartography.storage import validate

    setup = Graph(mode="setup").snapshot()
    monkeypatch.setattr(
        "tencent_cloud_cartography.neo4j.connect",
        lambda *a, **k: pytest.fail("Setup must never connect to or clear a database"),
    )
    with pytest.raises(ValueError, match="Setup state"):
        mirror(setup, "bolt://127.0.0.1:7688")
    setup["accounts"] = [dict(id="100", display="Fake inventory")]
    with pytest.raises(ValueError, match="Setup state"):
        validate(setup)
