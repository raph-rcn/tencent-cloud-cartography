import json
from copy import deepcopy

import pytest

from tencent_cloud_cartography.cli import main
from tencent_cloud_cartography.collect import CollectorRunner, collect
from tencent_cloud_cartography.fleet_coverage import overview
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.projects import ProjectRepository
from tencent_cloud_cartography.storage import load, save, validate
from tencent_cloud_cartography.transport import CollectionError


class Identity:
    def __init__(self, account, final=None):
        self.account, self.final = account, final
        self.checks = 0

    def call(self, service, action, region=None, **params):
        assert service == "sts" and action == "GetCallerIdentity"
        self.checks += 1
        value = self.final if self.checks > 1 and self.final is not None else self.account
        if isinstance(value, Exception):
            raise value
        if isinstance(value, dict):
            return value
        return dict(AccountId=value, PrincipalId="reader", Type="CAMUser")


def stage(runner, services):
    for region in [*runner.regions, "global"]:
        runner.scope("cloudrc", "SearchResources", region, lambda record: None)
    if not services or "cvm" in services:
        for region in runner.regions_for("cvm"):

            def add(record, region=region):
                runner.graph.add(
                    runner.account, region, "cvm.instance", "ins-" + runner.transport.account
                )
                record["count"] = 1

            runner.scope("cvm", "DescribeInstances", region, add)
    if (not services or "organization" in services) and runner.account == "100":

        def members(record):
            for member in ("200", "303", "404"):
                nid = runner.graph.add(
                    "100", "global", "organization.member", member, "Member " + member
                )
                runner.graph.nodes[nid]["properties"]["MemberUin"] = int(member)
            record["count"] = 3

        runner.scope("organization", "DescribeOrganizationMembers", "global", members)


def fleet(monkeypatch, transports, services=None):
    monkeypatch.setattr(CollectorRunner, "run", stage)
    return collect(
        list(transports),
        ["eu-frankfurt"],
        services or {"cvm"},
        transport_factory=transports.__getitem__,
        progress=lambda _: None,
    )


def test_expired_and_denied_profiles_do_not_discard_healthy_inventory(monkeypatch):
    data = fleet(
        monkeypatch,
        {
            "expired": Identity(CollectionError("MissingCredentials", "NEVER_PRINT")),
            "healthy": Identity("200"),
            "denied": Identity(CollectionError("UnauthorizedOperation")),
        },
    )
    assert {a["id"] for a in data["accounts"]} == {"200"}
    assert {n["account"] for n in data["nodes"]} == {"200"}
    assert data["status"] == "partial"
    assert [p["status"] for p in data["collection"]["profiles"]] == ["failed", "scanned", "failed"]
    assert "NEVER_PRINT" not in json.dumps(data)
    assert overview(data)["counts"]["unscanned"] > 0
    validate(data)


@pytest.mark.parametrize(
    "final",
    [
        CollectionError("MissingCredentials"),
        dict(AccountId="404", PrincipalId="different", Type="CAMUser"),
        dict(AccountId="999", PrincipalId="reader", Type="CAMUser"),
    ],
)
def test_identity_change_or_expiry_discards_only_that_account(final, monkeypatch):
    data = fleet(monkeypatch, {"changing": Identity("404", final), "healthy": Identity("200")})
    assert {n["account"] for n in data["nodes"]} == {"200"}
    assert data["collection"]["profiles"][0]["status"] == "discarded"
    assert all(
        r["resource_count"] == 0 for r in data["collection"]["scopes"] if r["account"] == "404"
    )
    assert any(r.get("inventory_discarded") for r in data["coverage"])
    assert data["collection"]["profiles"][1]["committed"]


def test_duplicate_verified_accounts_are_aliases_without_double_collection(monkeypatch):
    first, alias = Identity("200"), Identity("200")
    data = fleet(monkeypatch, {"first": first, "alias": alias})
    assert len(data["accounts"]) == 1 and len(data["nodes"]) == 1
    assert data["collection"]["profiles"][1]["alias_of"] == "first"
    assert alias.checks == 1 and first.checks == 2
    assert not any(r["profile"] == "alias" for r in data["collection"]["scopes"])


def test_backup_profile_can_collect_after_an_unverified_attempt(monkeypatch):
    data = fleet(
        monkeypatch,
        {
            "changing": Identity("200", CollectionError("MissingCredentials")),
            "backup": Identity("200"),
        },
    )
    assert data["collection"]["profiles"][1]["committed"]
    assert data["accounts"][0]["name"] == "backup"
    assert len(data["nodes"]) == 1


def test_organization_reconciliation_uses_returned_identity_not_profile_name(monkeypatch):
    data = fleet(
        monkeypatch,
        {
            "manager": Identity("100"),
            "member": Identity("200"),
            "303": Identity(CollectionError("MissingCredentials")),
            "failed-member": Identity("404", CollectionError("MissingCredentials")),
        },
        {"cvm", "organization"},
    )
    rows = {r["member_account"]: r for r in data["collection"]["organization"]}
    assert rows["200"]["state"] == "scanned" and rows["200"]["matched_profiles"] == ["member"]
    assert rows["303"]["state"] == "unscanned" and not rows["303"]["matched_profiles"]
    assert rows["404"]["state"] == "failed" and rows["404"]["matched_profiles"] == ["failed-member"]
    members = {n["resource_id"]: n for n in data["nodes"] if n["kind"] == "organization.member"}
    assert members["200"]["properties"]["member_inventory_collected"]
    assert not members["303"]["properties"]["member_inventory_collected"]
    assert data["collection"]["organization_discovery"][0]["enumeration_complete"]
    assert any(c.get("error") == "no_identity_verified_profile" for c in data["coverage"])


def test_denied_member_enumeration_remains_incomplete_even_with_observed_member(monkeypatch):
    def partial(runner, services):
        stage(runner, services)
        if runner.account == "100":
            records = [
                r for r in runner.graph.coverage if r["action"] == "DescribeOrganizationMembers"
            ]
            records[0].update(status="denied", error="UnauthorizedOperation")

    monkeypatch.setattr(CollectorRunner, "run", partial)
    data = collect(
        ["manager"],
        ["eu-frankfurt"],
        {"cvm", "organization"},
        transport_factory=lambda _: Identity("100"),
        progress=lambda _: None,
    )
    assert len(data["collection"]["organization"]) == 3
    assert not data["collection"]["organization_discovery"][0]["enumeration_complete"]
    assert data["collection"]["organization_discovery"][0]["state"] == "failed"


def test_account_exception_is_sanitized_and_other_accounts_continue(monkeypatch):
    def interrupted(runner, services):
        if runner.account == "404":
            raise RuntimeError("NEVER_PRINT_CREDENTIAL")
        stage(runner, services)

    monkeypatch.setattr(CollectorRunner, "run", interrupted)
    data = collect(
        ["broken", "healthy"],
        ["eu-frankfurt"],
        {"cvm"},
        transport_factory={"broken": Identity("404"), "healthy": Identity("200")}.__getitem__,
        progress=lambda _: None,
    )
    assert any(n["account"] == "200" for n in data["nodes"])
    assert data["collection"]["profiles"][0]["error"] == "AccountCollectionInterrupted"
    assert "NEVER_PRINT" not in json.dumps(data)
    assert any(
        r["state"] == "unscanned" and r["account"] == "404" for r in data["collection"]["scopes"]
    )


def test_all_failed_sync_retains_previous_inventory_and_exposes_attempt(
    monkeypatch, tmp_path, capsys
):
    data = fleet(monkeypatch, {"expired": Identity(CollectionError("MissingCredentials"))})
    path = tmp_path / "inventory.json"
    previous = Graph()
    previous.accounts = {"100": dict(id="100", display="Previous inventory")}
    previous.add("100", "eu-frankfurt", "cvm.instance", "ins-existing")
    save(previous.snapshot(), path)
    # Ensure the attempted collection is newer than the previous snapshot.
    data["created_at"] = "2099-01-01T00:00:00+00:00"
    original = path.read_bytes()
    monkeypatch.setattr("tencent_cloud_cartography.cli.collect", lambda *a, **k: data)
    assert main(["sync", "--profile", "expired", "--regions", "auto", "--output", str(path)]) == 1
    assert path.read_bytes() == original
    report = path.with_name(path.name + ".attempt.json")
    assert report.stat().st_mode & 0o777 == 0o600
    assert load(report)["collection"]["profiles"][0]["error"] == "MissingCredentials"
    view = ProjectRepository(default_path=path).read_snapshot()
    assert view["nodes"][0]["resource_id"] == "ins-existing" and view["status"] == "partial"
    summary = overview(view)
    assert summary["latest_attempt_failed"] and summary["counts"]["unscanned"] > 0
    assert "existing snapshot preserved" in capsys.readouterr().err


def test_successful_new_snapshot_supersedes_old_failed_attempt(monkeypatch, tmp_path):
    data = fleet(monkeypatch, {"healthy": Identity("200")})
    path = tmp_path / "inventory.json"
    failed = deepcopy(data)
    failed["created_at"] = "2000-01-01T00:00:00+00:00"
    save(failed, path.with_name(path.name + ".attempt.json"))
    save(data, path)
    assert not ProjectRepository(default_path=path).read_snapshot().get("latest_attempt")


def test_reanalysis_preserves_collection_plan_and_input(monkeypatch):
    from tencent_cloud_cartography.permissions import analyze_snapshot

    data = fleet(monkeypatch, {"healthy": Identity("200")})
    original = deepcopy(data)
    result = analyze_snapshot(data)
    assert data == original and result["collection"] == original["collection"]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: c["scopes"][0].update(state="complete"),
        lambda c: c["scopes"][0].update(query_count=999),
        lambda c: c["profiles"][0].update(account="999"),
        lambda c: c.update(version=2),
    ],
)
def test_malformed_plan_cannot_be_presented_as_coverage_proof(monkeypatch, mutate):
    data = fleet(monkeypatch, {"healthy": Identity("200")})
    mutate(data["collection"])
    with pytest.raises(ValueError):
        validate(data)


def test_legacy_snapshot_overview_does_not_invent_a_scope_census():
    g = Graph()
    g.coverage = [
        dict(
            account="100",
            region="eu-frankfurt",
            service="cvm",
            action="DescribeInstances",
            status="empty",
            count=0,
            request_ids=[],
        )
    ]
    result = overview(g.snapshot())
    assert result["basis"] == "recorded_operations_only" and result["counts"]["scanned"] == 1
    assert not result["organization"]


def test_http_overview_exposes_plan_and_failed_attempt_with_previous_graph(monkeypatch, tmp_path):
    import http.client
    import threading

    from tencent_cloud_cartography.server import create_server

    data = fleet(monkeypatch, {"expired": Identity(CollectionError("MissingCredentials"))})
    path = tmp_path / "inventory.json"
    previous = Graph()
    previous.accounts = {"100": dict(id="100", display="Previous inventory")}
    previous.add("100", "eu-frankfurt", "cvm.instance", "ins-existing")
    save(previous.snapshot(), path)
    data["created_at"] = "2099-01-01T00:00:00+00:00"
    save(data, path.with_name(path.name + ".attempt.json"))
    server = create_server(port=0, repository=ProjectRepository(default_path=path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def get(url):
        conn = http.client.HTTPConnection("127.0.0.1", server.server_port)
        conn.request("GET", url)
        response = conn.getresponse()
        value = json.loads(response.read())
        assert response.status == 200
        conn.close()
        return value

    try:
        assert get("/api/health")["latest_attempt_failed"]
        assert get("/api/health")["resources"] == 1
        report = get("/api/coverage")
        assert report["overview"]["latest_attempt_failed"]
        assert report["overview"]["profiles"][0]["error"] == "MissingCredentials"
        assert report["coverage"][0]["profile"] == "expired"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_empty_setup_has_no_claim_of_a_scanned_scope_census():
    report = overview(Graph(mode="setup").snapshot())
    assert report["basis"] == "no_collection"
    assert report["inventory_created_at"] is None
    assert sum(report["counts"].values()) == 0


def test_incomplete_plan_cannot_claim_complete_coverage_when_api_records_are_empty(monkeypatch):
    data = fleet(monkeypatch, {"expired": Identity(CollectionError("MissingCredentials"))})
    g = Graph()
    g.collection = data["collection"]
    assert g.snapshot()["status"] == "partial"
    data["coverage"] = []
    data["status"] = "complete"
    with pytest.raises(ValueError, match="Incomplete collection"):
        validate(data)
