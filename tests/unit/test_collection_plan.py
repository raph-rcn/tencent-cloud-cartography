import pytest

from tencent_cloud_cartography.collect import CollectorRunner, collect
from tencent_cloud_cartography.collection_plan import RegionPlan, region_restrictions
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.transport import CollectionError


class Regions:
    def __init__(self, products=None, regions=None):
        self.products = products if products is not None else ["cvm", "vpc", "cos"]
        self.regions = regions or {
            "cvm": {"eu-frankfurt": "AVAILABLE"},
            "vpc": {"ap-singapore": "AVAILABLE"},
        }
        self.calls = []

    def call(self, service, action, region=None, **params):
        self.calls.append((service, action, region, params))
        if action == "DescribeProducts":
            return dict(
                Products=[dict(Name=n) for n in self.products],
                TotalCount=len(self.products),
                RequestId="products",
            )
        value = self.regions[params["Product"]]
        if isinstance(value, Exception):
            raise value
        if isinstance(value, list):
            return dict(RegionSet=value, TotalCount=len(value))
        return dict(
            RegionSet=[dict(Region=k, RegionState=v) for k, v in value.items()],
            TotalCount=len(value),
            RequestId="regions-" + params["Product"],
        )


def build(transport, restrictions=None, services=None):
    coverage = []
    plan = RegionPlan.build(
        transport, "100", "prod", restrictions, services or {"cvm", "vpc"}, coverage, automatic=True
    )
    return plan, coverage


def test_each_service_uses_its_own_returned_regions_and_no_cvm_fallback():
    plan, coverage = build(Regions())
    assert plan.regions_for("cvm") == ["eu-frankfurt"]
    assert plan.regions_for("vpc") == ["ap-singapore"]
    assert plan.regions == ["ap-singapore", "eu-frankfurt"]
    assert not plan.permitted("vpc", "eu-frankfurt")
    assert not plan.permitted("cos", "eu-frankfurt")
    assert plan.permitted("cloudrc", "eu-frankfurt")
    assert [r["request_ids"] for r in coverage] == [["products"], ["regions-cvm"], ["regions-vpc"]]
    assert any(
        r["state"] == "excluded" and r["reason"] == "region_not_available_for_service"
        for r in plan.scopes
    )


def test_explicit_restrictions_survive_discovery_and_record_outside_regions():
    plan, _ = build(Regions(), ["eu-frankfurt"])
    assert plan.regions == ["eu-frankfurt"]
    assert plan.regions_for("vpc") == []
    assert not plan.permitted("cloudrc", "ap-singapore")
    assert any(
        r["region"] == "ap-singapore" and r["reason"] == "region_restriction" for r in plan.scopes
    )


def test_explicit_only_does_not_require_discovery_or_change_region_order():
    transport = Regions()
    plan = RegionPlan.build(transport, "100", "prod", ["eu-frankfurt", "ap-singapore"], {"cvm"}, [])
    assert plan.regions_for("cvm") == ["eu-frankfurt", "ap-singapore"]
    assert not transport.calls


@pytest.mark.parametrize("bad", [[], ["auto", "eu-frankfurt"], ["global"], ["../escape"], [True]])
def test_invalid_region_boundaries_rejected(bad):
    with pytest.raises(ValueError):
        region_restrictions(bad)


@pytest.mark.parametrize(
    "rows",
    [
        [
            dict(Region="eu-frankfurt", RegionState="AVAILABLE"),
            dict(Region="eu-frankfurt", RegionState="UNAVAILABLE"),
        ],
        [dict(Region="../escape", RegionState="AVAILABLE")],
        [dict(Region="eu-frankfurt", RegionState=None)],
        [None],
    ],
)
def test_invalid_region_response_never_broadens_collection(rows):
    plan, coverage = build(Regions(regions={"cvm": rows}), services={"cvm"})
    assert plan.regions_for("cvm") == []
    assert any(r["state"] == "unscanned" and r["region"] == "unknown" for r in plan.scopes)
    assert coverage[-1]["status"] == "error"


def test_unavailable_and_unknown_region_states_do_not_authorize_collection():
    plan, _ = build(
        Regions(regions={"cvm": {"eu-frankfurt": "UNAVAILABLE", "ap-tokyo": "FUTURE_STATE"}}),
        services={"cvm"},
    )
    assert not plan.regions and not plan.regions_for("cvm")


def test_unlisted_product_is_unscanned_not_assumed_supported():
    transport = Regions(products=["cvm"])
    plan, coverage = build(transport)
    assert plan.regions_for("vpc") == []
    assert any(r.get("error") == "RegionProductUnavailable" for r in coverage)
    assert len([r for r in transport.calls if r[1] == "DescribeRegions"]) == 1


def test_missing_discovery_with_explicit_bounds_allows_only_direct_bounded_attempts():
    plan, _ = build(Regions(products=[]), ["eu-frankfurt"])
    assert plan.regions_for("cvm") == ["eu-frankfurt"]
    assert not plan.permitted("cvm", "ap-singapore")
    assert not any(r["region"] == "unknown" for r in plan.scopes)


def test_denied_discovery_is_independent_between_products():
    plan, coverage = build(
        Regions(
            regions={
                "cvm": CollectionError("UnauthorizedOperation"),
                "vpc": {"ap-singapore": "AVAILABLE"},
            }
        )
    )
    assert plan.regions_for("cvm") == [] and plan.regions_for("vpc") == ["ap-singapore"]
    assert any(r.get("error") == "UnauthorizedOperation" for r in coverage)


def test_product_alias_must_be_observed_and_ambiguity_cannot_choose_one():
    plan, _ = build(
        Regions(products=["as"], regions={"as": {"eu-frankfurt": "AVAILABLE"}}),
        services={"autoscaling"},
    )
    assert plan.regions_for("autoscaling") == ["eu-frankfurt"]
    plan, coverage = build(Regions(products=["as", "autoscaling"]), services={"autoscaling"})
    assert not plan.regions and coverage[-1]["error"] == "AmbiguousRegionProduct"


def test_scope_guard_prevents_cross_service_regions_and_excluded_service_calls():
    plan, _ = build(Regions())
    graph = Graph()
    runner = CollectorRunner(graph, Regions(), "100", plan.regions, lambda _: None, plan)
    for service, region in [
        ("vpc", "eu-frankfurt"),
        ("cos", "eu-frankfurt"),
        ("cvm", "ap-singapore"),
    ]:
        row = runner.scope(
            service, "ReadMetadata", region, lambda _: pytest.fail("Outside plan must never run")
        )
        assert row["status"] == "not-queried"
    assert not runner.transport.calls


def test_unknown_account_profile_cannot_invent_account_identity(monkeypatch):
    class Bad:
        def call(self, *args, **kwargs):
            raise CollectionError("MissingCredentials", "NEVER_PRINT")

    data = collect(
        ["expired"],
        ["eu-frankfurt"],
        services={"cvm"},
        transport_factory=lambda _: Bad(),
        progress=lambda _: None,
    )
    assert not data["accounts"] and not data["nodes"]
    assert data["collection"]["profiles"][0]["account"] is None
    assert all(r["account"] is None for r in data["collection"]["scopes"])
    assert "NEVER_PRINT" not in str(data)


class FullTransport(Regions):
    def __init__(self, account="100", **kwargs):
        super().__init__(**kwargs)
        self.account = account

    def call(self, service, action, region=None, **params):
        if service == "region":
            return super().call(service, action, region, **params)
        self.calls.append((service, action, region, params))
        if service == "sts":
            return dict(AccountId=self.account, PrincipalId="reader", Type="CAMUser")
        if service == "cloudrc":
            return dict(Resources=[], RequestId="baseline-" + str(region))
        from tencent_cloud_cartography.catalog import COLLECTORS, EXTRA_COLLECTORS

        if action == "DescribeIdentityCenter":
            return dict(ServiceStatus="Disabled")
        spec = next(
            s
            for s in (*COLLECTORS, *EXTRA_COLLECTORS)
            if s.service == service and s.action == action
        )
        values = [dict(InstanceId="ins-" + self.account)] if action == "DescribeInstances" else []
        result = {"RequestId": service + "-" + action}
        for path, value in ((spec.result, values), (spec.total or "TotalCount", len(values))):
            cursor = result
            keys = path.split(".")
            for key in keys[:-1]:
                cursor = cursor.setdefault(key, {})
            cursor[keys[-1]] = value
        return result


def test_real_collector_dispatch_follows_service_specific_discovery():
    transport = FullTransport()
    data = collect(
        ["prod"],
        None,
        {"cvm", "vpc"},
        transport_factory=lambda _: transport,
        progress=lambda _: None,
    )
    assert any(n["kind"] == "cvm.instance" for n in data["nodes"])
    calls = [(s, r) for s, a, r, p in transport.calls if s in {"cvm", "vpc"} and r != "global"]
    assert calls and all(r == ("eu-frankfurt" if s == "cvm" else "ap-singapore") for s, r in calls)
    assert transport.calls[0][0] == "sts" and transport.calls[-1][0] == "sts"
    scopes = data["collection"]["scopes"]
    assert (
        next(r for r in scopes if r["service"] == "cvm" and r["region"] == "eu-frankfurt")["state"]
        == "scanned"
    )
    assert (
        next(r for r in scopes if r["service"] == "vpc" and r["region"] == "ap-singapore")["state"]
        == "scanned"
    )


def test_real_dispatch_never_queries_discovered_regions_outside_explicit_limit():
    transport = FullTransport()
    data = collect(
        ["prod"],
        ["eu-frankfurt"],
        {"cvm", "vpc"},
        discover_regions=True,
        transport_factory=lambda _: transport,
        progress=lambda _: None,
    )
    assert all(
        r in {None, "global", "eu-frankfurt"} for s, a, r, p in transport.calls if s != "region"
    )
    assert not any(s == "vpc" and r != "global" for s, a, r, p in transport.calls)
    assert any(r["reason"] == "region_restriction" for r in data["collection"]["scopes"])


def test_new_project_defaults_to_automatic_and_persists_bounded_discovery(tmp_path):
    from tencent_cloud_cartography.cli import main
    from tencent_cloud_cartography.projects import ProjectStore

    root = tmp_path / "projects"
    assert main(["projects", "--projects-dir", str(root), "init", "auto-project"]) == 0
    assert ProjectStore(root).read("auto-project")["regions"] == ["auto"]
    assert (
        main(
            [
                "projects",
                "--projects-dir",
                str(root),
                "init",
                "bounded",
                "--regions",
                "eu-frankfurt",
                "--discover-regions",
            ]
        )
        == 0
    )
    config = ProjectStore(root).read("bounded")
    assert config["regions"] == ["eu-frankfurt"] and config["discover_regions"]


def test_empty_product_region_list_is_an_explicit_no_available_scope():
    plan, _ = build(Regions(regions={"cvm": []}), services={"cvm"})
    assert next(r for r in plan.scopes if r["service"] == "cvm")["reason"] == "no_available_regions"


def test_automatic_baseline_retains_assets_in_regions_missing_from_discovery():
    class Inventory(FullTransport):
        def call(self, service, action, region=None, **params):
            if service == "cloudrc" and not params.get("Filters"):
                self.calls.append((service, action, region, params))
                return dict(
                    Resources=[
                        dict(
                            Uin="100",
                            RegionCode="ap-hongkong",
                            ResourceType="qcs::cvm::instance",
                            ResourceId="ins-outside-rms",
                        )
                    ]
                )
            return super().call(service, action, region, **params)

    transport = Inventory()
    data = collect(
        ["prod"], None, {"cvm"}, transport_factory=lambda _: transport, progress=lambda _: None
    )
    assert any(
        n["resource_id"] == "ins-outside-rms" and n["status"] == "inventory-only"
        for n in data["nodes"]
    )
    assert any(
        r["service"] == "cvm" and r["region"] == "ap-hongkong" and r["state"] == "unscanned"
        for r in data["collection"]["scopes"]
    )
    assert not any(s == "cvm" and r == "ap-hongkong" for s, a, r, p in transport.calls)
    bounded = Inventory()
    data = collect(
        ["prod"],
        ["eu-frankfurt"],
        {"cvm"},
        discover_regions=True,
        transport_factory=lambda _: bounded,
        progress=lambda _: None,
    )
    assert not any(n["resource_id"] == "ins-outside-rms" for n in data["nodes"])


def test_empty_explicit_region_argument_cannot_expand_to_automatic(monkeypatch, tmp_path):
    from tencent_cloud_cartography.cli import main

    monkeypatch.setattr(
        "tencent_cloud_cartography.cli.collect",
        lambda *a, **k: pytest.fail("Invalid restriction must not collect"),
    )
    assert main(["sync", "--regions", "", "--output", str(tmp_path / "inventory.json")]) == 1
    assert not (tmp_path / "inventory.json").exists()


def test_discovery_is_per_account_and_not_cached_across_profiles():
    first = FullTransport("100", regions={"cvm": {"eu-frankfurt": "AVAILABLE"}})
    second = FullTransport("200", regions={"cvm": {"ap-singapore": "AVAILABLE"}})
    data = collect(
        ["first", "second"],
        None,
        {"cvm"},
        transport_factory={"first": first, "second": second}.__getitem__,
        progress=lambda _: None,
    )
    assert all(r == "eu-frankfurt" for s, a, r, p in first.calls if s == "cvm")
    assert all(r == "ap-singapore" for s, a, r, p in second.calls if s == "cvm")
    assert {n["account"] for n in data["nodes"]} == {"100", "200"}
