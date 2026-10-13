import json
from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.catalog import COLLECTORS, SCF_NAMESPACES
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.inventory import reconcile_global_inventory
from tencent_cloud_cartography.model import Graph, resource_kind
from tencent_cloud_cartography.topology import topology
from tencent_cloud_cartography.transport import CollectionError

REGION = "eu-frankfurt"


def item(kind="qcs::cvm::instance", rid="ins-1", region=REGION, **extra):
    return dict(
        Uin=100,
        RegionCode=region,
        ResourceType=kind,
        ResourceId=rid,
        ResourceAlias="Inventory name",
        Tags=[dict(Key="environment", Value="test")],
        **extra,
    )


def baseline(g, responses, region=REGION):
    responses = iter(responses)
    calls = []

    def call(s, a, **params):
        calls.append((s, a, params))
        response = next(responses)
        if isinstance(response, Exception):
            raise response
        return response

    record = CollectorRunner(
        g, SimpleNamespace(call=call), "100", [REGION], lambda _: None
    ).baseline(region)
    return record, calls


@pytest.mark.parametrize(
    "raw_type,kind,rid,field",
    [
        ("qcs::cvm::volume", "cbs.disk", "disk-1", "DiskId"),
        ("ckafka::ckafkaId", "ckafka.instance", "ckafka-1", "InstanceId"),
        ("cdb::instanceId", "cdb.instance", "cdb-1", "InstanceId"),
        ("postgres::DBInstanceId", "postgres.dbinstanceid", "postgres-1", "DBInstanceId"),
    ],
)
def test_documented_types_merge_with_native_identities(raw_type, kind, rid, field):
    g = Graph()
    baseline(g, [dict(Resources=[item(raw_type, rid)], RequestId="baseline")])
    spec = next(s for s in COLLECTORS if s.kind == kind)
    nid = g.native(
        "100",
        REGION,
        spec,
        {field: rid, spec.names[0]: "Native name"},
        spec.service + "." + spec.action,
    )
    assert len(g.nodes) == 1 and g.nodes[nid]["status"] == "enriched"
    assert g.nodes[nid]["name"] == "Native name"
    assert g.nodes[nid]["properties"]["inventory_resource_type"] == raw_type
    assert g.nodes[nid]["properties"]["inventory_resource_id"] == rid
    assert g.nodes[nid]["properties"]["inventory_name"] == "Inventory name"
    assert json.loads(g.nodes[nid]["properties"]["inventory_tags"]) == [
        dict(Key="environment", Value="test")
    ]
    assert set(g.nodes[nid]["sources"]) == {
        "cloudrc.SearchResources",
        spec.service + "." + spec.action,
    }
    assert icon_for(kind) != "unmapped.svg" and g.snapshot()["unresolved"] == 0


def test_scf_inventory_type_cannot_impersonate_native_namespace():
    g = Graph()
    baseline(g, [dict(Resources=[item("scf::namespace", "default")])])
    g.native("100", REGION, SCF_NAMESPACES, dict(Name="default"), "scf.ListNamespaces")
    assert len(g.nodes) == 2
    ambiguous = next(n for n in g.nodes.values() if n["status"] == "inventory-only")
    assert ambiguous["kind"] == "scf.inventoryresource"
    assert ambiguous["properties"]["inventory_type_resolution"] == "ambiguous-provider-type"


@pytest.mark.parametrize("region", [None, ""])
def test_missing_region_requires_native_global_identity_before_merge(region):
    g = Graph()
    baseline(g, [dict(Resources=[item("privatedns::zone", "zone-1", region)])], "global")
    old = next(iter(g.nodes))
    assert g.nodes[old]["region"] == "unknown"
    other = g.add("100", "global", "privatedns.record", "record-1")
    g.edge(old, other, "HAS_RECORD", "baseline fixture")
    gid = g.add(
        "100",
        "global",
        "privatedns.zone",
        "zone-1",
        "Native zone",
        source="privatedns.DescribePrivateZoneList",
    )
    g.edge(other, old, "BELONGS_TO", "fixture")
    g.edge(gid, other, "HAS_RECORD", "native fixture")
    reconcile_global_inventory(g)
    assert old not in g.nodes and len(g.nodes) == 2
    edge = next(e for e in g.edges.values() if e["relationship"] == "HAS_RECORD")
    assert "baseline fixture" in edge["provenance"] and "native fixture" in edge["provenance"]
    assert g.nodes[gid]["name"] == "Native zone"
    assert g.nodes[gid]["properties"]["inventory_region_resolution"] == "native-global"
    assert {e["relationship"] for e in g.edges.values()} == {"HAS_RECORD", "BELONGS_TO"}
    assert all(e["source"] in g.nodes and e["target"] in g.nodes for e in g.edges.values())


@pytest.mark.parametrize("variant", ["foreign-owner", "regional", "reference", "non-global-kind"])
def test_unknown_scope_not_resolved_from_an_unproven_match(variant):
    g = Graph()
    kind = "cvm::instance" if variant == "non-global-kind" else "privatedns::zone"
    baseline(g, [dict(Resources=[item(kind, "resource-1", None)])], "global")
    old = next(iter(g.nodes))
    g.add(
        "200" if variant == "foreign-owner" else "100",
        REGION if variant == "regional" else "global",
        resource_kind(kind),
        "resource-1",
        status="reference" if variant == "reference" else "enriched",
    )
    reconcile_global_inventory(g)
    assert old in g.nodes and g.nodes[old]["status"] == "inventory-only"


@pytest.mark.parametrize(
    "patch,error",
    [
        (dict(Uin=None), "InvalidInventoryOwner"),
        (dict(Uin=True), "InvalidInventoryOwner"),
        (dict(Uin=200), "AccountMismatch"),
        (dict(ResourceId=None), "InvalidInventoryResourceId"),
        (dict(ResourceId=123), "InvalidInventoryResourceId"),
        (dict(ResourceType="cvm"), "InvalidInventoryType"),
        (dict(ResourceType="qcs::cvm::::instance"), "InvalidInventoryType"),
        (dict(RegionCode=True), "InvalidInventoryRegion"),
        (dict(ResourceAlias={}), "InvalidInventoryName"),
        (dict(Tags=[dict(Key="x", Value={"secret": "private"})]), "InvalidInventoryTags"),
    ],
)
def test_malformed_identity_and_metadata_fail_without_nodes(patch, error):
    g = Graph()
    record, _ = baseline(g, [dict(Resources=[{**item(), **patch}])])
    assert record["error"] == error and not g.nodes


@pytest.mark.parametrize("token", [1, [], True])
def test_invalid_continuation_token_preserves_prior_rows(token):
    g = Graph()
    record, _ = baseline(g, [dict(Resources=[item()], NextToken=token)])
    assert record["error"] == "InvalidInventoryToken" and record["count"] == 1


def test_duplicate_identity_across_aliases_and_rotating_tokens_is_partial():
    g = Graph()
    record, _ = baseline(
        g,
        [
            dict(Resources=[item("cvm::volume", "disk-1")], NextToken="first"),
            dict(Resources=[item("cbs::disk", "disk-1")], NextToken="second"),
        ],
    )
    assert (
        record["error"] == "DuplicateInventoryResource"
        and record["count"] == 1
        and len(g.nodes) == 1
    )


def test_account_wide_pass_counts_scans_but_retains_only_global_and_unknown_regions():
    g = Graph()
    record, calls = baseline(
        g,
        [
            dict(
                Resources=[
                    item(),
                    item("privatedns::zone", "zone-1", "global"),
                    item("future::widget", "opaque", None),
                ]
            )
        ],
        "global",
    )
    assert record["scanned_count"] == 3 and record["count"] == 2
    assert {n["region"] for n in g.nodes.values()} == {"global", "unknown"}
    assert "Filters" not in calls[0][2]
    assert g.snapshot()["status"] == "partial"


def test_baseline_denial_does_not_become_empty_or_drop_prior_inventory():
    g = Graph()
    record, _ = baseline(
        g,
        [
            dict(Resources=[item()], NextToken="next", RequestId="request"),
            CollectionError("UnauthorizedOperation"),
        ],
    )
    assert record["status"] == "denied" and record["count"] == 1
    assert record["request_ids"] == ["request"] and len(g.nodes) == 1


def test_regional_scope_does_not_guess_missing_region_from_filter():
    g = Graph()
    record, _ = baseline(g, [dict(Resources=[item(region=None)])])
    assert record["error"] == "RegionMismatch" and not g.nodes


def test_only_documented_top_level_metadata_reaches_graph():
    g = Graph()
    baseline(
        g,
        [
            dict(
                Resources=[
                    item(
                        PrivateIpAddress=["10.0.0.7"],
                        Unexpected=dict(PrivateIpAddress="private", Password="hidden"),
                    )
                ]
            )
        ],
    )
    props = next(iter(g.nodes.values()))["properties"]
    assert props["ip_addresses"] == "10.0.0.7"
    assert "private" not in g.dump() and "hidden" not in g.dump()


def test_alias_reconciliation_updates_diagram_inventory_count():
    g = Graph(mode="demo")
    g.accounts["100"] = dict(id="100", display="Test")
    baseline(g, [dict(Resources=[item("cvm::volume", "disk-1")])])
    before = topology(g.snapshot(), include_inventory=True, view="full")
    assert before["stats"]["unresolvedAvailable"] == 1
    disk = next(s for s in COLLECTORS if s.kind == "cbs.disk")
    g.native("100", REGION, disk, dict(DiskId="disk-1", DiskName="Data disk"), "cbs.DescribeDisks")
    after = topology(g.snapshot(), view="full")
    assert after["stats"]["unresolvedAvailable"] == 0
    assert after["stats"]["resources"] == 1
