from dataclasses import replace
from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.catalog import COLLECTORS
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.peering import collect, link
from tencent_cloud_cartography.transport import CollectionError

REGION = "eu-frankfurt"
SPEC = next(s for s in COLLECTORS if s.kind == "vpc.peeringconnection")


def peering(**values):
    return dict(
        dict(
            PeeringConnectionId="pcx-one",
            PeeringConnectionName="Frankfurt to Singapore",
            SourceVpcId="vpc-one",
            PeerVpcId="vpc-two",
            DestinationVpcId="vpc-two",
            SourceUin=100,
            DestinationUin=200,
            SourceRegion="de",
            DestinationRegion="sg",
            AppId=12345,
            PeerAppId=67890,
            Type="VPC_PEER",
            State="ISOLATED",
            IsNgw=True,
            Bandwidth=0,
            QosLevel="AU",
            ChargeType="POSTPAID_BY_DAY_MAX",
            CreateTime="2026-10-14",
        ),
        **values,
    )


def run(rows=None, mutate=None, spec=SPEC):
    rows = [peering()] if rows is None else rows
    g, calls = Graph(), []

    def call(service, action, **params):
        assert service == "vpc" and action == SPEC.action and params["region"] == REGION
        calls.append(params)
        response = dict(
            PeerConnectionSet=rows[params["Offset"] : params["Offset"] + params["Limit"]],
            TotalCount=len(rows),
            RequestId=str(len(calls)),
        )
        return mutate(response) if mutate else response

    collect(
        CollectorRunner(g, SimpleNamespace(call=call), "100", [REGION], lambda _: None),
        spec,
        REGION,
    )
    return g, calls


def resource(g):
    return next(n for n in g.nodes.values() if n["kind"] == "vpc.peeringconnection")


def add_network(g, account="200", region="ap-singapore", rid="vpc-two", kind="vpc.vpc", block=True):
    nid = g.add(account, region, kind, rid, source="synthetic")
    if block:
        bid = g.add(account, region, "vpc.cidr", f"{rid}/10.0.0.0/16", source="synthetic")
        g.nodes[bid]["properties"].update(VpcId=rid, cidr="10.0.0.0/16", ip_version=4)
        g.edge(nid, bid, "HAS_CIDR", "synthetic")
    return nid


def test_explicit_sides_preserve_owner_regions_metadata_and_state():
    g, _ = run()
    n = resource(g)
    props = n["properties"]
    assert props["State"] == "ISOLATED" and props["Bandwidth"] == 0 and props["IsNgw"]
    assert props["SourceRegion"] == "de" and props["source_region"] == REGION
    assert props["DestinationUin"] == "200" and props["PeerAppId"] == 67890
    assert not props["reachability_verified"]
    assert icon_for(n["kind"]) == "en-peering-connection.svg"
    assert {
        (v["account"], v["region"], v["resource_id"])
        for v in g.nodes.values()
        if v["kind"] == "vpc.vpc"
    } == {("100", REGION, "vpc-one"), ("200", "ap-singapore", "vpc-two")}
    assert not any(e["relationship"] == "IN_VPC" for e in g.edges.values())


def test_cidrs_link_only_to_collected_endpoint_vpc_inventory():
    g, _ = run()
    add_network(g)
    add_network(g, account="100", region=REGION, rid="vpc-one")
    link(g)
    assert {"SOURCE_VPC_CIDR", "PEER_VPC_CIDR"} <= {e["relationship"] for e in g.edges.values()}
    assert resource(g)["properties"]["peer_cidr_resolution"] == "collected-vpc-inventory"
    assert g.snapshot()["status"] == "complete"


@pytest.mark.parametrize(
    "change",
    [dict(account="300"), dict(region=REGION), dict(rid="vpc-other"), dict(kind="bmvpc.vpc")],
)
def test_similar_cidr_inventory_cannot_cross_endpoint_scope(change):
    g, _ = run()
    add_network(g, **change)
    link(g)
    assert not any(e["relationship"] == "PEER_VPC_CIDR" for e in g.edges.values())


def test_missing_owner_keeps_metadata_and_partial_without_appid_guess():
    g, _ = run([peering(DestinationUin=None)])
    link(g)
    assert resource(g)["properties"]["peer_resolution"] == "missing-owner"
    assert len(g.nodes) == 2 and g.coverage[0]["error"] == "IncompletePeeringEndpoint"
    assert not any(e["relationship"] == "PEER_VPC" for e in g.edges.values())


def test_unknown_region_keeps_metadata_without_fake_region_container():
    g, _ = run([peering(DestinationRegion="unknown")])
    link(g)
    assert resource(g)["properties"]["DestinationRegion"] == "unknown"
    assert not any(n["region"] == "unknown" for n in g.nodes.values())
    assert g.coverage[0]["status"] == "error"


def test_unknown_or_bare_metal_type_needs_inventory_before_linking():
    for value in ("VPC_BM_PEER", "VPC0", None, "FUTURE"):
        g, _ = run([peering(Type=value)])
        assert len(g.nodes) == 1
        add_network(g, kind="bmvpc.vpc", block=False)
        add_network(g, account="100", region=REGION, rid="vpc-one", block=False)
        link(g)
        assert resource(g)["properties"]["peer_resolution"] == "matched-collected-network"
        assert g.snapshot()["status"] == "complete"


def test_unresolved_type_and_ambiguous_network_are_explicit():
    g, _ = run([peering(Type="VPC_BM_PEER")])
    add_network(g)
    add_network(g, kind="bmvpc.vpc", block=False)
    link(g)
    assert not any(e["relationship"] == "PEER_VPC" for e in g.edges.values())
    assert resource(g)["properties"]["peer_cidr_resolution"] == "ambiguous-network"
    assert g.coverage[-1]["error"] == "UnresolvedPeeringNetworkType"


@pytest.mark.parametrize(
    "values",
    [
        dict(DestinationVpcId="vpc-other"),
        dict(SourceVpcId="ins-wrong"),
        dict(PeeringConnectionId="wrong"),
        dict(SourceUin=True),
        dict(DestinationUin="00123"),
        dict(DestinationUin=0),
        dict(DestinationUin="12.5"),
        dict(SourceRegion=1),
        dict(Bandwidth=-1),
        dict(IsNgw="true"),
        dict(AppId="12345"),
    ],
)
def test_invalid_page_adds_no_nodes(values):
    g, _ = run([peering(PeeringConnectionId="pcx-good"), peering(**values)])
    assert not g.nodes and g.coverage[0]["status"] == "error"


def test_paginated_peerings_and_duplicate_parent_detection():
    g, calls = run(
        [peering(), peering(PeeringConnectionId="pcx-two")], spec=replace(SPEC, page_size=1)
    )
    assert len(calls) == 2 and g.coverage[0]["count"] == 2
    g, _ = run([peering(), peering()], spec=replace(SPEC, page_size=1))
    assert g.coverage[0]["status"] == "error"


def test_missing_totals_and_access_denied_are_partial():
    def missing(response):
        response.pop("TotalCount")
        return response

    def denied(response):
        raise CollectionError("UnauthorizedOperation")

    for mutate, status in ((missing, "error"), (denied, "denied")):
        g, _ = run(mutate=mutate)
        assert not g.nodes and g.coverage[0]["status"] == status


def test_cidr_with_wrong_parent_or_scope_is_not_attached():
    g, _ = run()
    nid = add_network(g)
    bad = g.add("999", "ap-singapore", "vpc.cidr", "vpc-two/192.0.2.0/24", source="bad-fixture")
    g.nodes[bad]["properties"].update(VpcId="vpc-two")
    g.edge(nid, bad, "HAS_CIDR")
    for n in g.nodes.values():
        if n["kind"] == "vpc.cidr" and n["account"] == "200":
            n["properties"]["VpcId"] = "vpc-other"
    link(g)
    assert not any(e["relationship"] == "PEER_VPC_CIDR" for e in g.edges.values())
