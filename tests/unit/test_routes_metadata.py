from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.catalog import COLLECTORS
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.routes import collect, link_next_hops
from tencent_cloud_cartography.transport import CollectionError

REGION = "eu-frankfurt"
SPEC = next(s for s in COLLECTORS if s.kind == "vpc.routetable")


def route(**values):
    return dict(
        dict(
            RouteItemId="rti-one",
            RouteTableId="rtb-one",
            DestinationCidrBlock="0.0.0.0/0",
            GatewayType="NAT",
            GatewayId="nat-one",
            Enabled=False,
            PublishedToVbc=True,
            RouteDescription="Default egress",
            RouteType="USER",
            RouteId=1,
        ),
        **values,
    )


def table(**values):
    return dict(
        dict(
            RouteTableId="rtb-one",
            RouteTableName="Application routing",
            VpcId="vpc-one",
            Main=True,
            AssociationSet=[dict(RouteTableId="rtb-one", SubnetId="subnet-one")],
            RouteSet=[route()],
            LocalCidrForCcn=[dict(Cidr="10.0.0.0/16", PublishedToVbc=False)],
        ),
        **values,
    )


def run(tables=None, routes=None, mutate=None):
    tables = [table()] if tables is None else tables
    routes = [route()] if routes is None else routes
    graph, calls = Graph(), []

    def call(service, action, **params):
        assert service == "vpc" and params["region"] == REGION
        calls.append((action, params))
        if action == "DescribeRouteTables":
            assert params["NeedRouterInfo"] is True
            rows, key = tables, "RouteTableSet"
        else:
            assert action == "DescribeRouteList"
            assert params["Filters"][1] == dict(Name="vpc-id", Values=["vpc-one"])
            parent = params["Filters"][0]["Values"][0]
            rows, key = (
                [r for r in routes if r.get("_parent", r.get("RouteTableId")) == parent],
                "RouteSet",
            )
        response = {
            key: rows[params["Offset"] : params["Offset"] + params["Limit"]],
            "TotalCount": len(rows),
            "RequestId": str(len(calls)),
        }
        return mutate(action, params, response) if mutate else response

    runner = CollectorRunner(graph, SimpleNamespace(call=call), "100", [REGION], lambda _: None)
    collect(runner, SPEC, REGION)
    return graph, calls


def resources(g, kind):
    return [n for n in g.nodes.values() if n["kind"] == kind]


def test_table_association_route_metadata_and_disabled_gateway_link():
    g, calls = run()
    node = resources(g, "vpc.route")[0]
    assert node["properties"]["RouteDescription"] == "Default egress"
    assert node["properties"]["PublishedToVbc"] and not node["properties"]["Enabled"]
    assert not node["properties"]["reachability_verified"]
    assert len(node["sources"]) == 2 and len(calls) == 2
    parent = resources(g, "vpc.routetable")[0]
    assert parent["properties"]["Main"]
    association = resources(g, "vpc.routeassociation")[0]
    assert association["properties"]["identity_source"] == "table/subnet"
    assert icon_for(association["kind"]) == "en-virtual-private-cloud.svg"
    assert {
        "HAS_ROUTE",
        "HAS_ASSOCIATION",
        "ASSOCIATED_SUBNET",
        "USES_ROUTE_TABLE",
        "ROUTES_TO",
        "IN_VPC",
    } == {e["relationship"] for e in g.edges.values()}


@pytest.mark.parametrize(
    "typ,rid,kind,region",
    [
        ("CCN", "ccn-one", "vpc.ccn", "global"),
        ("USER_CCN", "ccn-one", "vpc.ccn", "global"),
        ("LOCAL_GATEWAY", "lgw-one", "vpc.localgateway", REGION),
        ("GWLB_ENDPOINT", "vpce-one", "vpc.endpoint", REGION),
    ],
)
def test_additional_gateway_types_keep_correct_namespace(typ, rid, kind, region):
    row = route(GatewayType=typ, GatewayId=rid)
    g, _ = run([table(RouteSet=[row])], [row])
    if kind == "vpc.ccn":
        assert not resources(g, kind)
        ccn = g.add("200", "global", "vpc.ccn", rid, source="vpc.DescribeCcns")
        link_next_hops(g)
        assert any(
            e["relationship"] == "ROUTES_TO" and e["target"] == ccn for e in g.edges.values()
        )
        assert g.nodes[ccn]["account"] == "200"
        return
    target = resources(g, kind)[0]
    assert target["region"] == region and target["status"] == "reference"
    assert icon_for(kind) != "unmapped.svg"


@pytest.mark.parametrize(
    "typ,rid", [("EIP", "0"), ("FUTURE", "unknown-one"), ("CCN", "0"), ("INTRANAT", "opaque-one")]
)
def test_sentinels_and_unmapped_gateways_remain_metadata(typ, rid):
    row = route(GatewayType=typ, GatewayId=rid)
    g, _ = run([table(RouteSet=[row])], [row])
    assert resources(g, "vpc.route")[0]["properties"]["GatewayId"] == rid
    assert not any(e["relationship"] == "ROUTES_TO" for e in g.edges.values())


def test_ipv6_zero_numeric_ids_do_not_collide():
    rows = [
        route(
            RouteItemId=None,
            RouteId=0,
            DestinationCidrBlock=None,
            DestinationIpv6CidrBlock=f"2001:db8:{i}::/64",
        )
        for i in (1, 2)
    ]
    g, _ = run([table(RouteSet=rows)], rows)
    assert len(resources(g, "vpc.route")) == 2


@pytest.mark.parametrize(
    "field,value",
    [
        ("DestinationCidrBlock", "10.0.0.1/24"),
        ("Enabled", 1),
        ("PublishedToVbc", "true"),
        ("RouteId", -1),
        ("RouteTableId", "rtb-wrong"),
        ("DestinationIpv6CidrBlock", "::/0"),
    ],
)
def test_invalid_embedded_route_page_adds_nothing(field, value):
    g, _ = run([table(RouteSet=[route(**{field: value})])])
    assert not g.nodes and g.coverage[0]["status"] == "error"


def test_wrong_parent_and_duplicate_associations_are_rejected():
    for associations in (
        [dict(RouteTableId="rtb-other", SubnetId="subnet-one")],
        [dict(SubnetId="subnet-one")] * 2,
    ):
        g, _ = run([table(AssociationSet=associations)])
        assert not g.nodes and g.coverage[0]["status"] == "error"


def test_route_listing_failure_keeps_embedded_inventory():
    def mutate(action, params, response):
        if action == "DescribeRouteList":
            raise CollectionError("UnauthorizedOperation")
        return response

    g, _ = run(mutate=mutate)
    assert len(resources(g, "vpc.route")) == 1 and g.coverage[-1]["status"] == "denied"
    assert resources(g, "vpc.route")[0]["sources"] == ["vpc.DescribeRouteTables"]


def test_changed_route_does_not_add_a_stale_second_gateway_edge():
    g, _ = run(routes=[route(GatewayId="nat-two")])
    assert g.coverage[-1]["error"] == "RouteInventoryChanged"
    assert [n["resource_id"] for n in resources(g, "vpc.nat")] == ["nat-one"]


def test_disappearing_embedded_route_marks_listing_partial():
    g, _ = run(routes=[])
    assert g.coverage[-1]["error"] == "RouteInventoryChanged"
    assert resources(g, "vpc.route")


def test_pagination_can_extend_an_embedded_route_set():
    rows = [route(RouteItemId=f"rti-{i}") for i in range(101)]
    g, calls = run([table(RouteSet=rows[:1])], rows)
    assert len(resources(g, "vpc.route")) == 101
    assert [p["Offset"] for a, p in calls if a == "DescribeRouteList"] == [0, 100]
    assert g.coverage[-1]["count"] == 101


def test_scoped_listing_rejects_wrong_parent_and_duplicates():
    for rows in ([route(RouteTableId="rtb-wrong", _parent="rtb-one")], [route(), route()]):
        g, _ = run([table(RouteSet=[])], rows)
        assert not resources(g, "vpc.route") and g.coverage[-1]["status"] == "error"


def address_inventory(g, account="100", region=REGION, vpc_id="vpc-one", suffix="one"):
    vid = g.add(account, region, "vpc.vpc", vpc_id)
    eni = g.add(account, region, "vpc.networkinterface", "eni-" + suffix)
    addr = g.add(account, region, "vpc.interfaceaddress", "eni-" + suffix + "/10.0.0.8")
    g.nodes[addr]["properties"]["address"] = "10.0.0.8"
    vm = g.add(account, region, "cvm.instance", "ins-" + suffix)
    for n in (eni, addr, vm):
        g.edge(n, vid, "IN_VPC")
    g.edge(eni, addr, "HAS_ADDRESS")
    g.edge(eni, vm, "ATTACHED_TO")
    return vm


def ip_route():
    return route(GatewayType="NORMAL_CVM", GatewayId="10.0.0.8")


def test_normal_cvm_ip_matches_only_collected_interface_and_instance():
    row = ip_route()
    g, _ = run([table(RouteSet=[row])], [row])
    vm = address_inventory(g)
    link_next_hops(g)
    node = resources(g, "vpc.route")[0]
    assert node["properties"]["next_hop_resolution"] == "matched-instance"
    assert any(
        e["source"] == node["id"] and e["target"] == vm and e["relationship"] == "ROUTES_TO"
        for e in g.edges.values()
    )
    assert not node["properties"]["reachability_verified"]


@pytest.mark.parametrize("boundary", ["account", "region", "vpc", "ambiguous"])
def test_ip_next_hop_resolution_rejects_other_scope_and_ambiguity(boundary):
    row = ip_route()
    g, _ = run([table(RouteSet=[row])], [row])
    address_inventory(
        g,
        account="200" if boundary == "account" else "100",
        region="ap-guangzhou" if boundary == "region" else REGION,
        vpc_id="vpc-other" if boundary == "vpc" else "vpc-one",
    )
    if boundary == "ambiguous":
        address_inventory(g, suffix="two")
    link_next_hops(g)
    assert resources(g, "vpc.route")[0]["properties"]["next_hop_resolution"] in {
        "unresolved",
        "ambiguous",
    }
    assert not any(e["relationship"] == "ROUTES_TO" for e in g.edges.values())


def test_ambiguous_ccn_owner_never_gets_a_route_edge():
    row = route(GatewayType="USER_CCN", GatewayId="ccn-one")
    g, _ = run([table(RouteSet=[row])], [row])
    for account in ("200", "300"):
        g.add(account, "global", "vpc.ccn", "ccn-one")
    link_next_hops(g)
    assert resources(g, "vpc.route")[0]["properties"]["next_hop_resolution"] == "ambiguous-owner"
    assert not any(e["relationship"] == "ROUTES_TO" for e in g.edges.values())


def test_independent_parent_denial_and_missing_route_totals():
    tables = [table(), table(RouteTableId="rtb-two", AssociationSet=[], RouteSet=[])]

    def mutate(action, params, response):
        if action == "DescribeRouteList" and params["Filters"][0]["Values"] == ["rtb-one"]:
            raise CollectionError("UnauthorizedOperation")
        return response

    g, _ = run(tables, routes=[route(RouteTableId="rtb-two")], mutate=mutate)
    assert len(resources(g, "vpc.route")) == 2
    assert [c["status"] for c in g.coverage] == ["complete", "denied", "complete"]

    def missing(action, params, response):
        if action == "DescribeRouteList":
            response.pop("TotalCount")
        return response

    g, _ = run(mutate=missing)
    assert g.coverage[-1]["status"] == "error"
    assert resources(g, "vpc.route")


def test_private_nat_gateway_identity_and_native_origin_state_are_preserved():
    row = route(GatewayType="INTRANAT", GatewayId="intranat-one", RouteType="CCN", Enabled=False)
    g, _ = run([table(RouteSet=[row])], [row])
    node = resources(g, "vpc.route")[0]
    assert node["properties"]["origin_resolution"] == "provider-ccn"
    assert node["properties"]["route_state_resolution"] == "disabled-reported"
    assert any(
        n["kind"] == "vpc.privatenat" and n["resource_id"] == "intranat-one"
        for n in g.nodes.values()
    )
    assert not any(n["kind"] == "vpc.internetgateway" for n in g.nodes.values())


def test_ccn_owner_proven_by_shared_attachment_can_resolve_reference_gateway():
    row = route(GatewayType="USER_CCN", GatewayId="ccn-shared")
    g, _ = run([table(RouteSet=[row])], [row])
    ccn = g.add("200", "global", "vpc.ccn", "ccn-shared", status="reference")
    aid = g.add("200", "global", "vpc.ccnattachment", "attachment")
    g.nodes[aid]["properties"].update(CcnUin="200", CcnId="ccn-shared")
    g.edge(ccn, aid, "HAS_ATTACHMENT")
    link_next_hops(g)
    assert any(e["relationship"] == "ROUTES_TO" and e["target"] == ccn for e in g.edges.values())
    g.nodes[aid]["properties"]["CcnUin"] = "300"
    link_next_hops(g)
    assert not any(e["relationship"] == "ROUTES_TO" for e in g.edges.values())
