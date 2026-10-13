from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.catalog import COLLECTORS
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.privatelink import collect, link, resource_pages
from tencent_cloud_cartography.transport import CollectionError

REGION = "eu-frankfurt"
SPECS = {s.kind: s for s in COLLECTORS if s.kind in {"vpc.endpoint", "vpc.endpointservice"}}


def endpoint(**values):
    return dict(
        dict(
            EndPointId="vpce-one",
            EndPointName="Consumer endpoint",
            VpcId="vpc-consumer",
            SubnetId="subnet-consumer",
            EndPointOwner="123456",
            ServiceVpcId="vpc-provider",
            EndPointServiceId="vpcsvc-one",
            EndPointVip="10.0.0.8",
            State="ACTIVE",
            GroupSet=["sg-one"],
        ),
        **values,
    )


def service(**values):
    return dict(
        dict(
            EndPointServiceId="vpcsvc-one",
            ServiceName="Provider service",
            VpcId="vpc-provider",
            ServiceOwner="789012",
            ServiceUin="200",
            ServiceType="CLB",
            ServiceInstanceId="lb-one",
            AutoAcceptFlag=False,
            EndPointCount=2,
            EndPointSet=[endpoint()],
            ServiceVip="10.1.0.8",
        ),
        **values,
    )


def run(endpoints=None, services=None, authorized=None, account="100", graph=None, mutate=None):
    graph, calls = graph or Graph(), []

    def call(product, action, **params):
        assert product == "vpc" and params["region"] == REGION
        calls.append((action, params))
        if action == "DescribeVpcEndPoint":
            rows, key = endpoints or [], "EndPointSet"
        else:
            key = "EndPointServiceSet"
            if params.get("IsListAuthorizedEndPointService"):
                assert "Filters" not in params
                rows = authorized or []
            else:
                typ = params["Filters"][0]["Values"][0]
                rows = [r for r in services or [] if r.get("ServiceType") == typ]
        rows = [r for r in rows if r.get("_family", "Ipv4") == params["IpAddressType"]]
        if params["IpAddressType"] == "DualStack":
            assert "Offset" not in params and "Limit" not in params
            offset, limit = int(params.get("NextToken", "0")), params["MaxResults"]
        else:
            offset, limit = params["Offset"], params["Limit"]
        response = {
            key: rows[offset : offset + limit],
            "TotalCount": len(rows),
            "RequestId": str(len(calls)),
        }
        if params["IpAddressType"] == "DualStack" and offset + limit < len(rows):
            response["NextToken"] = str(offset + limit)
        return mutate(action, params, response) if mutate else response

    runner = CollectorRunner(graph, SimpleNamespace(call=call), account, [REGION], lambda _: None)
    for spec in SPECS.values():
        collect(runner, spec, REGION)
    link(graph)
    return graph, calls


def resources(graph, kind):
    return [n for n in graph.nodes.values() if n["kind"] == kind]


def test_authorized_foreign_service_preserves_both_network_owners():
    g, calls = run([endpoint()], authorized=[service()])
    ep, svc = resources(g, "vpc.endpoint")[0], resources(g, "vpc.endpointservice")[0]
    assert ep["account"] == "100" and svc["account"] == "200"
    assert ep["properties"]["service_resolution"] == "matched"
    assert svc["properties"]["ServiceOwner"] == "789012"
    assert not svc["properties"]["AutoAcceptFlag"]
    assert svc["properties"]["endpoint_rows_truncated"]
    assert not ep["properties"]["connectivity_verified"]
    assert not any(n["account"] in {"123456", "789012"} for n in g.nodes.values())
    assert not any(
        n["account"] == "100" and n["resource_id"] == "vpc-provider" for n in g.nodes.values()
    )
    assert len(resources(g, "vpc.endpoint")) == 1
    assert any(
        e["relationship"] == "CONNECTS_TO_SERVICE" and e["target"] == svc["id"]
        for e in g.edges.values()
    )
    assert icon_for(ep["kind"]) == icon_for(svc["kind"]) == "en-private-link.svg"
    assert len(calls) == 18


def test_service_filters_cover_all_types_and_protocol_families():
    g, calls = run()
    pairs = {
        (p["IpAddressType"], p["Filters"][0]["Values"][0])
        for a, p in calls
        if a == "DescribeVpcEndPointService"
    }
    assert len(pairs) == 12
    assert len(g.coverage) == 15 and all(c["status"] == "empty" for c in g.coverage)


@pytest.mark.parametrize(
    "typ,rid,kind",
    [
        ("CLB", "lb-one", "clb.clb"),
        ("CDB", "cdb-one", "cdb.instance"),
        ("CRS", "crs-one", "redis.instance"),
        ("GWLB", "gwlb-one", "clb.gatewayloadbalancer"),
    ],
)
def test_backend_references_are_typed(typ, rid, kind):
    g, _ = run(services=[service(ServiceUin="100", ServiceType=typ, ServiceInstanceId=rid)])
    assert len(resources(g, kind)) == 1
    assert resources(g, kind)[0]["account"] == "100"


def test_unknown_backend_id_is_retained_without_invented_clb():
    g, _ = run(
        [endpoint()], authorized=[service(ServiceType="FUTURE", ServiceInstanceId="future-one")]
    )
    assert resources(g, "vpc.endpointservice")[0]["properties"]["ServiceInstanceId"] == "future-one"
    assert not resources(g, "clb.clb")
    assert icon_for("clb.gatewayloadbalancer") == "en-cloud-load-balancer.svg"


@pytest.mark.parametrize(
    "field,value",
    [
        ("ServiceUin", None),
        ("ServiceUin", 123),
        ("ServiceUin", "0"),
        ("EndPointServiceId", "vpcsvc-other"),
        ("VpcId", "subnet-wrong"),
        ("ServiceVip", "secret-not-an-ip"),
        ("AutoAcceptFlag", 1),
    ],
)
def test_invalid_authorized_service_never_creates_guessed_owner(field, value):
    g, _ = run([endpoint()], authorized=[service(**{field: value})])
    assert not resources(g, "vpc.endpointservice")
    assert resources(g, "vpc.endpoint")[0]["properties"]["service_resolution"] == "unresolved"
    assert any(c["status"] == "error" for c in g.coverage)


@pytest.mark.parametrize(
    "field,value",
    [
        ("EndPointId", "wrong"),
        ("GroupSet", "sg-one"),
        ("GroupSet", ["vpc-wrong"]),
        ("EndPointOwner", 123),
        ("EndPointVip", "fd00::8%en0"),
        ("ServiceVpcId", "not-a-vpc"),
    ],
)
def test_invalid_endpoint_page_is_atomic(field, value):
    g, _ = run([endpoint(EndPointId="vpce-valid"), endpoint(**{field: value})])
    assert not resources(g, "vpc.endpoint")
    assert g.coverage[0]["status"] == "error"


def test_owned_service_owner_mismatch_is_error():
    g, _ = run(services=[service()])
    assert not resources(g, "vpc.endpointservice")
    assert any(c.get("error") == "PrivateLinkOwnerMismatch" for c in g.coverage)


def test_multi_account_collection_links_without_authorized_lookup_result():
    g, _ = run([endpoint()])
    g, _ = run(services=[service()], account="200", graph=g)
    assert resources(g, "vpc.endpoint")[0]["properties"]["service_resolution"] == "matched"


@pytest.mark.parametrize("case", ["region", "vpc", "ambiguous"])
def test_service_match_rejects_wrong_scope_or_ambiguity(case):
    g, _ = run([endpoint()], authorized=[service()])
    svc = resources(g, "vpc.endpointservice")[0]
    g.edges = {k: e for k, e in g.edges.items() if e["relationship"] != "CONNECTS_TO_SERVICE"}
    if case == "region":
        svc["region"] = "ap-guangzhou"
    elif case == "vpc":
        svc["properties"]["VpcId"] = "vpc-wrong"
    else:
        n = g.add("300", REGION, "vpc.endpointservice", "vpcsvc-one")
        g.nodes[n]["properties"].update(svc["properties"])
    link(g)
    assert not any(e["relationship"] == "CONNECTS_TO_SERVICE" for e in g.edges.values())
    assert resources(g, "vpc.endpoint")[0]["properties"]["service_resolution"] != "matched"


@pytest.mark.parametrize("family", ["Ipv4", "DualStack"])
def test_pagination_preserves_family_and_advances(family):
    g, calls = run([endpoint(EndPointId=f"vpce-{i}", _family=family) for i in range(101)])
    assert len(resources(g, "vpc.endpoint")) == 101
    requests = [p for a, p in calls if a == "DescribeVpcEndPoint" and p["IpAddressType"] == family]
    assert len(requests) == 2
    assert requests[1].get("NextToken", requests[1].get("Offset")) in (100, "100")


def test_dualstack_follows_nonempty_token_even_after_short_page():
    responses = iter(
        [
            dict(EndPointSet=[endpoint()], TotalCount=2, NextToken="second"),
            dict(EndPointSet=[endpoint(EndPointId="vpce-two")], TotalCount=2),
        ]
    )
    rows = list(
        resource_pages(
            SimpleNamespace(call=lambda *a, **k: next(responses)),
            SPECS["vpc.endpoint"],
            REGION,
            {"IpAddressType": "DualStack"},
        )
    )
    assert len(rows) == 2


@pytest.mark.parametrize("bad", ["duplicate", "missing-total", "wrong-token", "premature-end"])
def test_bad_pages_record_incomplete_coverage(bad):
    def mutate(action, params, response):
        if action == "DescribeVpcEndPoint" and params["IpAddressType"] == "DualStack":
            if bad == "duplicate":
                response["EndPointSet"] *= 2
                response["TotalCount"] *= 2
            if bad == "missing-total":
                response.pop("TotalCount")
            if bad == "wrong-token":
                response["NextToken"] = 3
            if bad == "premature-end":
                response["TotalCount"] += 1
        return response

    g, _ = run([endpoint(_family="DualStack")], mutate=mutate)
    assert any(c["status"] == "error" for c in g.coverage)
    assert not resources(g, "vpc.endpoint")


def test_one_denied_service_type_does_not_hide_other_types():
    def mutate(action, params, response):
        if params.get("Filters", [{}])[0].get("Values") == ["CLB"]:
            raise CollectionError("UnauthorizedOperation")
        return response

    g, _ = run(
        services=[service(ServiceUin="100", ServiceType="CDB", ServiceInstanceId="cdb-one")],
        mutate=mutate,
    )
    assert len(resources(g, "cdb.instance")) == 1
    assert any(c["status"] == "denied" for c in g.coverage)
