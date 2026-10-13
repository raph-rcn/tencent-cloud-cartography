import json
from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.catalog import COLLECTORS
from tencent_cloud_cartography.ccn import collect
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.transport import CollectionError

SPEC = next(s for s in COLLECTORS if s.kind == "vpc.ccn")


def member(**overrides):
    return dict(
        dict(
            CcnId="ccn-one",
            CcnUin="100",
            InstanceUin="200",
            InstanceRegion="eu-frankfurt",
            InstanceType="VPC",
            InstanceId="vpc-one",
            State="ACTIVE",
            CidrBlock=["10.0.0.0/24", "fd00::/64"],
            RouteTableId="ccnrt-one",
        ),
        **overrides,
    )


def run(rows=None, networks=None, mutate=None, denied=None):
    graph, calls = Graph(), []
    networks = networks if networks is not None else [dict(CcnId="ccn-one", State="AVAILABLE")]

    def call(service, action, **params):
        assert service == "vpc" and params["region"] == "global"
        calls.append((action, params))
        if action == "DescribeCcns":
            records, key = networks, "CcnSet"
        else:
            assert action == "DescribeCcnAttachedInstances"
            if params["CcnId"] == denied:
                raise CollectionError("UnauthorizedOperation")
            records = [r for r in rows or [] if r.get("_parent", "ccn-one") == params["CcnId"]]
            key = "InstanceSet"
        response = {
            key: records[params["Offset"] : params["Offset"] + params["Limit"]],
            "TotalCount": len(records),
            "RequestId": str(len(calls)),
        }
        return mutate(action, response) if mutate else response

    runner = CollectorRunner(
        graph, SimpleNamespace(call=call), "100", ["eu-frankfurt"], lambda _: None
    )
    collect(runner, SPEC)
    return graph, calls


def attachments(graph):
    return [n for n in graph.nodes.values() if n["kind"] == "vpc.ccnattachment"]


def test_explicit_owner_region_and_network_metadata():
    graph, calls = run(
        [member()],
        networks=[dict(CcnId="ccn-one", CcnName="Backbone", RouteECMPFlag=True, RouteTableCount=2)],
    )
    node = attachments(graph)[0]
    target = next(n for n in graph.nodes.values() if n["kind"] == "vpc.vpc")
    assert (target["account"], target["region"], target["resource_id"]) == (
        "200",
        "eu-frankfurt",
        "vpc-one",
    )
    assert target["status"] == "reference"
    assert node["account"] == "100" and node["region"] == "global"
    assert node["properties"]["active_reported"]
    assert not node["properties"]["connectivity_verified"]
    assert json.loads(node["properties"]["CidrBlock"]) == ["10.0.0.0/24", "fd00::/64"]
    network = next(n for n in graph.nodes.values() if n["kind"] == "vpc.ccn")
    assert network["properties"]["RouteECMPFlag"] is True
    assert network["properties"]["RouteTableCount"] == 2
    assert {e["relationship"] for e in graph.edges.values()} == {
        "HAS_ATTACHMENT",
        "ATTACHED_NETWORK",
    }
    assert all(icon_for(n["kind"]) == "en-cloud-connect-network.svg" for n in [node, network])
    assert calls[1][1]["CcnId"] == "ccn-one"


@pytest.mark.parametrize("state", ["PENDING", "DELETED", "DETACHFAILED"])
def test_inactive_association_is_preserved_without_connectivity_claim(state):
    graph, _ = run([member(State=state)])
    props = attachments(graph)[0]["properties"]
    assert props["state"] == state and not props["active_reported"]
    assert not props["connectivity_verified"] and len(graph.edges) == 2


@pytest.mark.parametrize(
    "field,value",
    [
        ("CcnId", "ccn-wrong"),
        ("CcnUin", "200"),
        ("CcnUin", None),
        ("InstanceUin", None),
        ("InstanceUin", 200),
        ("InstanceUin", "0"),
        ("InstanceRegion", "global"),
        ("InstanceId", "subnet-wrong"),
        ("CidrBlock", "10.0.0.0/24"),
        ("CidrBlock", ["10.0.0.1/24"]),
        ("CidrBlock", ["invalid"]),
        ("RouteTableId", "rtb-wrong"),
    ],
)
def test_invalid_page_never_adds_partial_attachment_rows(field, value):
    graph, _ = run([member(InstanceId="vpc-valid"), member(**{field: value})])
    assert not attachments(graph)
    assert len(graph.nodes) == 1
    assert graph.coverage[-1]["status"] == "error"


def test_unknown_provider_type_is_metadata_only():
    graph, _ = run([member(InstanceType="FUTURE", InstanceId="future-1")])
    assert len(graph.nodes) == 2 and len(graph.edges) == 1
    assert attachments(graph)[0]["properties"]["InstanceType"] == "FUTURE"


def test_identity_qualifies_type_owner_and_region():
    graph, _ = run(
        [
            member(),
            member(InstanceUin="300"),
            member(InstanceRegion="ap-guangzhou"),
            member(InstanceType="BMVPC"),
        ]
    )
    assert len(attachments(graph)) == 4
    assert len({n["resource_id"] for n in attachments(graph)}) == 4


def test_direct_connect_has_provider_specific_reference():
    graph, _ = run([member(InstanceType="DIRECTCONNECT", InstanceId="dcg-one")])
    assert any(n["kind"] == "vpc.directconnectgateway" for n in graph.nodes.values())


def test_duplicate_page_rejected():
    graph, _ = run([member(), member()])
    assert not attachments(graph)
    assert graph.coverage[-1]["error"] == "DuplicateCcnAttachment"


def test_pagination_keeps_explicit_parent_and_request_ids():
    graph, calls = run([member(InstanceId=f"vpc-{i}") for i in range(101)])
    assert len(attachments(graph)) == 101
    assert [p["Offset"] for a, p in calls if a == "DescribeCcnAttachedInstances"] == [0, 100]
    assert graph.coverage[-1]["count"] == 101
    assert len(graph.coverage[-1]["request_ids"]) == 2


@pytest.mark.parametrize("action", ["DescribeCcns", "DescribeCcnAttachedInstances"])
def test_missing_total_is_coverage_error(action):
    def mutate(current, response):
        if current == action:
            response.pop("TotalCount")
        return response

    graph, _ = run([member()], mutate=mutate)
    assert graph.coverage[-1]["status"] == "error"
    assert not attachments(graph)


def test_denied_parent_does_not_discard_another_network():
    graph, _ = run(
        [member(CcnId="ccn-two", _parent="ccn-two")],
        networks=[dict(CcnId="ccn-one"), dict(CcnId="ccn-two")],
        denied="ccn-one",
    )
    assert len(attachments(graph)) == 1
    assert [c["status"] for c in graph.coverage] == ["complete", "denied", "complete"]


@pytest.mark.parametrize(
    "raw",
    [
        dict(CcnId="wrong"),
        dict(CcnId="ccn-one", RouteECMPFlag=1),
        dict(CcnId="ccn-one", InstanceCount=-1),
    ],
)
def test_invalid_network_is_not_enriched(raw):
    graph, _ = run(networks=[raw])
    assert not graph.nodes and graph.coverage[0]["status"] == "error"
