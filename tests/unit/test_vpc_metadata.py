import json
from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.catalog import COLLECTORS
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.topology import topology
from tencent_cloud_cartography.transport import CollectionError
from tencent_cloud_cartography.vpc import collect

REGION = "eu-frankfurt"
SPECS = {s.kind: s for s in COLLECTORS if s.kind in {"vpc.vpc", "vpc.subnet"}}


def vpc(**values):
    return dict(
        dict(
            VpcId="vpc-one",
            VpcName="Application network",
            CidrBlock="10.0.0.0/16",
            Ipv6CidrBlock="fd00:0:0:0::/56",
            IsDefault=False,
            EnableDhcp=True,
            DnsServerSet=["10.0.0.2", "fd00::2"],
            DomainName="internal.example",
            DhcpOptionsId="dopt-one",
            Ipv6CidrBlockSet=[dict(IPv6CidrBlock="fd00::/56", ISPType="BGP", AddressType="ULA")],
            AssistantCidrSet=[
                dict(
                    VpcId="vpc-one",
                    CidrBlock="10.2.0.0/16",
                    AssistantType=1,
                    SubnetSet=[
                        dict(VpcId="vpc-one", SubnetId="subnet-one", CidrBlock="10.2.0.0/24")
                    ],
                )
            ],
        ),
        **values,
    )


def subnet(**values):
    return dict(
        dict(
            SubnetId="subnet-one",
            SubnetName="Application subnet",
            VpcId="vpc-one",
            CidrBlock="10.2.0.0/24",
            Zone="eu-frankfurt-1",
            RouteTableId="rtb-one",
            NetworkAclId="acl-one",
            IsDefault=False,
            AvailableIpAddressCount=0,
            TotalIpAddressCount=253,
            IsRemoteVpcSnat=True,
        ),
        **values,
    )


def run(vpcs=None, subnets=None, mutate=None, account="100"):
    graph, calls = Graph(), []

    def call(service, action, **params):
        assert service == "vpc" and params["region"] == REGION
        calls.append((action, params))
        rows, key = (
            (vpcs or [], "VpcSet") if action == "DescribeVpcs" else (subnets or [], "SubnetSet")
        )
        response = {
            key: rows[params["Offset"] : params["Offset"] + params["Limit"]],
            "TotalCount": len(rows),
            "RequestId": str(len(calls)),
        }
        return mutate(action, response) if mutate else response

    runner = CollectorRunner(graph, SimpleNamespace(call=call), account, [REGION], lambda _: None)
    for spec in SPECS.values():
        collect(runner, spec, REGION)
    return graph, calls


def resources(graph, kind):
    return [n for n in graph.nodes.values() if n["kind"] == kind]


def test_primary_auxiliary_and_provider_ipv6_cidrs_preserve_explicit_containment():
    g, _ = run([vpc()], [subnet()])
    blocks = resources(g, "vpc.cidr")
    assert len(blocks) == 3
    assert all(icon_for(n["kind"]) == "en-virtual-private-cloud.svg" for n in blocks)
    ipv6 = next(n for n in blocks if n["properties"]["ip_version"] == 6)
    assert json.loads(ipv6["properties"]["roles"]) == ["primary_ipv6", "provider_ipv6"]
    assert ipv6["properties"]["AddressType"] == "ULA"
    parent = resources(g, "vpc.vpc")[0]
    assert not any(
        e["source"] == parent["id"] and e["relationship"] == "IN_SUBNET" for e in g.edges.values()
    )
    assert any(e["relationship"] == "HAS_SUBNET" for e in g.edges.values())
    assert json.loads(parent["properties"]["DnsServerSet"]) == ["10.0.0.2", "fd00::2"]
    assert parent["properties"]["EnableDhcp"] and not parent["properties"]["IsDefault"]
    assert parent["properties"]["DhcpOptionsId"] == "dopt-one"
    sub = resources(g, "vpc.subnet")[0]
    assert sub["properties"]["AvailableIpAddressCount"] == 0
    assert sub["properties"]["zone"] == "eu-frankfurt-1"
    assert {"IN_VPC", "USES_ROUTE_TABLE", "USES_NETWORK_ACL"} <= {
        e["relationship"] for e in g.edges.values() if e["source"] == sub["id"]
    }
    arch = topology(g.snapshot())
    assert not ({n["id"] for n in blocks} & {e["data"]["id"] for e in arch["elements"]})
    full = topology(g.snapshot(), view="full")
    assert full["stats"]["relationships"] == len(g.edges)
    assert {n["id"] for n in blocks} <= {e["data"]["id"] for e in full["elements"]}


def test_same_cidr_in_separate_vpcs_remains_separate():
    g, _ = run([vpc(AssistantCidrSet=[]), vpc(VpcId="vpc-two", AssistantCidrSet=[])])
    assert len(resources(g, "vpc.cidr")) == 4
    assert len({n["resource_id"] for n in resources(g, "vpc.cidr")}) == 4


def test_ipv6_only_network_does_not_fabricate_ipv4():
    g, _ = run([vpc(CidrBlock="", AssistantCidrSet=[], StackType="IPv6Only")])
    blocks = resources(g, "vpc.cidr")
    assert len(blocks) == 1 and blocks[0]["properties"]["ip_version"] == 6


@pytest.mark.parametrize(
    "field,value",
    [
        ("CidrBlock", "10.0.0.1/16"),
        ("CidrBlock", "fd00::/64"),
        ("Ipv6CidrBlock", "fd00::%en0/64"),
        ("IsDefault", 1),
        ("DnsServerSet", "10.0.0.2"),
        ("DnsServerSet", ["not-an-ip"]),
        ("AssistantCidrSet", {}),
        ("Ipv6CidrBlockSet", [{}]),
    ],
)
def test_invalid_network_page_adds_no_nodes(field, value):
    g, _ = run([vpc(VpcId="vpc-valid", AssistantCidrSet=[]), vpc(**{field: value})])
    assert not g.nodes and g.coverage[0]["status"] == "error"


@pytest.mark.parametrize(
    "case", ["parent", "subnet-parent", "subnet-cidr", "duplicate", "duplicate-subnet"]
)
def test_assistant_cidr_rejects_wrong_parent_or_membership(case):
    raw = vpc()
    assistant = raw["AssistantCidrSet"][0]
    if case == "parent":
        assistant["VpcId"] = "vpc-wrong"
    if case == "subnet-parent":
        assistant["SubnetSet"][0]["VpcId"] = "vpc-wrong"
    if case == "subnet-cidr":
        assistant["SubnetSet"][0]["CidrBlock"] = "10.99.0.0/24"
    if case == "duplicate":
        raw["AssistantCidrSet"] *= 2
    if case == "duplicate-subnet":
        assistant["SubnetSet"] *= 2
    g, _ = run([raw])
    assert not g.nodes and g.coverage[0]["status"] == "error"


@pytest.mark.parametrize(
    "field,value",
    [
        ("VpcId", "bad"),
        ("Zone", "ap-guangzhou-1"),
        ("AvailableIpAddressCount", -1),
        ("NetworkAclId", "sg-wrong"),
        ("RouteTableId", "vpc-wrong"),
        ("CidrBlock", "10.0.1.1/24"),
    ],
)
def test_invalid_subnet_never_creates_wrong_placement(field, value):
    g, _ = run(subnets=[subnet(**{field: value})])
    assert not g.nodes and g.coverage[-1]["status"] == "error"


def test_multiple_ipv6_provider_cidrs_are_not_collapsed():
    raw = vpc(AssistantCidrSet=[])
    raw["Ipv6CidrBlockSet"].append(
        dict(IPv6CidrBlock="2001:db8::/56", ISPType="CMCC", AddressType="GUA")
    )
    g, _ = run([raw])
    assert len([n for n in resources(g, "vpc.cidr") if n["properties"]["ip_version"] == 6]) == 2


def test_page_counts_and_duplicate_ids_are_checked():
    g, calls = run([vpc(VpcId=f"vpc-{i}", AssistantCidrSet=[]) for i in range(101)])
    assert len(resources(g, "vpc.vpc")) == 101
    assert [p["Offset"] for a, p in calls if a == "DescribeVpcs"] == [0, 100]
    g, _ = run([vpc(), vpc()])
    assert not g.nodes and g.coverage[0]["error"] == "DuplicateVpcResource"


def test_missing_total_and_denied_vpc_do_not_hide_valid_subnet():
    def mutate(action, response):
        if action == "DescribeVpcs":
            raise CollectionError("UnauthorizedOperation")
        return response

    g, _ = run([vpc()], [subnet()], mutate=mutate)
    assert resources(g, "vpc.subnet")[0]["status"] == "enriched"
    assert resources(g, "vpc.vpc")[0]["status"] == "reference"
    assert g.coverage[0]["status"] == "denied"

    def missing(action, response):
        response.pop("TotalCount")
        return response

    g, _ = run([vpc()], mutate=missing)
    assert not g.nodes and all(c["status"] == "error" for c in g.coverage)
