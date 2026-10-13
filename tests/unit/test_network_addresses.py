import copy
from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.catalog import COLLECTORS
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.network_addresses import collect, link

REGION = "eu-frankfurt"
SPECS = {s.kind: s for s in COLLECTORS if s.kind in {"vpc.networkinterface", "vpc.eip"}}


def eni(id="eni-test", vpc="vpc-test"):
    return dict(
        NetworkInterfaceId=id,
        NetworkInterfaceName="Application ENI",
        VpcId=vpc,
        SubnetId="subnet-test",
        Business="cvm",
        Primary=True,
        Zone="eu-frankfurt-1",
        GroupSet=["sg-test"],
        NetworkInterfaceState="INUSE",
        Attachment=dict(
            InstanceId="ins-test", InstanceAccountId="opaque-provider-owner", DeviceIndex=0
        ),
        PrivateIpAddressSet=[
            dict(
                PrivateIpAddress="10.0.0.8",
                Primary=True,
                PublicIpAddress="203.0.113.8",
                AddressId="eip-test",
                IsWanIpBlocked=False,
            )
        ],
        Ipv6AddressSet=[dict(Address="fd00:0:0:0:0:0:0:8", Primary=False, AddressType="ULA")],
    )


def eip():
    return dict(
        AddressId="eip-test",
        AddressIp="203.0.113.8",
        PrivateAddressIp="10.0.0.8",
        NetworkInterfaceId="eni-test",
        AddressStatus="BIND",
        InstanceId="ins-test",
        InstanceType="CVM",
        IsBlocked=False,
    )


def run(interfaces=None, eips=None, mutate=None):
    g, calls = Graph(), []

    def call(service, action, **params):
        calls.append((action, params))
        assert service == "vpc" and params["region"] == REGION
        rows = interfaces or [] if action == "DescribeNetworkInterfaces" else eips or []
        result = {
            "NetworkInterfaceSet" if action == "DescribeNetworkInterfaces" else "AddressSet": rows[
                params["Offset"] : params["Offset"] + params["Limit"]
            ],
            "TotalCount": len(rows),
            "RequestId": str(len(calls)),
        }
        return mutate(result) if mutate else result

    runner = CollectorRunner(g, SimpleNamespace(call=call), "100", [REGION], lambda _: None)
    for spec in SPECS.values():
        collect(runner, spec, REGION)
    return g, calls


def endpoint(g, account="100", vpc="vpc-test", region=REGION):
    vid = g.add(account, region, "vpc.vpc", vpc)
    instance = g.add(
        account, region, "cvm.instance", "ins-test", "Worker", source="cvm.DescribeInstances"
    )
    g.edge(instance, vid, "IN_VPC", "cvm.DescribeInstances")
    lb = g.add(account, region, "clb.clb", "lb-test")
    g.edge(lb, vid, "IN_VPC", "clb.DescribeLoadBalancersDetail")
    listener = g.add(account, region, "clb.listener", "lb-test/lbl-test")
    target = g.add(account, region, "clb.target", "lb-test/10.0.0.8:443", "10.0.0.8")
    g.edge(lb, listener, "HAS_LISTENER")
    g.edge(listener, target, "FORWARDS_TO")
    return instance, target


def test_interface_address_identity_properties_and_eip_target_resolution():
    g, _ = run([eni()], [eip()])
    instance, target = endpoint(g)
    link(g)
    addresses = [n for n in g.nodes.values() if n["kind"] == "vpc.interfaceaddress"]
    assert len(addresses) == 2
    assert {n["properties"]["address"] for n in addresses} == {"10.0.0.8", "fd00::8"}
    assert all(n["account"] == "100" and n["region"] == REGION for n in addresses)
    assert all(icon_for(n["kind"]) == "en-elastic-network-interface.svg" for n in addresses)
    assert any(
        e["source"] == target
        and e["target"] == instance
        and e["relationship"] == "RESOLVES_TO_INSTANCE"
        for e in g.edges.values()
    )
    assert any(e["relationship"] == "BINDS_ADDRESS" for e in g.edges.values())
    en = next(n for n in g.nodes.values() if n["kind"] == "vpc.networkinterface")
    assert en["properties"]["attachment_InstanceAccountId"] == "opaque-provider-owner"
    assert en["properties"]["attachment_resolution"] == "matched-collected-instance-and-vpc"
    assert not g.nodes[target]["properties"]["reachability_verified"]


@pytest.mark.parametrize("scope", ["account", "region", "vpc"])
def test_equal_ip_in_different_scope_never_resolves(scope):
    g, _ = run([eni()])
    _, target = endpoint(
        g,
        account="200" if scope == "account" else "100",
        region="ap-guangzhou" if scope == "region" else REGION,
        vpc="vpc-other" if scope == "vpc" else "vpc-test",
    )
    link(g)
    assert g.nodes[target]["properties"]["address_resolution"] == "unresolved"
    assert not any(e["relationship"] == "RESOLVES_TO_INSTANCE" for e in g.edges.values())


def test_duplicate_ip_in_one_vpc_remains_ambiguous():
    g, _ = run([eni(), eni("eni-second")])
    _, target = endpoint(g)
    link(g)
    assert g.nodes[target]["properties"]["address_resolution"] == "ambiguous"
    assert not any(
        e["source"] == target and e["relationship"] == "MATCHES_INTERFACE_ADDRESS"
        for e in g.edges.values()
    )


def test_non_cvm_attachment_does_not_resolve_to_cvm():
    raw = eni()
    raw["Business"] = "eks"
    g, _ = run([raw])
    _, target = endpoint(g)
    link(g)
    assert g.nodes[target]["properties"]["address_resolution"] == "matched"
    assert not any(e["relationship"] == "RESOLVES_TO_INSTANCE" for e in g.edges.values())


@pytest.mark.parametrize("field,value", [("AddressIp", "203.0.113.99"), ("AddressId", "eip-other")])
def test_conflicting_eip_metadata_is_not_silently_reconciled(field, value):
    raw = eip()
    raw[field] = value
    g, _ = run([eni()], [raw])
    link(g)
    node = next(n for n in g.nodes.values() if n["kind"] == "vpc.eip" and n["status"] == "enriched")
    assert node["properties"]["address_binding_resolution"] == "conflicting-metadata"
    assert not any(
        e["source"] == node["id"] and e["relationship"] == "BINDS_ADDRESS" for e in g.edges.values()
    )


def test_nat_eip_is_not_a_cvm_and_unknown_target_type_is_retained():
    raw = eip()
    raw.update(InstanceId="nat-test", InstanceType="NAT", NetworkInterfaceId=None)
    g, _ = run(eips=[raw])
    assert any(n["kind"] == "vpc.nat" for n in g.nodes.values())
    assert not any(n["kind"] == "cvm.instance" for n in g.nodes.values())
    raw["InstanceType"] = "FUTURE"
    g, _ = run(eips=[raw])
    assert (
        len(g.nodes) == 1 and next(iter(g.nodes.values()))["properties"]["InstanceId"] == "nat-test"
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("NetworkInterfaceId", "bad"),
        ("Primary", 1),
        ("Zone", "ap-guangzhou-1"),
        ("PrivateIpAddressSet", None),
        ("GroupSet", "sg-test"),
        ("Attachment", []),
        ("PrivateIpAddressSet", [{"PrivateIpAddress": "bad"}]),
        ("PrivateIpAddressSet", [{"PrivateIpAddress": "::1"}]),
        ("Ipv6AddressSet", [{"Address": "fe80::1%en0"}]),
    ],
)
def test_invalid_interface_page_adds_no_nodes(field, value):
    raw = eni()
    raw[field] = value
    g, _ = run([raw])
    assert not g.nodes and g.coverage[-1]["status"] == "error"


def test_ipv6_response_alias_merge_and_conflicts():
    raw = eni()
    raw["Ipv6Addresses"] = copy.deepcopy(raw["Ipv6AddressSet"])
    g, _ = run([raw])
    assert len([n for n in g.nodes.values() if n["kind"] == "vpc.interfaceaddress"]) == 2
    raw["Ipv6Addresses"][0]["Primary"] = True
    g, _ = run([raw])
    assert not g.nodes and g.coverage[-1]["status"] == "error"


def test_duplicate_address_and_required_total():
    raw = eni()
    raw["PrivateIpAddressSet"] *= 2
    g, _ = run([raw])
    assert not g.nodes
    g, _ = run([eni()], mutate=lambda r: {**r, "TotalCount": None})
    assert not g.nodes
    assert g.coverage[-1]["error"] == "InvalidTotal"


def test_pagination_and_duplicate_interface_id():
    g, calls = run([eni(f"eni-{i}") for i in range(101)])
    assert [p["Offset"] for a, p in calls if a == "DescribeNetworkInterfaces"] == [0, 100]
    assert g.coverage[-1]["count"] == 101
    g, _ = run([eni(), eni()])
    assert not g.nodes


def test_unavailable_ipv6_metadata_remains_explicit():
    raw = eni()
    raw["Ipv6AddressSet"] = None
    g, _ = run([raw])
    node = next(n for n in g.nodes.values() if n["kind"] == "vpc.networkinterface")
    assert node["properties"]["Ipv6AddressSet_available"] is False
    assert len([n for n in g.nodes.values() if n["kind"] == "vpc.interfaceaddress"]) == 1
