"""Provider response contracts and negative ownership/scope controls."""

import json
from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.catalog import ALLOWED_ACTIONS, COLLECTORS
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.exposure import analyze
from tencent_cloud_cartography.model import Graph, stable_id
from tencent_cloud_cartography.network_parity import (
    collect,
    cross_targets,
    endpoint_permissions,
    link,
    security_group_metadata,
    shared_ccn,
    simple_networks,
)
from tencent_cloud_cartography.permissions import analyze_snapshot
from tencent_cloud_cartography.transport import CollectionError

REGION = "eu-frankfurt"


def add(g, kind, rid, account="100", region=REGION, **props):
    nid = g.add(account, region, kind, rid, source="fixture")
    g.nodes[nid]["properties"].update(props)
    return g.nodes[nid]


def runner(g, call):
    def guarded(service, action, region=None, **params):
        assert (service, action) in ALLOWED_ACTIONS
        return call(service, action, region, params)

    return CollectorRunner(g, SimpleNamespace(call=guarded), "100", [REGION], lambda _: None)


def relations(g, relation):
    return [e for e in g.edges.values() if e["relationship"] == relation]


def cross_fixture(account="200", region="ap-singapore"):
    g = Graph()
    vpc = add(g, "vpc.vpc", "vpc-local")
    lb = add(g, "clb.clb", "lb-one", VpcId="vpc-local", Forward=1)
    listener = add(g, "clb.listener", "lb-one/lbl-one", ListenerId="lbl-one")
    target = add(g, "clb.target", "target", TargetAddress="10.1.0.8")
    remote = add(g, "vpc.vpc", "vpc-remote", account, region)
    eni = add(
        g,
        "vpc.networkinterface",
        "eni-remote",
        account,
        region,
        VpcId="vpc-remote",
        attachment_InstanceId="ins-remote",
        Business="cvm",
    )
    address = add(
        g,
        "vpc.interfaceaddress",
        "eni-remote/10.1.0.8",
        account,
        region,
        NetworkInterfaceId="eni-remote",
        address="10.1.0.8",
        VpcId="vpc-remote",
    )
    instance = add(g, "cvm.instance", "ins-remote", account, region)
    for node in (eni, address, instance):
        g.edge(node["id"], remote["id"], "IN_VPC")
    for a, b, relation in (
        (lb, vpc, "IN_VPC"),
        (lb, listener, "HAS_LISTENER"),
        (listener, target, "FORWARDS_TO"),
        (eni, address, "HAS_ADDRESS"),
        (eni, instance, "ATTACHED_TO"),
    ):
        g.edge(a["id"], b["id"], relation)

    def call(service, action, region, params):
        assert (service, action, region) == ("clb", "DescribeCrossTargets", REGION)
        assert params["Filters"] == [
            {"Name": "vpc-id", "Values": ["vpc-local"]},
            {"Name": "listener-id", "Values": ["lbl-one"]},
        ]
        return dict(
            TotalCount=1,
            RequestId="cross",
            CrossTargetSet=[
                dict(
                    LocalVpcId="vpc-local",
                    VpcId="vpc-remote",
                    IP="10.1.0.8",
                    Region=eni["region"],
                    EniId="eni-remote",
                    InstanceId="ins-remote",
                    Environment="must-not-retain",
                )
            ],
        )

    cross_targets(runner(g, call), lb)
    return g, dict(
        lb=lb,
        listener=listener,
        target=target,
        eni=eni,
        address=address,
        instance=instance,
        vpc=remote,
    )


@pytest.mark.parametrize(
    "account,region",
    [("100", REGION), ("100", "ap-singapore"), ("200", REGION), ("200", "ap-singapore")],
)
def test_cross_targets_require_corroborated_owner_region_vpc_eni_and_address(account, region):
    g, n = cross_fixture(account, region)
    link(g)
    analyze(g)
    assert {e["target"] for e in relations(g, "EXPOSE")} == {
        n[k]["id"] for k in ("eni", "address", "instance")
    }
    assert all(
        not row["properties"]["reachability_verified"]
        for row in g.nodes.values()
        if row["kind"] == "clb.exposurepath"
    )
    assert "must-not-retain" not in g.dump()
    before = g.dump()
    link(g)
    analyze(g)
    assert g.dump() == before
    assert analyze_snapshot(g.snapshot())["edges"] == list(g.edges.values())


@pytest.mark.parametrize(
    "mutation",
    [
        "eni-vpc",
        "address-vpc",
        "attachment",
        "eni-reference",
        "address-reference",
        "missing-address-edge",
        "missing-vpc-edge",
        "wrong-listener",
        "wrong-lb",
        "missing-evidence-edge",
        "conflicting-target-id",
        "duplicate-owner",
    ],
)
def test_cross_target_negative_controls_never_expose(mutation):
    g, n = cross_fixture()
    evidence = next(row for row in g.nodes.values() if row["kind"] == "clb.crosstarget")
    if mutation == "eni-vpc":
        n["eni"]["properties"]["VpcId"] = "vpc-wrong"
    elif mutation == "address-vpc":
        n["address"]["properties"]["VpcId"] = "vpc-wrong"
    elif mutation == "attachment":
        n["eni"]["properties"]["attachment_InstanceId"] = "ins-wrong"
    elif mutation.endswith("-reference"):
        n[mutation.split("-")[0]]["status"] = "reference"
    elif mutation == "wrong-listener":
        evidence["properties"]["ListenerId"] = "lbl-wrong"
    elif mutation == "wrong-lb":
        evidence["properties"]["LoadBalancerId"] = "lb-wrong"
    elif mutation == "conflicting-target-id":
        n["target"]["properties"]["TargetId"] = "eni-wrong"
    elif mutation == "duplicate-owner":
        other_vpc = add(g, "vpc.vpc", "vpc-remote", "300", n["eni"]["region"])
        other_eni = add(
            g,
            "vpc.networkinterface",
            "eni-remote",
            "300",
            n["eni"]["region"],
            **n["eni"]["properties"],
        )
        other_addr = add(
            g,
            "vpc.interfaceaddress",
            "eni-remote/10.1.0.8",
            "300",
            n["eni"]["region"],
            **n["address"]["properties"],
        )
        for node in (other_eni, other_addr):
            g.edge(node["id"], other_vpc["id"], "IN_VPC")
        g.edge(other_eni["id"], other_addr["id"], "HAS_ADDRESS")
    else:
        relationship = {
            "missing-address-edge": "HAS_ADDRESS",
            "missing-vpc-edge": "IN_VPC",
            "missing-evidence-edge": "HAS_CROSS_TARGET_METADATA",
        }[mutation]
        source = n["eni"]["id"] if mutation != "missing-evidence-edge" else n["listener"]["id"]
        g.edges = {
            k: e
            for k, e in g.edges.items()
            if not (e["source"] == source and e["relationship"] == relationship)
        }
    link(g)
    analyze(g)
    assert not relations(g, "EXPOSE")
    assert g.snapshot()["status"] == "partial"


def test_offline_exposure_does_not_trust_stale_cross_corroboration_edges():
    g, n = cross_fixture()
    link(g)
    analyze(g)
    n["eni"]["properties"]["attachment_InstanceId"] = "ins-changed"
    analyze(g)
    assert not relations(g, "EXPOSE")


def test_cross_target_queries_and_resolution_are_rule_specific():
    g, n = cross_fixture()
    # Replace the listener-level fixture evidence with rule-scoped API results.
    obsolete = {node["id"] for node in g.nodes.values() if node["kind"] == "clb.crosstarget"}
    g.nodes = {k: node for k, node in g.nodes.items() if k not in obsolete}
    g.edges = {
        k: e
        for k, e in g.edges.items()
        if e["target"] not in obsolete and e["relationship"] != "FORWARDS_TO"
    }
    rules = [
        add(g, "clb.rule", "lb-one/lbl-one/loc-" + name, LocationId="loc-" + name)
        for name in ("one", "two")
    ]
    for rule in rules:
        g.edge(n["listener"]["id"], rule["id"], "HAS_RULE")
        g.edge(rule["id"], n["target"]["id"], "FORWARDS_TO")
    queried = []

    def call(service, action, region, params):
        loc = params["Filters"][-1]
        assert loc["Name"] == "location-id"
        queried.extend(loc["Values"])
        rows = (
            []
            if loc["Values"] == ["loc-two"]
            else [
                dict(
                    LocalVpcId="vpc-local",
                    VpcId="vpc-remote",
                    IP="10.1.0.8",
                    Region="ap-singapore",
                    EniId="eni-remote",
                    InstanceId="ins-remote",
                )
            ]
        )
        return dict(CrossTargetSet=rows, TotalCount=len(rows))

    cross_targets(runner(g, call), n["lb"])
    link(g)
    analyze(g)
    assert queried == ["loc-one", "loc-two"]
    paths = [node for node in g.nodes.values() if node["kind"] == "clb.exposurepath"]
    assert len(paths) == 3 and {node["properties"]["frontend_id"] for node in paths} == {
        rules[0]["resource_id"]
    }
    assert any(row.get("error") == "UnresolvedClbBackend" for row in g.coverage)


@pytest.mark.parametrize(
    "mutation", [None, "wrong-region", "wrong-vpc", "missing-id", "duplicate-owner", "uncollected"]
)
def test_legacy_cross_region_binding_resolves_only_exact_collected_cvm_identity(mutation):
    g, n = cross_fixture()
    g.edges = {k: e for k, e in g.edges.items() if e["relationship"] != "HAS_CROSS_TARGET_METADATA"}
    n["lb"]["properties"]["TargetRegionInfo"] = json.dumps(
        dict(Region="ap-singapore", VpcId="vpc-remote")
    )
    n["target"]["properties"]["TargetId"] = "ins-remote"
    if mutation == "wrong-region":
        n["instance"]["region"] = REGION
    elif mutation == "wrong-vpc":
        g.edges = {
            k: e
            for k, e in g.edges.items()
            if not (e["source"] == n["instance"]["id"] and e["relationship"] == "IN_VPC")
        }
    elif mutation == "missing-id":
        n["target"]["properties"].pop("TargetId")
    elif mutation == "uncollected":
        n["instance"]["status"] = "reference"
    elif mutation == "duplicate-owner":
        other_vpc = add(g, "vpc.vpc", "vpc-remote", "300", "ap-singapore")
        other = add(g, "cvm.instance", "ins-remote", "300", "ap-singapore")
        g.edge(other["id"], other_vpc["id"], "IN_VPC")
    link(g)
    analyze(g)
    assert bool(relations(g, "EXPOSE")) is (mutation is None)


@pytest.mark.parametrize(
    "field,value", [("account", "200"), ("region", "ap-singapore"), ("VpcId", "vpc-other")]
)
def test_acl_reported_association_cannot_cross_identity_scope(field, value):
    g = Graph()
    subnet = add(g, "vpc.subnet", "subnet-one", VpcId="vpc-one")
    acl = add(g, "vpc.networkacl", "acl-one", VpcId="vpc-one")
    if field == "VpcId":
        acl["properties"][field] = value
    else:
        acl[field] = value
    g.edge(subnet["id"], acl["id"], "USES_NETWORK_ACL")
    link(g)
    assert not relations(g, "USES_NETWORK_ACL")
    assert subnet["properties"]["network_acl_resolution"] == "conflicting-provider-association"


def test_security_group_ownership_collisions_are_not_guessed():
    g = Graph()
    group = add(g, "vpc.securitygroup", "sg-target")
    rule = add(g, "vpc.securitygrouprule", "sg-source/INGRESS/0", SecurityGroupId="sg-target")
    g.edge(rule["id"], group["id"], "REFERENCES_SECURITY_GROUP")
    link(g)
    assert rule["properties"]["group_reference_resolution"] == "matched-caller-account"
    add(g, "vpc.securitygroup", "sg-target", "200")
    link(g)
    assert not relations(g, "REFERENCES_SECURITY_GROUP")
    assert rule["properties"]["group_reference_resolution"] == "ambiguous-owner"
    assert any(r.get("error") == "UnresolvedSecurityGroupOwner" for r in g.coverage)


def test_security_group_counts_and_reverse_reference_metadata_exclude_payloads():
    g = Graph()
    group = add(g, "vpc.securitygroup", "sg-one")

    def call(service, action, region, params):
        assert params == dict(SecurityGroupIds=["sg-one"])
        key = (
            "ReferredSecurityGroupSet"
            if action == "DescribeSecurityGroupReferences"
            else "SecurityGroupAssociationStatisticsSet"
        )
        return {
            key: [
                dict(
                    SecurityGroupId="sg-one",
                    ReferredSecurityGroupIds=["sg-two"],
                    CVM=3,
                    ENI=2,
                    TotalCount=5,
                    SecretValue="not-retained",
                )
            ],
            "RequestId": action,
        }

    security_group_metadata(runner(g, call), REGION)
    assert json.loads(group["properties"]["reported_referring_group_ids"]) == ["sg-two"]
    assert json.loads(group["properties"]["association_statistics"]) == dict(
        CVM=3, ENI=2, TotalCount=5
    )
    assert "not-retained" not in g.dump()


@pytest.mark.parametrize(
    "response,error",
    [
        ({}, "SecurityGroupMetadataMismatch"),
        (
            {"ReferredSecurityGroupSet": [{"SecurityGroupId": "sg-other"}]},
            "SecurityGroupMetadataMismatch",
        ),
        (
            {
                "ReferredSecurityGroupSet": [
                    {"SecurityGroupId": "sg-one", "ReferredSecurityGroupIds": ["sg-two", "sg-two"]}
                ]
            },
            "InvalidSecurityGroupReferences",
        ),
    ],
)
def test_invalid_group_metadata_is_scoped_partial(response, error):
    g = Graph()
    add(g, "vpc.securitygroup", "sg-one")
    security_group_metadata(runner(g, lambda *args: response), REGION)
    assert g.coverage[0]["error"] == error


def test_endpoint_permission_is_a_native_allowlist_not_aws_iam_policy():
    g = Graph()
    service = add(g, "vpc.endpointservice", "vpcsvc-one")

    def call(product, action, region, params):
        assert params["Filters"] == [{"Name": "end-point-service-id", "Values": ["vpcsvc-one"]}]
        return dict(
            VpcEndpointServiceUserSet=[
                dict(
                    EndPointServiceId="vpcsvc-one",
                    UserUin="200",
                    Owner=987654,
                    Description="consumer",
                    SecretValue="not-retained",
                )
            ],
            TotalCount=1,
        )

    endpoint_permissions(runner(g, call), service)
    permission = next(n for n in g.nodes.values() if n["kind"] == "vpc.endpointservicepermission")
    assert permission["account"] == "100" and permission["properties"]["UserUin"] == "200"
    assert permission["properties"]["Owner"] == 987654
    assert not permission["properties"]["effective_access_verified"]
    assert len(relations(g, "ALLOWS_ENDPOINT_ACCOUNT")) == 1
    assert "not-retained" not in g.dump()


def test_shared_ccn_discovery_uses_explicit_owner_and_local_vpc_filter():
    g = Graph()
    vpc = add(g, "vpc.vpc", "vpc-local")
    subnet = add(g, "vpc.subnet", "subnet-one", VpcId="vpc-local", CidrBlock="10.0.1.0/24")

    def call(product, action, region, params):
        assert "CcnId" not in params
        assert params["Filters"] == [
            {"Name": "instance-id", "Values": ["vpc-local"]},
            {"Name": "instance-type", "Values": ["VPC"]},
            {"Name": "instance-region", "Values": [REGION]},
        ]
        return dict(
            InstanceSet=[
                dict(
                    CcnId="ccn-shared",
                    CcnUin="200",
                    InstanceUin="100",
                    InstanceType="VPC",
                    InstanceId="vpc-local",
                    InstanceRegion=REGION,
                    CidrBlock=["10.0.0.0/16"],
                    State="ACTIVE",
                )
            ],
            TotalCount=1,
        )

    shared_ccn(runner(g, call), vpc)
    link(g)
    ccn = next(n for n in g.nodes.values() if n["kind"] == "vpc.ccn")
    assert (ccn["account"], ccn["status"]) == ("200", "reference")
    assert relations(g, "ATTACHED_NETWORK")[0]["target"] == vpc["id"]
    assert relations(g, "COVERS_SUBNET_CIDR")[0]["target"] == subnet["id"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("CcnUin", None),
        ("InstanceUin", "200"),
        ("InstanceRegion", "ap-singapore"),
        ("InstanceId", "vpc-other"),
    ],
)
def test_shared_ccn_wrong_scope_does_not_create_foreign_nodes(field, value):
    g = Graph()
    vpc = add(g, "vpc.vpc", "vpc-local")
    row = dict(
        CcnId="ccn-shared",
        CcnUin="200",
        InstanceUin="100",
        InstanceType="VPC",
        InstanceId="vpc-local",
        InstanceRegion=REGION,
    )
    row[field] = value
    shared_ccn(runner(g, lambda *a: dict(InstanceSet=[row], TotalCount=1)), vpc)
    assert len(g.nodes) == 1 and g.coverage[-1]["error"] == "SharedCcnScopeMismatch"


def test_ipv6_variants_dhcp_and_local_gateway_are_all_metadata_reads():
    g, calls = Graph(), []

    def call(service, action, region, params):
        calls.append((action, params))
        if action in {"DescribeHaVips", "DescribeVpnGateways", "DescribeDirectConnectGateways"}:
            key = {
                "DescribeHaVips": "HaVipSet",
                "DescribeVpnGateways": "VpnGatewaySet",
                "DescribeDirectConnectGateways": "DirectConnectGatewaySet",
            }[action]
            return {key: [], "TotalCount": 0}
        if action == "DescribeIp6Addresses":
            return dict(
                AddressSet=[
                    dict(AddressId="eip-old", AddressIp="2001:db8::1", UnVpcId="vpc-local")
                ],
                TotalCount=1,
            )
        if action == "DescribeIPv6Addresses":
            typ = params["Filters"][0]["Values"][0]
            index = {"EIPv6": 2, "WanIPv6": 3, "HighQualityEIPv6": 4}[typ]
            assert params["Traditional"] is False
            return dict(
                AddressSet=[
                    dict(
                        AddressId="eipv6-" + str(index),
                        AddressIp="2001:db8::" + str(index),
                        AddressType=typ,
                    )
                ],
                TotalCount=1,
            )
        if action == "DescribeDhcpIps":
            return dict(
                DhcpIpSet=[
                    dict(
                        DhcpIpId="dhcpip-one",
                        VpcId="vpc-local",
                        SubnetId="subnet-one",
                        PrivateIpAddress="10.0.0.8",
                        AddressIp="203.0.113.8",
                        NetworkInterfaceId="eni-one",
                        State="AVAILABLE",
                    )
                ],
                TotalCount=1,
            )
        if action == "DescribeLocalGateway":
            return dict(
                LocalGatewaySet=[
                    dict(
                        LocalGatewayId="lgw-one",
                        UniqLocalGwId="lgw-one",
                        VpcId="vpc-local",
                        LocalGwIp="10.0.0.1",
                    )
                ],
                TotalCount=1,
            )
        if action == "DescribePrivateNatGateways":
            return dict(
                PrivateNatGatewaySet=[
                    dict(
                        NatGatewayId="intranat-one",
                        VpcId="vpc-local",
                        Status="AVAILABLE",
                        CrossDomain=True,
                        NatType="CCN",
                        CrossDomainInfo=dict(
                            CcnId="ccn-one", LocalVpcId="vpc-local", PeerVpcId="vpc-other"
                        ),
                    )
                ],
                TotalCount=1,
            )
        raise AssertionError(action)

    collect(runner(g, call), {"vpc"})
    assert len([n for n in g.nodes.values() if n["kind"] == "vpc.eip"]) == 4
    assert all(r["status"] in {"complete", "empty"} for r in g.coverage)
    assert {n["kind"] for n in g.nodes.values()} >= {
        "vpc.dhcpip",
        "vpc.localgateway",
        "vpc.privatenat",
    }
    assert not any("InternetGateway" in a for a, _ in calls)


def test_permission_failure_is_visible_and_other_reads_continue():
    g = Graph()

    def call(*args):
        raise CollectionError("UnauthorizedOperation")

    simple_networks(runner(g, call), REGION)
    assert [r["status"] for r in g.coverage] == ["denied", "denied"]


def test_default_subnet_cidr_acl_and_non_cvm_attachment_semantics():
    g = Graph()
    subnet = add(
        g,
        "vpc.subnet",
        "subnet-one",
        VpcId="vpc-one",
        Zone=REGION + "-1",
        IsDefault=True,
        CidrBlock="10.0.1.0/24",
        NetworkAclId="acl-one",
        network_acl_association="explicit",
    )
    cidr = add(
        g, "vpc.cidr", "vpc-one/10.0.0.0/16", VpcId="vpc-one", cidr="10.0.0.0/16", ip_version=4
    )
    acl = add(g, "vpc.networkacl", "acl-one", VpcId="vpc-one")
    g.edge(subnet["id"], acl["id"], "USES_NETWORK_ACL")
    eni = add(
        g,
        "vpc.networkinterface",
        "eni-eks",
        Business="eks",
        attachment_InstanceId="eks-one",
        attachment_InstanceAccountId="123456",
        ResourceId="retained-ip-resource",
    )
    link(g)
    assert (
        subnet["properties"]["default_scope_resolution"] == "unique-collected-default-in-vpc-zone"
    )
    assert subnet["properties"]["network_acl_resolution"] == "corroborated"
    assert relations(g, "WITHIN_VPC_CIDR")[0]["target"] == cidr["id"]
    child = g.nodes[relations(g, "HAS_REPORTED_ATTACHMENT")[0]["target"]]
    assert child["properties"]["attachment_InstanceId"] == "eks-one"
    assert "ResourceId" not in child["properties"]
    assert not relations(g, "ATTACHED_TO")
    before = g.dump()
    link(g)
    assert g.dump() == before
    eni["properties"]["Business"] = "cvm"
    link(g)
    assert not relations(g, "HAS_REPORTED_ATTACHMENT")


def test_conflicting_acl_and_default_scope_are_visible_and_repeatable():
    g = Graph()
    subnet = add(
        g,
        "vpc.subnet",
        "subnet-one",
        VpcId="vpc-one",
        Zone=REGION + "-1",
        IsDefault=True,
        network_acl_association="none",
    )
    add(g, "vpc.subnet", "subnet-two", VpcId="vpc-one", Zone=REGION + "-1", IsDefault=True)
    acl = add(g, "vpc.networkacl", "acl-one", VpcId="vpc-one")
    g.edge(subnet["id"], acl["id"], "USES_NETWORK_ACL")
    link(g)
    assert not relations(g, "USES_NETWORK_ACL")
    assert len(relations(g, "REPORTED_NETWORK_ACL")) == 1
    assert subnet["properties"]["network_acl_resolution"] == "conflicting-provider-association"
    assert {r["error"] for r in g.coverage} == {
        "ConflictingNetworkAclAssociation",
        "AmbiguousDefaultSubnetScope",
    }
    before = g.dump()
    link(g)
    assert g.dump() == before


def test_clb_remote_configuration_does_not_relocate_load_balancer():
    g = Graph()
    spec = next(s for s in COLLECTORS if s.action == "DescribeLoadBalancers")
    nid = g.native(
        "100",
        REGION,
        spec,
        dict(
            LoadBalancerId="lb-one",
            VpcId="vpc-local",
            TargetRegionInfo=dict(VpcId="vpc-remote", Region="ap-singapore"),
            ExtraInfo=dict(SecretKey="not-retained"),
            Forward=1,
            MixIpTarget=True,
        ),
        "clb.DescribeLoadBalancers",
    )
    assert {
        g.nodes[e["target"]]["resource_id"] for e in relations(g, "IN_VPC") if e["source"] == nid
    } == {"vpc-local"}
    assert json.loads(g.nodes[nid]["properties"]["TargetRegionInfo"])["VpcId"] == "vpc-remote"
    assert "not-retained" not in g.dump()


def test_endpoint_interface_and_private_dns_require_explicit_vpc_binding():
    g = Graph()
    vpc = add(g, "vpc.vpc", "vpc-one")
    endpoint = add(
        g,
        "vpc.endpoint",
        "vpce-one",
        VpcId="vpc-one",
        SubnetId="subnet-one",
        EndPointVip="10.0.1.8",
    )
    eni = add(g, "vpc.networkinterface", "eni-one", VpcId="vpc-one")
    address = add(
        g,
        "vpc.interfaceaddress",
        "eni-one/10.0.1.8",
        VpcId="vpc-one",
        SubnetId="subnet-one",
        address="10.0.1.8",
        NetworkInterfaceId="eni-one",
    )
    zone = add(g, "privatedns.zone", "zone-one", region="global")
    add(
        g,
        "privatedns.record",
        "zone-one/one",
        region="global",
        dns_zone=zone["id"],
        record_type="A",
        record_value="10.0.1.8",
        enabled=True,
    )
    for node in (endpoint, eni, address):
        g.edge(node["id"], vpc["id"], "IN_VPC")
    g.edge(eni["id"], address["id"], "HAS_ADDRESS")
    link(g)
    assert len(relations(g, "USES_COLLECTED_INTERFACE")) == 1
    assert not relations(g, "CONFIGURED_ENDPOINT_DNS")
    g.edge(zone["id"], vpc["id"], "ASSOCIATED_WITH_VPC")
    link(g)
    assert len(relations(g, "CONFIGURED_ENDPOINT_DNS")) == 1


def test_unknown_classic_backend_ip_is_preserved_and_resolves_in_local_vpc_only():
    g, n = cross_fixture("100", REGION)
    # Same local VPC with a non-CVM workload interface.
    for key in ("eni", "address", "instance"):
        g.edges = {
            k: e
            for k, e in g.edges.items()
            if not (e["source"] == n[key]["id"] and e["relationship"] == "IN_VPC")
        }
        g.edge(n[key]["id"], stable_id("100", REGION, "vpc.vpc", "vpc-local"), "IN_VPC")
    n["address"]["properties"]["VpcId"] = n["eni"]["properties"]["VpcId"] = "vpc-local"
    n["eni"]["properties"]["Business"] = "eks"
    g.edges = {
        k: e
        for k, e in g.edges.items()
        if e["relationship"] not in {"FORWARDS_TO", "HAS_CROSS_TARGET_METADATA"}
    }
    binding = add(
        g,
        "clb.targetbinding",
        "binding",
        Type="OTHER",
        InstanceId="opaque",
        addresses='["10.1.0.8"]',
    )
    g.edge(n["listener"]["id"], binding["id"], "HAS_BACKEND")
    link(g)
    analyze(g)
    assert {e["target"] for e in relations(g, "EXPOSE")} == {n["address"]["id"]}
    assert len(relations(g, "FORWARDS_TO")) == 1
