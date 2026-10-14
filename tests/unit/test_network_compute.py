import json

from tencent_cloud_cartography.catalog import CHILDREN, COLLECTORS, KIND_ICONS
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.icons import names
from tencent_cloud_cartography.model import Graph, stable_id
from tencent_cloud_cartography.topology import topology


def native(graph, action, raw, account="1", region="eu-frankfurt"):
    spec = next(
        s
        for s in (*COLLECTORS, *CHILDREN.values())
        if s.action == action and (action != "DescribeInstances" or s.service == "cvm")
    )
    return graph.native(account, region, spec, raw, action)


def test_acl_subnet_association_and_ordered_rules():
    graph = Graph()
    nid = native(
        graph,
        "DescribeNetworkAcls",
        dict(
            NetworkAclId="acl-1",
            VpcId="vpc-1",
            SubnetSet=[dict(SubnetId="subnet-1")],
            IngressEntries=[
                dict(
                    Priority=1, Protocol="TCP", Port="443", CidrBlock="0.0.0.0/0", Action="ACCEPT"
                ),
                dict(Priority=2, Protocol="ALL", Action="DROP"),
            ],
            EgressEntries=[],
        ),
    )
    edges = list(graph.edges.values())
    assert any(
        e["source"] == stable_id("1", "eu-frankfurt", "vpc.subnet", "subnet-1")
        and e["target"] == nid
        and e["relationship"] == "USES_NETWORK_ACL"
        for e in edges
    )
    assert not any(e["source"] == nid and e["relationship"] == "IN_SUBNET" for e in edges)
    rules = [n for n in graph.nodes.values() if n["kind"] == "vpc.networkaclrule"]
    assert sorted(n["properties"]["Priority"] for n in rules) == [1, 2]
    assert len({n["resource_id"] for n in rules}) == 2


def test_route_gateway_identity_and_ipv6_collision_controls():
    graph = Graph()
    table = native(
        graph,
        "DescribeRouteTables",
        dict(
            RouteTableId="rtb-1",
            VpcId="vpc-1",
            AssociationSet=[dict(SubnetId="subnet-1")],
            RouteSet=[
                dict(
                    RouteItemId="r-1",
                    DestinationCidrBlock="0.0.0.0/0",
                    GatewayType="NAT",
                    GatewayId="nat-1",
                    Enabled=False,
                ),
                dict(
                    RouteId=0,
                    DestinationIpv6CidrBlock="2001:db8:1::/64",
                    GatewayType="NORMAL_CVM",
                    GatewayId="10.0.0.4",
                ),
                dict(
                    RouteId=0,
                    DestinationIpv6CidrBlock="2001:db8:2::/64",
                    GatewayType="EIP",
                    GatewayId="0",
                ),
            ],
        ),
    )
    routes = [n for n in graph.nodes.values() if n["kind"] == "vpc.route"]
    assert len(routes) == 3
    assert any(n["properties"].get("Enabled") is False for n in routes)
    targets = [
        graph.nodes[e["target"]] for e in graph.edges.values() if e["relationship"] == "ROUTES_TO"
    ]
    assert [n["resource_id"] for n in targets] == ["nat-1"]
    assert not any(n["resource_id"] in {"0", "10.0.0.4"} for n in graph.nodes.values())
    assert any(
        e["target"] == table and e["relationship"] == "USES_ROUTE_TABLE"
        for e in graph.edges.values()
    )


def test_peering_preserves_owner_and_region_never_uses_appid_as_uin():
    graph = Graph()
    native(
        graph,
        "DescribeVpcPeeringConnections",
        dict(
            PeeringConnectionId="pcx-1",
            SourceVpcId="vpc-a",
            PeerVpcId="vpc-b",
            SourceUin=1,
            DestinationUin=2,
            SourceRegion="eu-frankfurt",
            DestinationRegion="ap-singapore",
            AppId=123,
            PeerAppId=456,
        ),
    )
    vpcs = {
        (n["account"], n["region"], n["resource_id"])
        for n in graph.nodes.values()
        if n["kind"] == "vpc.vpc"
    }
    assert vpcs == {("1", "eu-frankfurt", "vpc-a"), ("2", "ap-singapore", "vpc-b")}
    graph2 = Graph()
    native(
        graph2,
        "DescribeVpcPeeringConnections",
        dict(
            PeeringConnectionId="pcx-2",
            SourceVpcId="vpc-a",
            PeerVpcId="vpc-b",
            AppId=123,
            PeerAppId=456,
        ),
    )
    assert len(graph2.nodes) == 1 and not graph2.edges


def test_ccn_attached_network_keeps_cross_account_region():
    graph = Graph()
    attachment = native(
        graph,
        "DescribeCcnAttachedInstances",
        dict(
            AttachmentId="attachment-1",
            CcnId="ccn-1",
            InstanceType="VPC",
            InstanceId="vpc-remote",
            InstanceUin="2",
            InstanceRegion="ap-singapore",
        ),
        region="global",
    )
    target = graph.nodes[stable_id("2", "ap-singapore", "vpc.vpc", "vpc-remote")]
    assert target["status"] == "reference"
    assert any(
        e["source"] == attachment and e["target"] == target["id"] for e in graph.edges.values()
    )
    assert not any(n["kind"] == "cvm.instance" for n in graph.nodes.values())


def test_launch_config_and_scaling_group_join_to_instances_and_dependencies():
    graph = Graph()
    config = native(
        graph,
        "DescribeLaunchConfigurations",
        dict(
            LaunchConfigurationId="asc-1",
            ImageId="img-1",
            LoginSettings=dict(KeyIds=["skey-1"], Password="do-not-save"),
            UserData="do-not-save",
        ),
    )
    group = native(
        graph,
        "DescribeAutoScalingGroups",
        dict(
            AutoScalingGroupId="asg-1",
            LaunchConfigurationId="asc-1",
            VpcId="vpc-1",
            SubnetIdSet=["subnet-1", "subnet-2"],
            LoadBalancerIdSet=["lb-1"],
            MinSize=1,
            MaxSize=4,
            DesiredCapacity=2,
        ),
    )
    instance = native(
        graph,
        "DescribeAutoScalingInstances",
        dict(InstanceId="ins-1", AutoScalingGroupId="asg-1", LaunchConfigurationId="asc-1"),
    )
    assert any(
        e["source"] == group and e["target"] == instance and e["relationship"] == "HAS_INSTANCE"
        for e in graph.edges.values()
    )
    assert any(
        e["source"] == group
        and e["target"] == config
        and e["relationship"] == "USES_LAUNCH_CONFIGURATION"
        for e in graph.edges.values()
    )
    assert "do-not-save" not in graph.dump()
    data = topology(graph.snapshot())
    projected = next(e["data"] for e in data["elements"] if e["data"]["id"] == group)
    assert projected["locationParent"] == stable_id("1", "eu-frankfurt", "vpc.vpc", "vpc-1")


def test_keypair_and_snapshot_relationships_never_persist_key_material():
    graph = Graph()
    native(
        graph,
        "DescribeKeyPairs",
        dict(
            KeyId="skey-1",
            AssociatedInstanceIds=["ins-1"],
            PrivateKey="private-material",
            PublicKey="public-material",
        ),
    )
    native(graph, "DescribeSnapshots", dict(SnapshotId="snap-1", DiskId="disk-1"))
    native(graph, "DescribeImages", dict(ImageId="img-1", SnapshotSet=[dict(SnapshotId="snap-1")]))
    assert {"USES_KEY_PAIR", "SNAPSHOT_OF", "USES_SNAPSHOT"} <= {
        e["relationship"] for e in graph.edges.values()
    }
    assert "material" not in graph.dump()


def test_launch_versions_workload_api_is_not_called_and_private_image_filter():
    class Transport:
        def call(self, service, action, region=None, **params):
            if action == "DescribeImages":
                assert params["Filters"] == [dict(Name="image-type", Values=["PRIVATE_IMAGE"])]
                return dict(ImageSet=[], TotalCount=0)
            raise AssertionError("Workload-bearing version API must not be called")

    graph = Graph()
    runner = CollectorRunner(graph, Transport(), "1", ["eu-frankfurt"], lambda _: None)
    runner.native(next(s for s in COLLECTORS if s.action == "DescribeImages"), "eu-frankfurt")
    for template in ("lt-1", "lt-2"):
        runner.native(
            CHILDREN["cvm.launchtemplate"], "eu-frankfurt", {"LaunchTemplateId": template}
        )
    versions = [
        n["resource_id"] for n in graph.nodes.values() if n["kind"] == "cvm.launchtemplateversion"
    ]
    assert versions == []
    assert all(
        r["error"] == "UnsupportedMetadataOnlyProjection"
        for r in graph.coverage
        if r["action"] == "DescribeLaunchTemplateVersions"
    )
    assert "do-not-save" not in graph.dump()


def test_all_explicit_network_icons_exist():
    for title in KIND_ICONS.values():
        assert title in names()


def test_all_edges_remain_in_full_graph():
    graph = Graph()
    native(
        graph,
        "DescribeRouteTables",
        dict(
            RouteTableId="rtb-1",
            VpcId="vpc-1",
            RouteSet=[
                dict(
                    RouteItemId="r-1",
                    DestinationCidrBlock="0.0.0.0/0",
                    GatewayType="NAT",
                    GatewayId="nat-1",
                )
            ],
        ),
    )
    full = topology(graph.snapshot(), view="full")
    assert full["stats"]["relationships"] == len(graph.edges)
    assert full["stats"]["resources"] == len(graph.nodes)
    assert len(json.dumps(full)) > 0


def test_inventory_toggle_and_service_groups_preserve_full_edges():
    graph = Graph()
    vm = native(
        graph, "DescribeInstances", dict(InstanceId="ins-1", VpcId="vpc-1", SubnetId="subnet-1")
    )
    unknown = graph.add("1", "eu-frankfurt", "future.product", "unknown-1", status="inventory-only")
    graph.edge(vm, unknown, "REFERENCES", "fixture")
    default = topology(graph.snapshot(), view="full")
    full = topology(graph.snapshot(), view="full", include_inventory=True)
    assert default["stats"]["unresolvedAvailable"] == 1
    assert default["stats"]["inventoryOnly"] == 0
    assert full["stats"]["inventoryOnly"] == 1
    assert full["stats"]["relationships"] == len(graph.edges)
    nodes = {e["data"]["id"]: e["data"] for e in full["elements"] if "source" not in e["data"]}
    assert nodes[nodes[vm]["parent"]]["type"] == "component"
    assert nodes[nodes[vm]["parent"]]["parent"] == nodes[vm]["locationParent"]
    assert nodes[unknown]["inventoryOnly"] is True


def test_common_vpc_is_inferred_only_when_all_subnets_agree():
    graph = Graph()
    for rid in ("subnet-a", "subnet-b"):
        native(graph, "DescribeSubnets", dict(SubnetId=rid, VpcId="vpc-one"))
    group = native(
        graph,
        "DescribeAutoScalingGroups",
        dict(AutoScalingGroupId="asg-1", SubnetIdSet=["subnet-a", "subnet-b"]),
    )

    def projected():
        return next(
            e["data"] for e in topology(graph.snapshot())["elements"] if e["data"]["id"] == group
        )

    assert projected()["locationParent"] == stable_id("1", "eu-frankfurt", "vpc.vpc", "vpc-one")
    subnet = stable_id("1", "eu-frankfurt", "vpc.subnet", "subnet-b")
    other = graph.add("1", "eu-frankfurt", "vpc.vpc", "vpc-two")
    graph.edge(subnet, other, "IN_VPC", "contradictory-fixture")
    assert projected()["locationParent"].startswith("region-")


def test_auxiliary_membership_preserves_cvm_state_and_snapshot_semantics():
    graph = Graph()
    vm = native(graph, "DescribeInstances", dict(InstanceId="ins-1", InstanceState="RUNNING"))
    native(
        graph,
        "DescribeAutoScalingInstances",
        dict(InstanceId="ins-1", LifeCycleState="IN_SERVICE", AutoScalingGroupId="asg-1"),
    )
    assert graph.nodes[vm]["properties"]["state"] == "RUNNING"
    assert graph.nodes[vm]["properties"]["LifeCycleState"] == "IN_SERVICE"
    snapshot = native(graph, "DescribeSnapshots", dict(SnapshotId="snap-1", DiskId="disk-1"))
    assert [e["relationship"] for e in graph.edges.values() if e["source"] == snapshot] == [
        "SNAPSHOT_OF"
    ]
