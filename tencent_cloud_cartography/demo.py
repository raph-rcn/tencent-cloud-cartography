"""Synthetic Frankfurt example. Never used as a fallback for failed collection."""

from .catalog import COLLECTORS
from .model import Graph


def demo():
    graph = Graph(mode="demo")
    account, region = "000000000001", "eu-frankfurt"
    graph.accounts[account] = dict(
        id=account, name="Synthetic demo", display="Synthetic demo · no live cloud data"
    )
    samples = {
        "vpc.vpc": [
            dict(VpcId="vpc-demo", VpcName="Frankfurt application VPC", CidrBlock="10.42.0.0/16")
        ],
        "vpc.subnet": [
            dict(
                SubnetId="subnet-web",
                SubnetName="Web tier",
                VpcId="vpc-demo",
                Zone="eu-frankfurt-1",
                CidrBlock="10.42.1.0/24",
            ),
            dict(
                SubnetId="subnet-data",
                SubnetName="Data tier",
                VpcId="vpc-demo",
                Zone="eu-frankfurt-2",
                CidrBlock="10.42.2.0/24",
            ),
        ],
        "vpc.securitygroup": [
            dict(SecurityGroupId="sg-web", SecurityGroupName="Web security group")
        ],
        "cvm.instance": [
            dict(
                InstanceId="ins-web",
                InstanceName="Application server",
                VirtualPrivateCloud=dict(VpcId="vpc-demo", SubnetId="subnet-web"),
                Placement=dict(Zone="eu-frankfurt-1"),
                SecurityGroupIds=["sg-web"],
                PrivateIpAddresses=["10.42.1.10"],
                InstanceState="RUNNING",
            )
        ],
        "clb.clb": [
            dict(
                LoadBalancerId="lb-demo",
                LoadBalancerName="Public HTTPS load balancer",
                VpcId="vpc-demo",
                SubnetId="subnet-web",
                ListenerId="lbl-https",
                Protocol="HTTPS",
                Port=443,
                TargetId="ins-web",
                TargetPort=8080,
            )
        ],
        "cdb.instance": [
            dict(
                InstanceId="cdb-demo",
                InstanceName="Application database",
                UniqVpcId="vpc-demo",
                UniqSubnetId="subnet-data",
                EngineVersion="8.0",
            )
        ],
        "cbs.disk": [
            dict(
                DiskId="disk-demo",
                DiskName="Application data disk",
                InstanceId="ins-web",
                DiskSize=100,
            )
        ],
        "tke.cluster": [
            dict(
                ClusterId="cls-demo",
                ClusterName="Worker cluster",
                ClusterNetworkSettings=dict(VpcId="vpc-demo"),
            )
        ],
        "cam.role": [dict(RoleId="10001", RoleName="Application read role")],
    }
    used = set()
    for spec in COLLECTORS:
        if spec.kind in used:
            continue
        used.add(spec.kind)
        for item in samples.get(spec.kind, []):
            graph.native(
                account, region if spec.regional else "global", spec, item, "synthetic-fixture"
            )
    graph.add(
        account,
        region,
        "cos.bucket",
        "demo-assets-1000000001",
        "Static assets",
        source="synthetic-fixture",
    )
    graph.add(
        account,
        region,
        "unknown.resource",
        "unmapped-demo",
        "Inventory-only example",
        source="synthetic-fixture",
        status="inventory-only",
    )
    graph.coverage = [
        dict(
            account=account,
            region=region,
            service="demo",
            action="SyntheticFixture",
            status="complete",
            count=len(graph.nodes),
            request_ids=[],
        ),
        dict(
            account=account,
            region=region,
            service="ssm",
            action="ListSecrets",
            status="denied",
            error="UnauthorizedOperation (synthetic example)",
            count=0,
            request_ids=[],
        ),
    ]
    return graph.snapshot()
