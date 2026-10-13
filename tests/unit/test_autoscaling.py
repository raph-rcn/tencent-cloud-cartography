import json
from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.autoscaling import collect
from tencent_cloud_cartography.catalog import ALLOWED_ACTIONS, COLLECTORS
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.transport import CollectionError, TccliTransport

REGION = "eu-frankfurt"
SPECS = {s.action: s for s in COLLECTORS if s.service == "autoscaling"}


def group(**kwargs):
    return dict(
        AutoScalingGroupId="asg-demo",
        AutoScalingGroupName="Workers",
        VpcId="vpc-demo",
        SubnetIdSet=["subnet-a", "subnet-b"],
        ZoneSet=["eu-frankfurt-1", "eu-frankfurt-2"],
        LaunchConfigurationId="asc-demo",
        LaunchConfigurationName="Worker configuration",
        DefaultCooldown=300,
        MinSize=1,
        MaxSize=10,
        DesiredCapacity=3,
        CapacityRebalance=False,
        EnabledStatus="ENABLED",
        HealthCheckType="CLB",
        LoadBalancerHealthCheckGracePeriod=600,
        TerminationPolicySet=["OLDEST_INSTANCE"],
        ServiceSettings={"ReplaceLoadBalancerUnhealthy": True, "ScalingMode": "CLASSIC_SCALING"},
        **kwargs,
    )


def member(**kwargs):
    return dict(
        InstanceId="ins-demo",
        AutoScalingGroupId="asg-demo",
        LaunchConfigurationId="asc-demo",
        LifeCycleState="IN_SERVICE",
        ProtectedFromScaleIn=False,
        Zone="eu-frankfurt-1",
        **kwargs,
    )


def run(groups=None, members=None, graph=None, mutate=None):
    graph = graph or Graph()
    calls = []
    inventories = {
        "DescribeAutoScalingGroups": groups or [],
        "DescribeAutoScalingInstances": members or [],
    }

    def call(service, action, **params):
        assert service == "autoscaling" and params["region"] == REGION
        assert set(params) == {"region", "Offset", "Limit"}
        calls.append((action, params))
        rows = inventories[action]
        if isinstance(rows, Exception):
            raise rows
        result = {
            SPECS[action].result: rows[params["Offset"] : params["Offset"] + params["Limit"]],
            "TotalCount": len(rows),
            "RequestId": str(len(calls)),
        }
        return mutate(action, result) if mutate else result

    runner = CollectorRunner(graph, SimpleNamespace(call=call), "100", [REGION], lambda _: None)
    for spec in SPECS.values():
        collect(runner, spec, REGION)
    return graph, calls


def test_group_metadata_subnet_choices_and_explicit_cross_region_load_balancer():
    g, _ = run(
        [
            group(
                ForwardLoadBalancerSet=[
                    dict(
                        LoadBalancerId="lb-demo",
                        Region="ap-shanghai-fsi",
                        ListenerId="lbl-demo",
                        TargetAttributes=[dict(Port=443, Weight=0)],
                    )
                ]
            )
        ]
    )
    node = next(n for n in g.nodes.values() if n["kind"] == "as.auto-scaling-group")
    p = node["properties"]
    assert p["DefaultCooldown"] == 300 and p["CapacityRebalance"] is False
    assert p["HealthCheckType"] == "CLB" and p["LoadBalancerHealthCheckGracePeriod"] == 600
    assert json.loads(p["ServiceSettings"])["ReplaceLoadBalancerUnhealthy"] is True
    assert p["zone"] == ""
    assert json.loads(p["ForwardLoadBalancerSet"])[0]["TargetAttributes"] == [
        dict(Port=443, Weight=0)
    ]
    assert sum(e["relationship"] == "IN_SUBNET" for e in g.edges.values()) == 2
    lb = next(n for n in g.nodes.values() if n["kind"] == "clb.clb")
    assert lb["region"] == "ap-shanghai-fsi" and lb["account"] == "100"
    assert icon_for(node["kind"]) == "en-auto-scaling.svg"
    cfg = next(n for n in g.nodes.values() if n["kind"] == "as.launch-configuration")
    assert (
        cfg["status"] == "reference"
        and cfg["properties"]["referenced_name"] == "Worker configuration"
    )


def test_membership_does_not_overwrite_cvm_inventory_or_other_account():
    g = Graph()
    nid = g.add(
        "100",
        REGION,
        "cvm.instance",
        "ins-demo",
        "Original VM",
        raw={"InstanceState": "RUNNING", "Zone": "eu-frankfurt-1"},
        source="cvm.DescribeInstances",
    )
    other = g.add("200", REGION, "cvm.instance", "ins-demo", "Other account")
    g, _ = run(members=[member()], graph=g)
    n = g.nodes[nid]
    assert (
        n["name"] == "Original VM"
        and n["properties"]["state"] == "RUNNING"
        and n["status"] == "enriched"
    )
    assert n["properties"]["as_ProtectedFromScaleIn"] is False
    assert n["properties"]["as_LifeCycleState"] == "IN_SERVICE"
    assert "autoscaling.DescribeAutoScalingInstances" in n["sources"]
    assert all(e["target"] != other for e in g.edges.values())
    assert "as_ProtectedFromScaleIn" not in g.nodes[other]["properties"]


def test_membership_alone_does_not_claim_cvm_enrichment():
    g, _ = run(members=[member()])
    n = next(n for n in g.nodes.values() if n["kind"] == "cvm.instance")
    assert n["status"] == "reference"
    assert {e["relationship"] for e in g.edges.values()} == {
        "HAS_INSTANCE",
        "USES_LAUNCH_CONFIGURATION",
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("MinSize", True),
        ("DefaultCooldown", -1),
        ("CapacityRebalance", "false"),
        ("SubnetIdSet", ["bad"]),
        ("SubnetIdSet", ["subnet-a", "subnet-a"]),
        ("ZoneSet", ["ap-guangzhou-1"]),
        ("ServiceSettings", []),
        ("ForwardLoadBalancerSet", False),
        ("ForwardLoadBalancerSet", [{"LoadBalancerId": "lb-ok", "Region": "invalid"}]),
    ],
)
def test_invalid_group_page_is_not_added(field, value):
    bad = group()
    bad[field] = value
    g, _ = run([bad])
    assert not g.nodes and g.coverage[0]["status"] == "error"


@pytest.mark.parametrize(
    "field,value",
    [
        ("AutoScalingGroupId", "bad"),
        ("InstanceId", None),
        ("Zone", "ap-guangzhou-1"),
        ("ProtectedFromScaleIn", 0),
    ],
)
def test_invalid_member_metadata(field, value):
    bad = member()
    bad[field] = value
    g, _ = run(members=[bad])
    assert not g.nodes and g.coverage[-1]["status"] == "error"


def test_duplicate_identity_page_fails_before_mutation():
    g, _ = run([group(), group()])
    assert not g.nodes and g.coverage[0]["error"] == "DuplicateAutoScalingResource"


def test_required_total_and_independent_membership_failure():
    g, _ = run(
        [group()],
        members=CollectionError("UnauthorizedOperation"),
        mutate=lambda a, r: {**r, "TotalCount": None},
    )
    assert not g.nodes
    assert [c["status"] for c in g.coverage] == ["error", "unsupported", "denied"]


def test_offset_pagination():
    rows = []
    for i in range(101):
        item = group()
        item["AutoScalingGroupId"] = f"asg-{i}"
        rows.append(item)
    g, calls = run(rows)
    assert [p["Offset"] for a, p in calls if a == "DescribeAutoScalingGroups"] == [0, 100]
    assert g.coverage[0]["count"] == 101


def test_user_data_api_is_never_requested(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Sensitive operation reached subprocess")

    monkeypatch.setattr("subprocess.run", forbidden)
    assert ("autoscaling", "DescribeLaunchConfigurations") not in ALLOWED_ACTIONS
    with pytest.raises(CollectionError, match="outside the metadata allowlist"):
        TccliTransport().call("autoscaling", "DescribeLaunchConfigurations")
    g, calls = run()
    assert [c["status"] for c in g.coverage] == ["empty", "unsupported", "empty"]
    assert all(a != "DescribeLaunchConfigurations" for a, p in calls)
