import json
from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.catalog import ALLOWED_ACTIONS, API_VERSIONS, COLLECTORS
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.gwlb import collect
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.transport import CollectionError

REGION = "eu-frankfurt"
SPEC = next(s for s in COLLECTORS if s.service == "gwlb")


def runner(graph, call):
    def invoke(service, action, region=None, **params):
        return call(service, action, region, params)

    return CollectorRunner(graph, SimpleNamespace(call=invoke), "100", [REGION], lambda _: None)


def run(mutate=None, size=1):
    graph, calls = Graph(), []

    def call(service, action, region, params):
        assert service == "gwlb" and region == REGION
        assert (service, action) in ALLOWED_ACTIONS
        calls.append((action, params))
        if action == "DescribeGatewayLoadBalancers":
            response = dict(
                LoadBalancerSet=[
                    dict(
                        LoadBalancerId="gwlb-one",
                        VpcId="vpc-one",
                        SubnetId="subnet-one",
                        Vips=["10.0.1.8"],
                        Status=1,
                        DeleteProtect=True,
                        TargetGroupId="lbtg-one",
                        SecretValue="never-persist",
                    )
                ],
                TotalCount=1,
            )
        elif action == "DescribeTargetGroups":
            response = dict(
                TargetGroupSet=[
                    dict(
                        TargetGroupId="lbtg-one",
                        VpcId="vpc-one",
                        Protocol="tencent_geneve",
                        Port=6081,
                        ForwardingMode="STATEFUL",
                        TcpIdleConnectTimeout=350,
                        AssociatedRule=[dict(LoadBalancerId="gwlb-one")],
                        HealthCheck=dict(
                            HealthSwitch=1, Protocol="TCP", Port=80, RequestBody="never-persist"
                        ),
                    )
                ],
                TotalCount=1,
            )
        elif action == "DescribeTargetGroupInstances":
            assert params["Filters"] == [{"Name": "TargetGroupId", "Values": ["lbtg-one"]}]
            rows = [
                dict(
                    TargetGroupId="lbtg-one",
                    Type="ENI" if i % 2 else "CVM",
                    InstanceId="eni-" + str(i) if i % 2 else "ins-" + str(i),
                    EniId="eni-" + str(i) if i % 2 else None,
                    Port=6081,
                    Weight=16,
                    PrivateIpAddresses=["10.0.1." + str(i + 10)],
                    UserData="never-persist",
                )
                for i in range(size)
            ]
            response = dict(
                TargetGroupInstanceSet=rows[params["Offset"] : params["Offset"] + params["Limit"]],
                RealCount=size,
                TotalCount=size,
            )
        elif action == "DescribeTargetGroupInstanceStatus":
            assert params == dict(TargetGroupId="lbtg-one")
            response = dict(
                TargetGroupInstanceSet=[
                    dict(InstanceIp="10.0.1." + str(i + 10), Status="health") for i in range(size)
                ]
            )
        else:
            raise AssertionError(action)
        response["RequestId"] = action
        return mutate(action, response) if mutate else response

    collect(runner(graph, call), SPEC, REGION)
    return graph, calls


def test_native_gwlb_metadata_health_and_scoped_backends_with_pagination():
    graph, calls = run(size=101)
    assert API_VERSIONS["gwlb"] == "2024-09-06"
    assert len([a for a, _ in calls if a == "DescribeTargetGroupInstances"]) == 2
    bindings = [n for n in graph.nodes.values() if n["kind"] == "gwlb.targetbinding"]
    assert len(bindings) == 101
    assert all(n["properties"]["reported_health"] == "health" for n in bindings)
    assert all(n["properties"]["reachability_verified"] is False for n in bindings)
    assert {
        graph.nodes[e["target"]]["kind"]
        for e in graph.edges.values()
        if e["relationship"] == "FORWARDS_TO"
    } == {"cvm.instance", "vpc.networkinterface"}
    group = next(n for n in graph.nodes.values() if n["kind"] == "gwlb.targetgroup")
    assert json.loads(group["properties"]["health_check"])["Port"] == 80
    assert "never-persist" not in graph.dump()
    assert all(c["status"] == "complete" for c in graph.coverage)
    assert all(
        icon_for(kind) == "en-cloud-load-balancer.svg"
        for kind in ("clb.gatewayloadbalancer", "gwlb.targetgroup", "gwlb.targetbinding")
    )
    assert not any(e["relationship"] == "EXPOSE" for e in graph.edges.values())


@pytest.mark.parametrize(
    "change,expected",
    [
        ("wrong-parent", "GatewayTargetGroupMismatch"),
        ("duplicate", "DuplicateGatewayBackend"),
        ("bad-health-ip", "UnresolvedGatewayHealthBackend"),
        ("duplicate-health", "InvalidGatewayHealthIdentity"),
        ("wrong-native-id", "InvalidVpcIdentity"),
    ],
)
def test_gateway_backend_and_health_controls_fail_visibly(change, expected):
    def mutate(action, response):
        if action == "DescribeTargetGroupInstances":
            row = response["TargetGroupInstanceSet"][0]
            if change == "wrong-parent":
                row["TargetGroupId"] = "lbtg-other"
            elif change == "duplicate":
                response["TargetGroupInstanceSet"].append(dict(row))
                response["RealCount"] = response["TotalCount"] = 2
            elif change == "wrong-native-id":
                row["InstanceId"] = "eni-mislabeled"
        if action == "DescribeTargetGroupInstanceStatus":
            if change == "bad-health-ip":
                response["TargetGroupInstanceSet"][0]["InstanceIp"] = "10.0.99.99"
            elif change == "duplicate-health":
                response["TargetGroupInstanceSet"] *= 2
        return response

    graph, _ = run(mutate)
    assert expected in {r.get("error") for r in graph.coverage}
    assert graph.snapshot()["status"] == "partial"


def test_gwlb_denials_are_recorded_per_api_scope():
    graph = Graph()

    def call(*args):
        raise CollectionError("UnauthorizedOperation")

    collect(runner(graph, call), SPEC, REGION)
    assert [r["status"] for r in graph.coverage] == ["denied", "denied"]
    assert not graph.nodes
