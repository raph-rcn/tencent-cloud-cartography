import json

import pytest

from tencent_cloud_cartography.clb import listener
from tencent_cloud_cartography.clb_depth import collect, health
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.exposure import analyze
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.transport import CollectionError


def setup(change=None):
    g = Graph()
    lb = g.add("100", "eu-frankfurt", "clb.clb", "lb-one")
    vm = g.add("100", "eu-frankfurt", "cvm.instance", "ins-one")
    vpc = g.add("100", "eu-frankfurt", "vpc.vpc", "vpc-one")
    g.edge(lb, vpc, "IN_VPC")
    g.edge(vm, vpc, "IN_VPC")
    listener(
        g, g.nodes[lb], dict(ListenerId="lbl-one", Protocol="TCP", Port=80), "clb.DescribeListeners"
    )
    calls = []

    class Transport:
        def call(self, service, action, region=None, **params):
            calls.append((action, params))
            if action == "DescribeTargetGroups":
                return dict(
                    TotalCount=1,
                    TargetGroupSet=[
                        dict(
                            TargetGroupId="lbtg-one",
                            VpcId="vpc-one",
                            TargetGroupName="one",
                            AssociatedRule=[dict(LoadBalancerId="lb-one", ListenerId="lbl-one")],
                            HealthCheck=dict(
                                HealthSwitch=True,
                                Protocol="TCP",
                                GapTime=5,
                                SendContext="OMIT_PAYLOAD",
                            ),
                        )
                    ],
                )
            if action == "DescribeTargetGroupInstances":
                assert params["Filters"] == [dict(Name="TargetGroupId", Values=["lbtg-one"])]
                item = dict(
                    TargetGroupId="lbtg-one",
                    Type="CVM",
                    InstanceId="ins-one",
                    Port=80,
                    Weight=0,
                    PrivateIpAddresses=["10.0.0.2"],
                )
                if change == "parent":
                    item["TargetGroupId"] = "lbtg-other"
                return dict(TotalCount=1, RealCount=1, TargetGroupInstanceSet=[item])
            if action == "DescribeTargetGroupInstanceStatus":
                if change == "denied":
                    raise CollectionError("UnauthorizedOperation")
                return dict(
                    TargetGroupInstanceSet=[
                        dict(
                            InstanceId="ins-one",
                            InstanceIp="10.0.0.2" if change != "ip" else "10.0.0.3",
                            Port=80,
                            Status="health",
                        )
                    ]
                )
            if action == "DescribeRewrite":
                return dict(
                    RewriteSet=[
                        dict(
                            ListenerId="lbl-one",
                            LocationId="loc-one",
                            RewriteTarget=dict(
                                TargetListenerId="lbl-two", TargetLocationId="loc-two"
                            ),
                        )
                    ]
                )
            raise AssertionError(action)

    collect(
        CollectorRunner(g, Transport(), "100", ["eu-frankfurt"], lambda _: None), "eu-frankfurt"
    )
    return g, lb, vm, calls


def test_groups_backend_health_redirect_and_exposure_path():
    g, lb, vm, _ = setup()
    binding = next(n for n in g.nodes.values() if n["kind"] == "clb.targetbinding")
    assert binding["properties"]["Weight"] == 0
    assert binding["properties"]["reported_health"] == "health"
    assert not binding["properties"]["reachability_verified"]
    assert "OMIT_PAYLOAD" not in g.dump()
    assert any(e["relationship"] == "REDIRECTS_TO" for e in g.edges.values())
    analyze(g)
    assert any(
        e["source"] == lb and e["target"] == vm and e["relationship"] == "EXPOSE"
        for e in g.edges.values()
    )
    assert any(
        n["kind"] == "clb.exposurepath" and n["properties"]["frontend_id"] == binding["resource_id"]
        for n in g.nodes.values()
    )


@pytest.mark.parametrize("change", ["ip", "denied", "parent"])
def test_health_failure_preserves_other_configuration(change):
    g, *_ = setup(change)
    assert any(n["kind"] == "clb.targetgroup" for n in g.nodes.values())
    assert any(e["relationship"] == "REDIRECTS_TO" for e in g.edges.values())
    assert any(r["status"] not in ("empty", "complete") for r in g.coverage)
    assert not any(n["properties"].get("reported_health") for n in g.nodes.values())


def test_listener_health_omits_custom_bodies_and_url_credentials():
    config = json.loads(
        health(
            dict(
                HttpCheckPath="/ready?token=SECRET#x",
                HealthSwitch=1,
                SendContext="SECRET",
                RecvContext="SECRET",
            )
        )
    )
    assert config["HttpCheckPath"] == "/ready" and config["HealthSwitch"] == 1
    assert "SECRET" not in json.dumps(config)
    assert config["custom_probe_payload_retained"] is False


def test_traditional_clb_generation_listener_wide_backend_and_reported_health():
    from tencent_cloud_cartography.clb import collect_listeners

    g = Graph()
    lid = g.add("100", "eu-frankfurt", "clb.clb", "lb-one")
    g.nodes[lid]["properties"]["Forward"] = 0

    class T:
        def call(self, s, a, region=None, **params):
            assert a.startswith("DescribeClassicalLB")
            if a == "DescribeClassicalLBListeners":
                return dict(
                    Listeners=[
                        dict(
                            ListenerId="lbl-one",
                            ListenerPort=80,
                            InstancePort=8080,
                            Protocol="TCP",
                            HealthSwitch=1,
                        )
                    ]
                )
            if a == "DescribeClassicalLBTargets":
                return dict(
                    Targets=[
                        dict(
                            InstanceId="ins-one",
                            Type="CVM",
                            PrivateIpAddresses=["10.0.0.2"],
                            Weight=10,
                        )
                    ]
                )
            return dict(
                HealthList=[
                    dict(IP="10.0.0.2", Port=8080, ListenerPort=80, Protocol="TCP", HealthStatus=1)
                ]
            )

    collect_listeners(CollectorRunner(g, T(), "100", ["eu-frankfurt"], lambda _: None))
    binding = next(n for n in g.nodes.values() if n["kind"] == "clb.targetbinding")
    assert (
        binding["properties"]["reported_health"] == 1
        and not binding["properties"]["reachability_verified"]
    )
    assert binding["properties"]["Port"] == 8080
    assert all(r["status"] == "complete" for r in g.coverage)


@pytest.mark.parametrize("generation", [False, 2])
def test_invalid_clb_generation_does_not_select_native_listener_api(generation):
    from tencent_cloud_cartography.clb import collect_listeners

    graph = Graph()
    nid = graph.add("100", "eu-frankfurt", "clb.clb", "lb-one")
    graph.nodes[nid]["properties"]["Forward"] = generation

    class Transport:
        def call(self, *args, **kwargs):
            pytest.fail("Invalid generation must not select an API")

    collect_listeners(CollectorRunner(graph, Transport(), "100", ["eu-frankfurt"], lambda _: None))
    assert graph.coverage[-1]["error"] == "InvalidClbGeneration"
