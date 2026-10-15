from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.clb import listener, rule
from tencent_cloud_cartography.clb_backends import collect
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.exposure import analyze
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.network_parity import link

REGION = "ap-singapore"


def run(mutate=None):
    g = Graph()
    lb_id = g.add("100", REGION, "clb.clb", "lb-one", raw=dict(VpcId="vpc-one", Forward=1))
    g.nodes[lb_id]["properties"].update(VpcId="vpc-one", Forward=1)
    vpc = g.add("100", REGION, "vpc.vpc", "vpc-one")
    g.edge(lb_id, vpc, "IN_VPC")
    lid = listener(
        g,
        g.nodes[lb_id],
        dict(ListenerId="lbl-one", Protocol="HTTP", Port=80),
        "clb.DescribeListeners",
    )
    rule(
        g,
        g.nodes[lid],
        dict(LocationId="loc-one", Domain="example.test", Url="/"),
        "clb.DescribeListeners",
    )
    fn = g.add("100", REGION, "scf.function", "lam-one", "handler", raw=dict(Namespace="default"))
    calls = []

    def call(service, action, region=None, **params):
        calls.append(action)
        assert (service, action, region) == ("clb", "DescribeTargets", REGION)
        assert params == dict(LoadBalancerId="lb-one", ListenerIds=["lbl-one"])
        response = dict(
            Listeners=[
                dict(
                    ListenerId="lbl-one",
                    Rules=[
                        dict(
                            LocationId="loc-one",
                            FunctionTargets=[
                                dict(
                                    Function=dict(
                                        FunctionNamespace="default",
                                        FunctionName="handler",
                                        FunctionQualifier="prod",
                                        FunctionQualifierType="ALIAS",
                                    ),
                                    Weight=100,
                                    UserData="not-retained",
                                )
                            ],
                        )
                    ],
                )
            ]
        )
        return mutate(response) if mutate else response

    runner = CollectorRunner(g, SimpleNamespace(call=call), "100", [REGION], lambda _: None)
    collect(runner, g.nodes[lb_id])
    link(g)
    analyze(g)
    return g, fn, calls


def test_scf_backend_metadata_resolves_exact_function_and_configured_exposure():
    g, fn, calls = run()
    assert calls == ["DescribeTargets"]
    binding = next(n for n in g.nodes.values() if n["kind"] == "clb.functiontarget")
    assert binding["properties"]["FunctionQualifier"] == "prod"
    assert binding["properties"]["FunctionQualifierType"] == "ALIAS"
    assert binding["properties"]["function_resolution"] == "matched-collected-function"
    assert {e["target"] for e in g.edges.values() if e["relationship"] == "EXPOSE"} == {fn}
    assert "not-retained" not in g.dump()
    assert all(
        n["properties"]["reachability_verified"] is False
        for n in g.nodes.values()
        if n["kind"] == "clb.exposurepath"
    )


@pytest.mark.parametrize(
    "field,value",
    [("account", "200"), ("region", "eu-frankfurt"), ("status", "reference"), ("name", "other")],
)
def test_scf_wrong_or_missing_identity_stays_unresolved(field, value):
    g, fn, _ = run()
    g.nodes[fn][field] = value
    link(g)
    analyze(g)
    assert not any(e["relationship"] == "EXPOSE" for e in g.edges.values())
    assert any(r.get("error") == "UnresolvedClbFunctionTarget" for r in g.coverage)


@pytest.mark.parametrize("change", ["listener", "rule", "duplicate", "qualifier"])
def test_backend_api_validates_parent_and_duplicates_before_committing(change):
    def mutate(response):
        listener = response["Listeners"][0]
        rule = listener["Rules"][0]
        if change == "listener":
            listener["ListenerId"] = "lbl-other"
        elif change == "rule":
            rule["LocationId"] = "loc-other"
        elif change == "duplicate":
            rule["FunctionTargets"] *= 2
        else:
            rule["FunctionTargets"][0]["Function"]["FunctionQualifierType"] = "TOKEN"
        return response

    g, _, _ = run(mutate)
    assert not any(n["kind"] == "clb.functiontarget" for n in g.nodes.values())
    assert g.coverage[0]["status"] == "error"


def test_native_non_cvm_backend_identity_is_preserved():
    def mutate(response):
        listener = response["Listeners"][0]
        listener["Rules"][0].pop("FunctionTargets")
        listener["Targets"] = [
            dict(
                Type="ENI",
                InstanceId="eni-one",
                EniId="eni-one",
                PrivateIpAddresses=["10.0.0.8"],
                Port=80,
                Weight=20,
            ),
            dict(
                Type="SRV",
                InstanceId="service.example.test",
                PrivateIpAddresses=[],
                Port=8080,
                Weight=10,
            ),
        ]
        return response

    g, _, _ = run(mutate)
    bindings = [n for n in g.nodes.values() if n["kind"] == "clb.targetbinding"]
    assert {n["properties"]["Type"] for n in bindings} == {"ENI", "SRV"}
    assert any(
        n["kind"] == "vpc.networkinterface"
        and n["resource_id"] == "eni-one"
        and n["status"] == "reference"
        for n in g.nodes.values()
    )
    assert any(
        n["kind"] == "clb.target" and n["properties"].get("TargetId") == "service.example.test"
        for n in g.nodes.values()
    )
    assert any(r.get("error") == "UnresolvedClbBackend" for r in g.coverage)
