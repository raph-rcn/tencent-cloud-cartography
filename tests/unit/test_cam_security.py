import json

import pytest

from tencent_cloud_cartography.cam import add_document, parse_document
from tencent_cloud_cartography.cam_security import collect
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.permissions import analyze


def doc(effect="allow", action="*", resource="*", condition=None):
    row = dict(effect=effect, action=action, resource=resource)
    if condition:
        row["condition"] = condition
    return json.dumps(dict(version="2.0", statement=[row]))


def setup():
    g = Graph()
    uid = g.add("100", "global", "cam.user", "101")
    pid = g.add("100", "global", "cam.policy", "1")
    add_document(g, pid, parse_document(doc()), "fixture")
    g.edge(uid, pid, "HAS_POLICY")
    target = g.add("100", "eu-frankfurt", "ssm.secret", "secret")
    g.nodes[target]["properties"]["CreateUin"] = "101"
    for action in ("ListUsers", "ListGroups", "DescribeRoleList"):
        g.coverage.append(dict(account="100", service="cam", action=action, status="complete"))
    g.coverage.append(
        dict(
            account="100",
            service="cam",
            action="ListAttachedUserPolicies",
            status="complete",
            detail=json.dumps(dict(TargetUin=101)),
        )
    )
    return g, uid


def test_metadata_keys_protection_and_boundary_wrapped_document():
    g, uid = setup()

    class T:
        def call(self, s, a, region=None, **params):
            if a == "ListAccessKeys":
                assert params == dict(TargetUin=101)
                return dict(
                    AccessKeys=[
                        dict(
                            AccessKeyId="identifier",
                            Status="Inactive",
                            CreateTime="now",
                            SecretKey="OMIT",
                        )
                    ]
                )
            if a == "DescribeSafeAuthFlagColl":
                assert params == dict(SubUin=101)
                return dict(LoginFlag=dict(Stoken=1, Phone=0), PromptTrust=0)
            return dict(
                PolicyId=2,
                PolicyDocument=json.dumps(
                    dict(strategyInfo=json.loads(doc(action="ssm:GetSecretValue")))
                ),
            )

    collect(CollectorRunner(g, T(), "100", [], lambda _: None))
    assert "OMIT" not in g.dump()
    assert g.nodes[uid]["properties"]["boundary_collection_status"] == "collected"
    assert (
        json.loads(g.nodes[uid]["properties"]["protection_configuration"])["LoginFlag"]["Stoken"]
        == 1
    )
    analyze(g)
    decision = next(n for n in g.nodes.values() if n["kind"] == "cam.permissiondecision")
    assert (
        decision["properties"]["decision"] == "allow_from_collected_identity_and_boundary_policies"
    )
    assert decision["properties"]["boundary_evaluated"] is True
    assert not decision["properties"]["effective_access_verified"]


@pytest.mark.parametrize(
    "policy,expected",
    [
        (doc("deny"), "explicit_deny"),
        (doc(action="cos:GetObject"), "denied_by_collected_permission_boundary"),
        (doc(condition={"unknown": {"k": "v"}}), "conditional"),
    ],
)
def test_boundaries_restrict_identity_allow(policy, expected):
    g, uid = setup()
    bid = g.add("100", "global", "cam.boundary", "101/2")
    add_document(g, bid, parse_document(policy), "fixture")
    g.edge(uid, bid, "HAS_PERMISSION_BOUNDARY")
    analyze(g)
    node = next(n for n in g.nodes.values() if n["kind"] == "cam.permissiondecision")
    assert node["properties"]["decision"] == expected
    assert (
        len(
            [
                e
                for e in g.edges.values()
                if e["source"] == node["id"] and e["relationship"] == "BASED_ON_STATEMENT"
            ]
        )
        >= 1
    )


@pytest.mark.parametrize(
    "raw",
    [
        dict(PolicyId=None),
        dict(
            PolicyId=2,
            PolicyDocument='{"strategyInfo":{"version":"2.0","version":"2.0","statement":[]}}',
        ),
    ],
)
def test_missing_or_duplicate_boundary_is_not_interpreted_as_no_boundary(raw):
    g, uid = setup()

    class T:
        def call(self, s, a, region=None, **params):
            if a == "GetUserPermissionBoundary":
                return raw
            raise Exception("not relevant")

    # The fixture uses structured transport failures for unrelated metadata reads.
    from tencent_cloud_cartography.transport import CollectionError

    class SafeT(T):
        def call(self, s, a, region=None, **params):
            if a == "GetUserPermissionBoundary":
                return raw
            raise CollectionError("UnauthorizedOperation")

    collect(CollectorRunner(g, SafeT(), "100", [], lambda _: None))
    assert not any(n["kind"] == "cam.boundary" for n in g.nodes.values())
    assert g.coverage[-1]["status"] == "error"


def test_tat_precondition_requires_matching_online_registered_agent():
    g, uid = setup()
    vm = g.add("100", "eu-frankfurt", "cvm.instance", "ins-one")
    analyze(g)
    assert not any(n["properties"].get("action", "").startswith("tat:") for n in g.nodes.values())
    agent = g.add("100", "eu-frankfurt", "tat.agent", "ins-one")
    g.nodes[agent]["properties"]["AgentStatus"] = "Offline"
    g.edge(vm, agent, "HAS_AGENT_INFORMATION")
    analyze(g)
    assert not any(n["properties"].get("action", "").startswith("tat:") for n in g.nodes.values())
    g.nodes[agent]["properties"]["AgentStatus"] = "Online"
    analyze(g)
    decisions = [
        n for n in g.nodes.values() if n["properties"].get("action", "").startswith("tat:")
    ]
    assert len(decisions) == 2
    assert all(
        n["properties"]["target_precondition"] == "collected_online_tat_agent" for n in decisions
    )
    assert all(
        n["properties"]["resource_scope"] == "qcs::cvm:eu-frankfurt:uin/100:instance/ins-one"
        for n in decisions
    )
