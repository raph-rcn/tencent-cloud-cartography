import copy
from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.dlc_authorization_metadata import collect, details, inventory
from tencent_cloud_cartography.model import Graph

REGION = "eu-frankfurt"


def run(call):
    graph = Graph()
    runner = CollectorRunner(graph, SimpleNamespace(call=call), "100", [REGION], lambda _: None)
    collect(runner, REGION)
    return graph


def api(service, action, region=None, **params):
    assert service == "dlc" and region == REGION
    if action == "DescribeUsers":
        assert params["AccountType"] in {"TencentAccount", "EntraAccount"}
        return dict(
            TotalCount=1,
            UserSet=[dict(UserId="same-id", AccountType=params["AccountType"], UserType="COMMON")],
        )
    if action == "DescribeWorkGroups":
        return dict(TotalCount=1, WorkGroupSet=[dict(WorkGroupId=7, WorkGroupName="analysts")])
    user = action == "DescribeUserInfo"
    root = "UserInfo" if user else "WorkGroupInfo"
    typ = params["Type"]
    if typ in {"DataAuth", "EngineAuth"}:
        key = "DataPolicyInfo" if typ == "DataAuth" else "EnginePolicyInfo"
        nested = dict(
            TotalCount=1,
            PolicySet=[
                dict(
                    PolicyType="User" if user else "WorkGroup",
                    Operation="SELECT",
                    Catalog="DataLakeCatalog",
                    Database="analytics",
                    Table="orders",
                    DataEngine="warehouse",
                    ReAuth=False,
                    PolicyId="policy-1",
                )
            ],
        )
    elif typ == "Group":
        key = "WorkGroupInfo"
        nested = dict(TotalCount=1, WorkGroupSet=[dict(WorkGroupId=7, WorkGroupName="analysts")])
    else:
        key = "UserInfo"
        nested = dict(TotalCount=1, UserSet=[dict(UserId="same-id", AccountType="EntraAccount")])
    meta = dict(Type=typ, **{key: nested})
    if user:
        meta.update(UserId=params["UserId"], AccountType=params["AccountType"])
    else:
        meta["WorkGroupId"] = params["WorkGroupId"]
    return {root: meta, "RequestId": "fixture"}


def test_both_user_namespaces_complete_grant_and_membership_scopes():
    g = run(api)
    users = [n for n in g.nodes.values() if n["kind"] == "dlc.user"]
    assert len(users) == 2 and users[0]["id"] != users[1]["id"]
    assert {n["properties"]["AccountType"] for n in users} == {"TencentAccount", "EntraAccount"}
    assert len([n for n in g.nodes.values() if n["kind"] == "dlc.accesspolicy"]) == 6
    assert len([n for n in g.nodes.values() if n["kind"] == "dlc.membership"]) == 3
    assert all(c["status"] == "complete" for c in g.coverage)
    assert not any(n["kind"].startswith("cam.") for n in g.nodes.values())
    assert all(not n["properties"].get("query_access_verified", False) for n in g.nodes.values())


@pytest.mark.parametrize(
    "bad", ["identity", "type", "namespace", "total", "duplicate", "bad-policy"]
)
def test_invalid_nested_policy_pages_fail_without_publishing_grants(bad):
    g = Graph()
    runner = CollectorRunner(g, SimpleNamespace(call=api), "100", [REGION], lambda _: None)
    p = inventory(runner, REGION, "dlc.user", "TencentAccount")[0]

    def broken(service, action, region=None, **params):
        data = copy.deepcopy(api(service, action, region, **params))
        meta = data["UserInfo"]
        if bad == "identity":
            meta["UserId"] = "other"
        elif bad == "type":
            meta["Type"] = "Group"
        elif bad == "namespace":
            meta["AccountType"] = "EntraAccount"
        elif bad == "total":
            meta["DataPolicyInfo"]["TotalCount"] = None
        elif bad == "duplicate":
            meta["DataPolicyInfo"]["PolicySet"] *= 2
            meta["DataPolicyInfo"]["TotalCount"] = 2
        else:
            del meta["DataPolicyInfo"]["PolicySet"][0]["Operation"]
        return data

    runner.transport.call = broken
    details(runner, p, "DataAuth")
    assert g.coverage[-1]["status"] == "error" and len(g.nodes) == 1


def test_nested_grants_paginate_beyond_first_page():
    g = Graph()
    runner = CollectorRunner(g, SimpleNamespace(call=api), "100", [REGION], lambda _: None)
    p = inventory(runner, REGION, "dlc.user", "TencentAccount")[0]
    offsets = []

    def paged(service, action, region=None, **params):
        data = api(service, action, region, **params)
        offsets.append(params["Offset"])
        data["UserInfo"]["DataPolicyInfo"] = dict(
            TotalCount=101,
            PolicySet=[
                dict(PolicyId=str(i), PolicyType="User", Operation="SELECT", Table=f"table-{i}")
                for i in range(params["Offset"], min(101, params["Offset"] + params["Limit"]))
            ],
        )
        return data

    runner.transport.call = paged
    details(runner, p, "DataAuth")
    assert offsets == [0, 100] and g.coverage[-1]["count"] == 101


def test_native_memberships_and_engine_references_use_exact_scoped_identity():
    from tencent_cloud_cartography.dlc_authorization_metadata import link

    g = run(api)
    wrong = g.add("200", REGION, "dlc.engine", "other")
    g.nodes[wrong]["properties"]["DataEngineName"] = "warehouse"
    engine = g.add("100", REGION, "dlc.engine", "one")
    g.nodes[engine]["properties"]["DataEngineName"] = "warehouse"
    link(g)
    assert {
        e["target"] for e in g.edges.values() if e["relationship"] == "REFERENCES_DATA_ENGINE"
    } == {engine}
    assert (
        len([e for e in g.edges.values() if e["relationship"] == "REFERENCES_NATIVE_MEMBER"]) == 3
    )
    before = g.dump()
    link(g)
    assert before == g.dump()
    duplicate = g.add("100", REGION, "dlc.engine", "two")
    g.nodes[duplicate]["properties"]["DataEngineName"] = "warehouse"
    link(g)
    assert not any(e["relationship"] == "REFERENCES_DATA_ENGINE" for e in g.edges.values())
