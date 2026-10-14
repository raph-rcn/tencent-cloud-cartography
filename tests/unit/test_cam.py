import json

import pytest

from tencent_cloud_cartography.cam import add_document, collect_details, parse_document
from tencent_cloud_cartography.catalog import CHILDREN, COLLECTORS
from tencent_cloud_cartography.collect import CollectorRunner, collect
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph, stable_id
from tencent_cloud_cartography.topology import topology
from tencent_cloud_cartography.transport import CollectionError


def policy(effect="allow", **extra):
    return json.dumps(
        dict(
            version="2.0",
            statement=[
                dict(
                    effect=effect,
                    action=["name/cvm:DescribeInstances"],
                    resource="*",
                    **extra,
                )
            ],
        )
    )


def test_policy_conditions_deny_and_top_level_principal_are_preserved():
    graph = Graph()
    role = graph.add("100", "global", "cam.role", "7")
    raw = dict(
        version="2.0",
        principal={"qcs": ["qcs::cam::uin/200:uin/201"]},
        statement=[
            dict(
                effect="allow",
                action="name/sts:AssumeRole",
                condition={"string_equal": {"sts:external_id": "synthetic-condition"}},
            ),
            dict(effect="deny", action="name/sts:AssumeRole", principal="*"),
        ],
    )
    document = parse_document(json.dumps(raw), trust=True)
    add_document(graph, role, document, "cam.GetRole", trust=True)
    statements = [n for n in graph.nodes.values() if n["kind"] == "cam.truststatement"]
    assert [n["properties"]["effect"] for n in statements] == ["allow", "deny"]
    assert json.loads(statements[0]["properties"]["condition"]) == raw["statement"][0]["condition"]
    assert all(n["properties"]["access_evaluated"] is False for n in statements)
    assert stable_id("200", "global", "cam.user", "201") in graph.nodes
    assert {e["relationship"] for e in graph.edges.values()} == {
        "HAS_TRUST_STATEMENT",
        "NAMES_PRINCIPAL",
    }
    assert all(icon_for(n["kind"]) != "unmapped.svg" for n in graph.nodes.values())
    assert topology(graph.snapshot(), view="full")["stats"]["relationships"] == 4
    assert topology(graph.snapshot())["stats"]["resources"] == 0


def test_principal_identity_controls_keep_appid_and_wildcards_unresolved():
    graph = Graph()
    parent = graph.add("100", "global", "cam.role", "7")
    values = ["qcs::cam::uid/200:uin/201", "qcs::cam::uin/200:uin/*", "qcs::cam::uin/200:uin/200"]
    raw = policy(principal={"qcs": values, "service": "cvm.qcloud.com"})
    add_document(graph, parent, parse_document(raw, True), "cam.GetRole", True)
    assert stable_id("200", "global", "cam.user", "201") not in graph.nodes
    assert stable_id("200", "global", "cam.rootprincipal", "200") in graph.nodes
    assert len([n for n in graph.nodes.values() if n["kind"] == "cam.principal"]) == 3


@pytest.mark.parametrize(
    "raw",
    [
        '{"version":"2.0","version":"1.0","statement":[]}',
        '{"version":"2.0","statement":[{"effect":"allow","effect":"deny"}]}',
        policy(condition=[]),
        policy(notAction=["*"]),
        '{"version":"2.0","statement":[]}',
        '{"version":"2.0","statement":[{"effect":"allow","action":"*"}]}',
        '{"version":"2.0","statement":[{"effect":"allow","action":"*","resource":"*","condition":{"x":NaN}}]}',
    ],
)
def test_bad_or_unsupported_policy_is_rejected(raw):
    with pytest.raises(CollectionError):
        parse_document(raw)


def test_detail_failures_preserve_inventory_without_partial_policy_edges():
    graph = Graph()
    group = graph.add("100", "global", "cam.group", "1")
    role = graph.add("100", "global", "cam.role", "2")
    policy_id = graph.add("100", "global", "cam.policy", "3")

    class Broken:
        def call(self, service, action, **params):
            if action == "GetGroup":
                return dict(GroupId=1, GroupNum=2, UserInfo=[dict(Uin=101)], RequestId="partial")
            if action == "GetRole":
                return dict(RoleInfo=dict(RoleId="999", PolicyDocument=policy()), RequestId="wrong")
            raise CollectionError("UnauthorizedOperation")

    collect_details(CollectorRunner(graph, Broken(), "100", [], lambda _: None))
    assert set(graph.nodes) == {group, role, policy_id} and not graph.edges
    assert [s["error"] for s in graph.coverage] == [
        "CountMismatch",
        "IdentityMismatch",
        "UnauthorizedOperation",
    ]
    assert graph.coverage[0]["request_ids"] == ["partial"]
    assert graph.snapshot()["status"] == "partial"


def test_end_to_end_cam_memberships_attachments_details_and_owner_isolation():
    calls = []
    specs = {s.action: s for s in (*COLLECTORS, *CHILDREN.values()) if s.service == "cam"}

    class CamTransport:
        def call(self, service, action, region=None, **params):
            calls.append((service, action, params))
            if service == "sts":
                return dict(AccountId="100", PrincipalId="test")
            if service == "cloudrc":
                return dict(Resources=[])
            if action == "GetGroup":
                assert params == {"GroupId": 9}
                return dict(
                    GroupId=9,
                    GroupNum=1,
                    UserInfo=[dict(Uin=101, Uid=999, Name="reader", Email="omit@example.test")],
                    RequestId="members",
                )
            if action == "GetRole":
                assert params == {"RoleId": "7"}
                return dict(
                    RoleInfo=dict(
                        RoleId="7",
                        RoleType="user",
                        SessionDuration=7200,
                        PolicyDocument=policy(principal={"qcs": "qcs::cam::uin/200:roleid/8"}),
                    ),
                    RequestId="trust",
                )
            if action == "GetPolicy":
                assert params["PolicyId"] in {11, 12, 13}
                return dict(
                    PolicyName="example",
                    PolicyDocument=policy(
                        "deny", condition={"ip_equal": {"qcs:ip": "192.0.2.0/24"}}
                    ),
                    SecretKey="omit-secret",
                    RequestId="policy",
                )
            if action == "ListAccessKeys":
                return dict(AccessKeys=[])
            if action == "DescribeSafeAuthFlagColl":
                return dict(PromptTrust=0)
            if action in ("GetUserPermissionBoundary", "GetRolePermissionBoundary"):
                return dict(PolicyId=1, PolicyDocument=policy())
            if action == "ListSAMLProviders":
                return dict(SAMLProviderSet=[], TotalCount=0)
            if action == "DescribeUserOIDCConfig":
                return dict(Status=0)
            spec = specs[action]
            if action == "ListPolicies":
                assert params["Scope"] == "Local"
            if action == "ListAttachedGroupPolicies":
                assert params["TargetGroupId"] == 9
            data = {
                "ListUsers": [dict(Uin=101, Name="reader")],
                "DescribeRoleList": [dict(RoleId="7", RoleName="operator")],
                "ListGroups": [dict(GroupId=9, GroupName="readers")],
                "ListPolicies": [dict(PolicyId=13, PolicyName="local-unused")],
                "ListAttachedUserPolicies": [dict(PolicyId=11, PolicyName="direct")],
                "ListAttachedRolePolicies": [dict(PolicyId=12, PolicyName="role")],
                "ListAttachedGroupPolicies": [dict(PolicyId=11, PolicyName="direct")],
            }[action]
            result = {spec.result: data, "RequestId": action}
            if spec.total:
                result[spec.total] = len(data)
            return result

    snapshot = collect(
        ["test"],
        ["eu-frankfurt"],
        services={"cam"},
        progress=lambda _: None,
        transport_factory=lambda _: CamTransport(),
    )
    graph = {n["id"]: n for n in snapshot["nodes"]}
    assert "omit-secret" not in json.dumps(snapshot) and "omit@example.test" not in json.dumps(
        snapshot
    )
    membership = [e for e in snapshot["edges"] if e["relationship"] == "MEMBER_OF"]
    assert len(membership) == 1
    assert graph[membership[0]["source"]]["resource_id"] == "101"  # UIN, never UID.
    assert graph[membership[0]["target"]]["resource_id"] == "9"
    attachments = [e for e in snapshot["edges"] if e["relationship"] == "HAS_POLICY"]
    assert len(attachments) == 3
    assert len([c for c in calls if c[1] == "GetPolicy"]) == 3  # Shared policy fetched once.
    assert len([c for c in calls if c[1] == "GetRole"]) == 1  # No request for foreign role 8.
    assert len([n for n in graph.values() if n["kind"] == "cam.policystatement"]) == 5
    assert all(c["status"] in {"complete", "empty", "not-queried"} for c in snapshot["coverage"])
