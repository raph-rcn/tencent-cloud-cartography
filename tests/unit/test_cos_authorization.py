import json
from copy import deepcopy

import pytest
from authorization_fixtures import PREFIX, add_policy, fixture, principal, statement

from tencent_cloud_cartography.cos import ALL_USERS, acl
from tencent_cloud_cartography.cos_authorization import analyze
from tencent_cloud_cartography.public_access import analyze as public_analysis


def result(g, uid, action="cos:GetObject", scope=PREFIX + "*"):
    return next(
        n["properties"]
        for n in g.nodes.values()
        if n["kind"] == "cos.authorizationdecision"
        and n["properties"]["principal_id"] == g.nodes[uid]["resource_id"]
        and n["properties"]["action"] == action
        and n["properties"]["resource_scope"] == scope
    )


def named(effect="allow", owner="100", rid="101", **extra):
    return statement(effect, principal={"qcs": [f"qcs::cam::uin/{owner}:uin/{rid}"]}, **extra)


@pytest.mark.parametrize(
    "identity,resource,expected",
    [
        ([statement()], None, "allowed"),
        ([statement()], [named("deny")], "denied"),
        ([statement("deny")], [named()], "denied"),
        ([], [named()], "allowed"),
        ([], None, "unknown"),
        ([statement()], [named("deny", rid="999")], "allowed"),
        ([statement()], [named("deny", resource=PREFIX + "private/*")], "conditional"),
    ],
)
def test_named_policy_union_and_deny_precedence(identity, resource, expected):
    g, uid, _ = fixture(identity, resource)
    analyze(g)
    props = result(g, uid)
    assert props["decision"] == expected
    assert (
        props["effective_access_decision"] == "unknown" and not props["effective_access_verified"]
    )


@pytest.mark.parametrize(
    "identity,resource,expected",
    [
        ([statement()], [named()], "allowed"),
        ([statement()], None, "unknown"),
        ([], [named()], "denied"),
        ([statement("deny")], [named()], "denied"),
        ([statement()], [named("deny")], "denied"),
    ],
)
def test_cross_account_requires_both_collected_grants(identity, resource, expected):
    g, uid, _ = fixture(identity, resource, owner="200")
    analyze(g)
    props = result(g, uid)
    assert props["cross_account"] and props["decision"] == expected
    assert props["cross_account_gate"] == "identity_and_resource"


@pytest.mark.parametrize(
    "selector",
    [{"qcs": ["qcs::cam::anyone:anyone"]}, {"qcs": ["qcs::cam::anonymous:anonymous"]}, "*"],
)
def test_anonymous_deny_is_not_a_deny_for_signed_identity(selector):
    g, uid, _ = fixture(resource=[statement("deny", principal=selector)])
    public_analysis(g)
    analyze(g)
    props = result(g, uid)
    assert props["decision"] == "allowed" and props["anonymous_route_decision"] == "denied"
    assert any(e["relationship"] == "ALTERNATIVE_UNSIGNED_ANALYSIS" for e in g.edges.values())


def test_anonymous_allow_is_separate_even_when_named_identity_explicitly_denied():
    g, uid, _ = fixture(
        [statement("deny")], [statement(principal={"qcs": ["qcs::cam::anyone:anyone"]})]
    )
    analyze(g)
    props = result(g, uid)
    assert props["decision"] == "denied" and props["anonymous_route_decision"] == "allowed"


@pytest.mark.parametrize("scope", [PREFIX + "docs/*", PREFIX + "one.txt"])
def test_object_prefixes_keep_exact_scopes_and_no_false_bucketwide_allow(scope):
    g, uid, _ = fixture([statement(resource=scope)], None)
    analyze(g)
    assert result(g, uid, scope=scope)["decision"] == "allowed"
    assert result(g, uid)["decision"] == "conditional"


@pytest.mark.parametrize(
    "boundary,missing,expected",
    [
        ([statement()], False, "allowed"),
        ([statement("deny")], False, "denied"),
        ([statement(action="cos:PutObject")], False, "denied"),
        (None, True, "unknown"),
    ],
)
def test_permission_boundary_unknowns_and_intersection(boundary, missing, expected):
    g, uid, _ = fixture(boundary=False)
    if not missing:
        add_policy(g, uid, boundary, True)
    analyze(g)
    assert result(g, uid)["decision"] == expected


def test_resource_only_grant_implicit_boundary_deny_is_not_an_aws_semantics_guess():
    g, uid, _ = fixture([], [named()], boundary=False)
    add_policy(g, uid, [statement(action="cos:PutObject")], True)
    analyze(g)
    assert result(g, uid)["decision"] == "unknown"
    assert result(g, uid)["decision_reason"] == "resource_grant_boundary_interaction_unverified"


def test_missing_bucket_policy_or_identity_read_suppresses_allow_but_not_known_deny():
    for broken in ("resource", "identity"):
        g, uid, bid = fixture()
        if broken == "resource":
            g.nodes[bid]["properties"].update(policy_collected=False, policy_absent=False)
        else:
            g.coverage[0]["status"] = "denied"
        analyze(g)
        assert result(g, uid)["decision"] == "unknown"
        add_policy(g, uid, [statement("deny")])
        analyze(g)
        assert result(g, uid)["decision"] == "denied"


def test_declared_ip_conditions_and_snapshot_idempotence():
    g, uid, _ = fixture([statement(condition={"ip_equal": {"qcs:ip": "192.0.2.0/24"}})])
    analyze(g)
    assert result(g, uid)["decision"] == "conditional"
    analyze(g, {"qcs:ip": "192.0.2.1"})
    assert result(g, uid)["decision"] == "allowed"
    analyze(g, {"qcs:ip": "198.51.100.1"})
    assert result(g, uid)["decision"] == "unknown"
    before = deepcopy(g.snapshot())
    analyze(g, {"qcs:ip": "198.51.100.1"})
    assert before == g.snapshot()


def test_exact_group_membership_and_owner_namespace_isolation():
    g, uid, _ = fixture([], [statement(principal={"qcs": ["qcs::cam::uin/100:groupid/9"]})])
    group = g.add("100", "global", "cam.group", "9")
    g.edge(uid, group, "MEMBER_OF")
    g.coverage.append(
        dict(account="100", service="cam", action="GetGroup", detail="9", status="complete")
    )
    g.coverage.append(
        dict(
            account="100",
            service="cam",
            action="ListAttachedGroupPolicies",
            detail=json.dumps(dict(TargetGroupId=9)),
            status="empty",
        )
    )
    foreign = principal(g, "300", "101", rows=[])
    analyze(g)
    assert result(g, uid)["decision"] == "allowed"
    props = [
        n["properties"]
        for n in g.nodes.values()
        if n["kind"] == "cos.authorizationdecision"
        and n["properties"]["principal_account"] == "300"
    ]
    assert all(p["decision"] != "allowed" for p in props)
    g.coverage = [r for r in g.coverage if r.get("action") != "GetGroup"]
    analyze(g)
    assert result(g, uid)["decision"] == "unknown"
    assert g.nodes[foreign]["account"] == "300"


def test_named_acl_object_read_requires_inheritance_but_bucket_list_does_not():
    g, uid, bid = fixture([])
    acl(
        g,
        g.nodes[bid],
        dict(
            Owner=dict(ID="qcs::cam::uin/100:uin/100"),
            AccessControlList=dict(
                Grant=[dict(Grantee=dict(ID="qcs::cam::uin/100:uin/101"), Permission="READ")]
            ),
        ),
        "fixture",
    )
    analyze(g)
    assert result(g, uid)["decision"] == "conditional"
    assert (
        result(g, uid, "cos:GetBucket", json.dumps([PREFIX, PREFIX + "*"]))["decision"] == "allowed"
    )


def test_public_bucket_acl_does_not_fabricate_named_signed_grant():
    g, uid, bid = fixture([])
    acl(
        g,
        g.nodes[bid],
        dict(
            Owner=dict(ID="qcs::cam::uin/100:uin/100"),
            AccessControlList=dict(Grant=[dict(Grantee=dict(URI=ALL_USERS), Permission="READ")]),
        ),
        "fixture",
    )
    analyze(g)
    props = result(g, uid, "cos:GetBucket", json.dumps([PREFIX, PREFIX + "*"]))
    assert props["decision"] == "denied" and props["anonymous_route_decision"] == "allowed"


def test_account_grant_is_delegated_not_a_direct_same_account_child_grant():
    g, uid, _ = fixture([], [named(rid="100")])
    analyze(g)
    assert result(g, uid)["decision"] != "allowed"


def test_implicit_resource_owner_is_resolved_only_for_the_policy_owner():
    g, uid, _ = fixture([statement(resource="qcs::cos:eu-frankfurt::docs-12345/*")])
    analyze(g)
    assert result(g, uid)["decision"] == "allowed"
    g.nodes[next(n["id"] for n in g.nodes.values() if n["kind"] == "cos.bucket")]["account"] = "200"
    analyze(g)
    assert result(g, uid)["decision"] == "unknown"


@pytest.mark.parametrize(
    "owner,expected", [("uin/100", "allowed"), ("uid/100", "unknown"), ("uin/", "allowed")]
)
def test_owner_format_uses_collected_bucket_association_never_numeric_equality(owner, expected):
    g, uid, _ = fixture([statement(resource=f"qcs::cos:eu-frankfurt:{owner}:docs-12345/*")])
    analyze(g)
    assert result(g, uid)["decision"] == expected


def test_bucket_root_is_not_an_empty_object_and_normalized_prefixes_remain_precise():
    g, uid, _ = fixture([statement(resource=PREFIX)])
    analyze(g)
    assert not any(
        n["kind"] == "cos.authorizationdecision"
        and n["properties"]["action"] == "cos:GetObject"
        and n["properties"]["resource_scope"] == PREFIX
        for n in g.nodes.values()
    )
    g, uid, _ = fixture([statement(resource="qcs::cos:eu-frankfurt:uin/100:docs-12345/docs/*")])
    analyze(g)
    assert result(g, uid, scope=PREFIX + "docs/*")["decision"] == "allowed"
    assert result(g, uid)["decision"] == "conditional"
