import json

import pytest

from tencent_cloud_cartography.cam import add_document, parse_document
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.permissions import analyze, evaluate


def statement(effect="allow", action="name/ssm:GetSecretValue", resource="*", **extra):
    return dict(effect=effect, action=[action], resource=[resource], **extra)


def fixture(statements=None):
    g = Graph()
    user = g.add("100", "global", "cam.user", "101", "Reader")
    policy = g.add("100", "global", "cam.policy", "1", "Secret access")
    add_document(
        g,
        policy,
        parse_document(json.dumps(dict(version="2.0", statement=statements or [statement()]))),
        "synthetic",
    )
    g.edge(user, policy, "HAS_POLICY", "synthetic")
    target = g.add("100", "eu-frankfurt", "ssm.secret", "demo-secret", "Demo secret")
    g.nodes[target]["properties"].update(CreateUinString="101")
    for action in ("ListUsers", "ListGroups", "DescribeRoleList"):
        g.coverage.append(
            dict(account="100", service="cam", action=action, status="complete", count=1)
        )
    g.coverage.append(
        dict(
            account="100",
            service="cam",
            action="ListAttachedUserPolicies",
            status="complete",
            detail=json.dumps(dict(TargetUin=101)),
        )
    )
    return g, user, policy, target


def decisions(g):
    return [n for n in g.nodes.values() if n["kind"] == "cam.permissiondecision"]


def test_identity_allow_evidence_graph_and_creator_identity():
    g, *_ = fixture()
    analyze(g)
    node = decisions(g)[0]
    p = node["properties"]
    assert p["decision"] == "allow_from_collected_identity_policies"
    assert p["resource_scope"] == "qcs::ssm:eu-frankfurt:uin/100:secret/creatorUin/101/demo-secret"
    assert not p["effective_access_verified"] and p["policy_collection_complete"]
    assert icon_for(node["kind"]) == "en-cloud-access-management.svg"
    assert {e["relationship"] for e in g.edges.values()} >= {
        "HAS_PERMISSION_ANALYSIS",
        "TARGETS_RESOURCE",
        "BASED_ON_STATEMENT",
    }


@pytest.mark.parametrize(
    "effect,condition,expected",
    [
        ("allow", None, "allow_from_collected_identity_policies"),
        (
            "allow",
            {"ip_equal": {"qcs:ip": "192.0.2.0/24"}},
            "allow_from_collected_identity_policies",
        ),
        ("deny", None, "explicit_deny"),
        ("deny", {"unknown": {"key": "value"}}, "conditional"),
    ],
)
def test_deny_precedence_and_conditions(effect, condition, expected):
    row = statement(effect)
    if condition:
        row["condition"] = condition
    decision, _ = evaluate(
        [("allow", statement()), ("second", row)],
        "ssm:GetSecretValue",
        "qcs::ssm:r:uin/100:secret/s",
    )
    assert decision == expected


def test_deny_in_separate_group_policy_overrides_direct_allow():
    g, user, _, _ = fixture()
    group = g.add("100", "global", "cam.group", "9")
    policy = g.add("100", "global", "cam.policy", "2")
    add_document(
        g,
        policy,
        parse_document(json.dumps(dict(version="2.0", statement=[statement("deny")]))),
        "synthetic",
    )
    g.edge(user, group, "MEMBER_OF")
    g.edge(group, policy, "HAS_POLICY")
    g.coverage.extend(
        [
            dict(account="100", service="cam", action="GetGroup", detail="9", status="complete"),
            dict(
                account="100",
                service="cam",
                action="ListAttachedGroupPolicies",
                detail=json.dumps(dict(TargetGroupId=9)),
                status="complete",
            ),
        ]
    )
    analyze(g)
    assert decisions(g)[0]["properties"]["decision"] == "explicit_deny"


@pytest.mark.parametrize(
    "change",
    ["no-records", "denied", "missing-attachment", "missing-policy", "missing-group-detail"],
)
def test_incomplete_policy_inventory_cannot_produce_allow(change):
    g, *_ = fixture()
    if change == "no-records":
        g.coverage = []
    elif change == "denied":
        g.coverage[0]["status"] = "denied"
    elif change == "missing-attachment":
        g.coverage.pop()
    elif change == "missing-policy":
        next(n for n in g.nodes.values() if n["kind"] == "cam.policy")["properties"].pop(
            "policy_document"
        )
    else:
        g.add("100", "global", "cam.group", "unqueried")
    analyze(g)
    assert decisions(g)[0]["properties"]["decision"] == "incomplete"
    assert g.coverage[-1]["status"] == "error"


def test_unconditional_explicit_deny_survives_incomplete_inventory():
    d, _ = evaluate(
        [("1", statement("deny"))],
        "ssm:GetSecretValue",
        "qcs::ssm:r:uin/100:secret/x",
        complete=False,
    )
    assert d == "explicit_deny"


@pytest.mark.parametrize(
    "values",
    [
        dict(action=["ssm:getsecretvalue"]),
        dict(action=["ssm:GetSecretValue?"]),
        dict(resource=["qcs::ssm:ap-singapore:uin/100:secret/*"]),
        dict(resource=["qcs::ssm:eu-frankfurt:uin/200:secret/*"]),
        dict(resource=["qcs::ssm:eu-frankfurt:uin/100:secret/creatorUin/999/*"]),
    ],
)
def test_action_case_account_region_creator_and_unsupported_controls(values):
    row = statement()
    row.update(values)
    g, *_ = fixture([row])
    analyze(g)
    assert decisions(g)[0]["properties"]["decision"] != "allow_from_collected_identity_policies"


def test_unknown_policy_expression_and_principal_are_conservative():
    for extra in (dict(resource=["${resource}"]), dict(principal="*")):
        row = statement()
        row.update(extra)
        d, _ = evaluate([("1", row)], "ssm:GetSecretValue", "resource")
        assert d in {"conditional", "incomplete"}


def test_missing_creator_is_visible_and_does_not_taint_other_targets_by_order():
    g, *_ = fixture()
    missing = g.add("100", "eu-frankfurt", "ssm.secret", "missing")
    # Reverse target order to detect accidental state mutation while iterating.
    g.nodes = {missing: g.nodes[missing], **{k: v for k, v in g.nodes.items() if k != missing}}
    analyze(g)
    assert (
        len(decisions(g)) == 1
        and decisions(g)[0]["properties"]["decision"] == "allow_from_collected_identity_policies"
    )
    assert g.coverage[-1]["status"] == "error"


def test_role_id_and_name_aliases_share_deny_decision():
    g, user, policy, _ = fixture(
        [
            statement(action="cam:PassRole"),
            statement("deny", action="name/cam:PassRole", resource="qcs::cam::uin/100:role/7"),
        ]
    )
    role = g.add("100", "global", "cam.role", "7", "Worker role")
    g.nodes[role]["properties"].update(RoleArn="qcs::cam::uin/100:role/7", RoleName="Worker")
    analyze(g)
    matched = [
        n
        for n in decisions(g)
        if n["properties"]["action"] == "cam:PassRole"
        and any(e["source"] == n["id"] and e["target"] == role for e in g.edges.values())
        and any(e["source"] == user and e["target"] == n["id"] for e in g.edges.values())
    ]
    assert matched and all(n["properties"]["decision"] == "explicit_deny" for n in matched)
    assert not any(e["relationship"] == "CAN_PASS_ROLE" for e in g.edges.values())


def test_cos_object_prefixes_remain_scoped_and_subset_denies_are_conditional():
    prefix = "qcs::cos:eu-frankfurt:uid/12345:demo-12345/"
    g, *_ = fixture(
        [
            statement(action="cos:GetObject", resource=prefix + "docs/*"),
            statement("deny", action="cos:GetObject", resource=prefix + "docs/private/*"),
        ]
    )
    g.add("100", "eu-frankfurt", "cos.bucket", "demo-12345")
    analyze(g)
    read = [n for n in decisions(g) if n["properties"]["action"] == "cos:GetObject"][0]
    assert read["properties"]["resource_scope"] == prefix + "docs/*"
    assert read["properties"]["decision"] == "conditional"
    write = [n for n in decisions(g) if n["properties"]["action"] == "cos:PutObject"][0]
    assert write["properties"]["decision"] == "implicit_deny_from_collected_identity_policies"


def test_disjoint_cos_object_deny_does_not_block_granted_prefix():
    prefix = "qcs::cos:eu-frankfurt:uid/12345:demo-12345/"
    g, *_ = fixture(
        [
            statement(action="cos:GetObject", resource=prefix + "docs/*"),
            statement("deny", action="cos:GetObject", resource=prefix + "other/*"),
        ]
    )
    g.add("100", "eu-frankfurt", "cos.bucket", "demo-12345")
    analyze(g)
    read = [n for n in decisions(g) if n["properties"]["action"] == "cos:GetObject"][0]
    assert read["properties"]["decision"] == "allow_from_collected_identity_policies"


def test_foreign_account_targets_do_not_receive_identity_policy_edges():
    g, *_ = fixture()
    g.add("200", "eu-frankfurt", "cos.bucket", "foreign-12345")
    analyze(g)
    assert len(decisions(g)) == 1


def test_reanalysis_removes_stale_allow_and_is_idempotent():
    g, user, policy, _ = fixture()
    analyze(g)
    first = g.dump()
    analyze(g)
    assert g.dump() == first
    # Replace policy document and its statement evidence with an explicit deny.
    add_document(
        g,
        policy,
        parse_document(json.dumps(dict(version="2.0", statement=[statement("deny")]))),
        "synthetic",
    )
    analyze(g)
    assert len(decisions(g)) == 1 and decisions(g)[0]["properties"]["decision"] == "explicit_deny"


def test_conditional_allow_alone_cannot_become_unconditional():
    d, _ = evaluate(
        [("one", statement(condition={"ip_equal": {"qcs:ip": "192.0.2.0/24"}}))],
        "ssm:GetSecretValue",
        "secret",
    )
    assert d == "conditional"


@pytest.mark.parametrize(
    "extra",
    [
        dict(action=["permid/123"]),
        dict(resource=["qcs:project:cam::uin/100:role/*"]),
        dict(action=["ssm:getsecretvalue"]),
    ],
)
def test_unexpanded_function_sets_and_legacy_project_semantics_cannot_hide_deny(extra):
    deny = statement("deny")
    deny.update(extra)
    d, _ = evaluate(
        [("allow", statement()), ("deny", deny)],
        "ssm:GetSecretValue",
        "qcs::ssm:r:uin/100:secret/x",
    )
    assert d == "incomplete"


def test_offline_cli_preserves_inputs_and_makes_no_cloud_call(tmp_path, monkeypatch):
    from tencent_cloud_cartography.cli import main
    from tencent_cloud_cartography.storage import load, save
    from tencent_cloud_cartography.transport import TccliTransport

    def forbidden(*args, **kwargs):
        raise AssertionError("No cloud calls allowed")

    monkeypatch.setattr(TccliTransport, "call", forbidden)
    g, *_ = fixture()
    g.mode = "demo"
    original = g.snapshot()
    before, after = tmp_path / "before.json", tmp_path / "after.json"
    save(original, before)
    assert main(["analyze", "--input", str(before), "--output", str(after)]) == 0
    result = load(after)
    assert load(before) == original
    assert result["mode"] == "demo" and result["created_at"] == original["created_at"]
    assert any(n["kind"] == "cam.permissiondecision" for n in result["nodes"])


def test_unsupported_expression_marks_snapshot_partial_even_with_complete_collection():
    g, *_ = fixture([statement(action="permid/123")])
    analyze(g)
    assert decisions(g)[0]["properties"]["decision"] == "incomplete"
    assert g.coverage[-1]["status"] == "error"
    assert g.snapshot()["status"] == "partial"
