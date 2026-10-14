from copy import deepcopy

import pytest
from authorization_fixtures import add_policy, bucket, principal, statement, trust

from tencent_cloud_cartography.cos_authorization import analyze as cos_analysis
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.role_assumption import analyze


def setup(identity=True, trust_effect="allow", boundary=True, condition=None):
    g = Graph(mode="demo")
    user = principal(
        g, rows=[statement(action="sts:AssumeRole")] if identity else [], boundary=boundary
    )
    role = principal(g, "200", "7", "cam.role", rows=[statement()])
    row = dict(
        effect=trust_effect,
        action=["sts:AssumeRole"],
        principal={"qcs": ["qcs::cam::uin/100:root"]},
    )
    if condition:
        row["condition"] = condition
    trust(g, role, [row])
    return g, user, role


def result(g, uid, role):
    did = next(
        e["target"]
        for e in g.edges.values()
        if e["source"] == uid and e["relationship"] == "HAS_ASSUMPTION_ANALYSIS"
    )
    assert any(
        e["source"] == did and e["target"] == role and e["relationship"] == "TARGETS_ROLE"
        for e in g.edges.values()
    )
    return g.nodes[did]["properties"]


@pytest.mark.parametrize(
    "identity,effect,boundary,expected",
    [
        (True, "allow", True, "allowed"),
        (False, "allow", True, "denied"),
        (True, "deny", True, "denied"),
        (True, "allow", False, "unknown"),
    ],
)
def test_role_assumption_requires_caller_authorization_boundary_and_trust(
    identity, effect, boundary, expected
):
    g, user, role = setup(identity, effect, boundary)
    analyze(g)
    props = result(g, user, role)
    assert props["decision"] == expected and props["cross_account"]
    assert (
        props["effective_access_decision"] == "unknown"
        and not props["effective_assumption_verified"]
    )
    assert "sts:AssumeRole" not in {
        r.get("action") for r in g.coverage if r.get("service") == "sts"
    }


@pytest.mark.parametrize(
    "expression,expected",
    [
        ("qcs::cam::uin/100:uin/101", "allowed"),
        ("qcs::cam::uin/100:uin/999", "denied"),
        ("qcs::cam::uin/300:uin/101", "denied"),
        ("qcs::cam::uid/100:uin/101", "unknown"),
    ],
)
def test_exact_caller_identity_and_uid_is_not_uin(expression, expected):
    g, user, role = setup()
    # Replace the fixture's trust metadata before generating any decisions.
    import json

    from tencent_cloud_cartography.cam import add_document, parse_document

    add_document(
        g,
        role,
        parse_document(
            json.dumps(
                dict(
                    version="2.0",
                    statement=[
                        dict(
                            effect="allow", action="sts:AssumeRole", principal={"qcs": [expression]}
                        )
                    ],
                )
            ),
            trust=True,
        ),
        "fixture",
        True,
    )
    analyze(g)
    assert result(g, user, role)["decision"] == expected


@pytest.mark.parametrize(
    "arn,expected",
    [
        ("qcs::cam::uin/100:uin/101", "allowed"),
        ("qcs::cam::uin/100:uin/999", "denied"),
    ],
)
def test_provider_assume_principal_condition_uses_collected_identity(arn, expected):
    g, user, role = setup(condition={"string_equal": {"qcs:assume_principal_arn": [arn]}})
    analyze(g)
    assert result(g, user, role)["decision"] == expected


def test_unprovided_external_id_and_ip_are_conditional_and_missing_trust_is_unknown():
    g, user, role = setup(
        condition={"string_equal": {"sts:external_id": "operator-secret-not-supplied"}}
    )
    analyze(g)
    assert result(g, user, role)["decision"] == "conditional"
    g.nodes[role]["properties"].pop("trust_document")
    analyze(g)
    assert result(g, user, role)["decision"] == "unknown"


def test_trust_and_caller_deny_across_role_name_arn_aliases():
    g, user, role = setup()
    add_policy(
        g,
        user,
        [
            statement(action="sts:AssumeRole"),
            statement("deny", "sts:AssumeRole", "qcs::cam::uin/200:roleName/Role7"),
        ],
    )
    analyze(g)
    assert result(g, user, role)["decision"] == "denied"


def test_missing_boundary_document_cannot_allow_and_known_trust_deny_survives():
    g, user, role = setup()
    bid = next(
        e["target"]
        for e in g.edges.values()
        if e["source"] == user and e["relationship"] == "HAS_PERMISSION_BOUNDARY"
    )
    g.nodes[bid]["properties"].pop("policy_document")
    analyze(g)
    assert result(g, user, role)["decision"] == "unknown"
    trust(
        g,
        role,
        [
            dict(
                effect="deny",
                action="sts:AssumeRole",
                principal={"qcs": ["qcs::cam::uin/100:root"]},
            )
        ],
    )
    analyze(g)
    assert result(g, user, role)["decision"] == "denied"


def test_role_chains_retain_conditions_cycle_bounds_and_evidence():
    g, user, role = setup()
    second = principal(
        g, "200", "8", "cam.role", rows=[statement(), statement(action="sts:AssumeRole")]
    )
    add_policy(g, role, [statement(), statement(action="sts:AssumeRole")])
    trust(
        g,
        second,
        [
            dict(
                effect="allow",
                action="sts:AssumeRole",
                principal={"qcs": ["qcs::cam::uin/200:root"]},
            )
        ],
    )
    # A real configured cycle 7 -> 8 -> 7. It must not recurse indefinitely.
    trust(
        g,
        role,
        [
            dict(
                effect="allow",
                action="sts:AssumeRole",
                principal={"qcs": ["qcs::cam::uin/100:root", "qcs::cam::uin/200:root"]},
            )
        ],
    )
    bucket(g, "200")
    cos_analysis(g)
    analyze(g)
    paths = [n for n in g.nodes.values() if n["kind"] == "cam.authorizationpath"]
    assert paths and any(n["properties"]["assumption_hops"] == 2 for n in paths)
    assert all(n["properties"]["assumption_hops"] <= 3 for n in paths)
    assert any(n["properties"]["decision"] == "allowed" for n in paths)
    assert all(not n["properties"]["effective_access_verified"] for n in paths)
    assert any(e["relationship"] == "SUPPORTED_BY_DECISION" for e in g.edges.values())
    before = deepcopy(g.snapshot())
    analyze(g)
    assert before == g.snapshot()


def test_role_paths_include_other_targets_and_never_bypass_cos_resource_deny():
    from tencent_cloud_cartography.permissions import analyze as identity_analysis

    g, user, role = setup()
    add_policy(g, role, [statement(), statement(action="ssm:GetSecretValue")])
    secret = g.add("200", "eu-frankfurt", "ssm.secret", "secret-one")
    g.nodes[secret]["properties"]["CreateUinString"] = "201"
    bucket(g, "200", [statement("deny", principal={"qcs": ["qcs::cam::uin/200:roleid/7"]})])
    identity_analysis(g)
    cos_analysis(g)
    analyze(g)
    paths = [n for n in g.nodes.values() if n["kind"] == "cam.authorizationpath"]
    assert any(
        n["properties"]["action"] == "ssm:GetSecretValue"
        and n["properties"]["decision"] == "allowed"
        for n in paths
    )
    assert not any(
        n["properties"]["action"] == "cos:GetObject" and n["properties"]["decision"] == "allowed"
        for n in paths
    )
    assert g.nodes[user]["kind"] == "cam.user"


def test_analysis_budget_is_visible_and_preserves_original_resources():
    g, user, role = setup()
    original = set(g.nodes)
    cos_analysis(g, max_decisions=1)
    analyze(g, max_decisions=1)
    assert original <= set(g.nodes)
    assert any(r.get("error") == "AuthorizationDecisionLimitExceeded" for r in g.coverage)
    assert len([n for n in g.nodes.values() if n["kind"] == "cam.assumptiondecision"]) == 1
    assert g.snapshot()["status"] == "partial"
