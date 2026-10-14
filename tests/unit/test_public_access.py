import json

import pytest

from tencent_cloud_cartography.cam import parse_document
from tencent_cloud_cartography.cos import ALL_USERS, acl, policy
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.public_access import analyze
from tencent_cloud_cartography.transport import CollectionError

PREFIX = "qcs::cos:eu-frankfurt:uid/12345:demo-12345/"


def statement(effect="allow", principal=None, action="cos:GetObject", resource=None, **extra):
    return dict(
        effect=effect,
        principal=principal or {"qcs": ["qcs::cam::anyone:anyone"]},
        action=[action],
        resource=[resource or PREFIX + "docs/*"],
        **extra,
    )


def fixture(rows=None, grants=None):
    g = Graph()
    nid = g.add("100", "eu-frankfurt", "cos.bucket", "demo-12345", source="synthetic")
    bucket = g.nodes[nid]
    policy(
        g,
        bucket,
        {"Policy": json.dumps(dict(version="2.0", statement=rows or [statement()]))},
        "synthetic",
    )
    acl(
        g,
        bucket,
        {"Owner": {"ID": "owner"}, "AccessControlList": {"Grant": grants or []}},
        "synthetic",
    )
    return g, bucket


def decision(g, action):
    return next(
        n["properties"]
        for n in g.nodes.values()
        if n["kind"] == "cos.publicaccessdecision" and n["properties"]["action"] == action
    )


def public_grant(permission, uri=ALL_USERS):
    return dict(Grantee=dict(URI=uri, Type="Group"), Permission=permission)


def test_anonymous_policy_prefix_and_configuration_evidence():
    g, _ = fixture()
    analyze(g)
    p = decision(g, "cos:GetObject")
    assert p["decision"] == "allow_from_collected_bucket_configuration"
    assert p["resource_scope"] == PREFIX + "docs/*"
    assert not p["effective_access_verified"] and not p["object_acl_overrides_evaluated"]
    assert all(
        icon_for(n["kind"]) == "en-cloud-object-storage.svg"
        for n in g.nodes.values()
        if n["kind"] == "cos.publicaccessdecision"
    )
    assert g.coverage[-1]["status"] == "complete"


def test_acl_read_listing_and_object_inheritance_are_distinct():
    g, _ = fixture([statement(effect="deny", action="cos:PutObject")], [public_grant("READ")])
    analyze(g)
    assert decision(g, "cos:GetBucket")["decision"] == "allow_from_collected_bucket_configuration"
    assert decision(g, "cos:GetBucket")["resource_scope"] == PREFIX
    assert decision(g, "cos:GetObject")["decision"] == "conditional"
    assert "object_acl_inherits_bucket" in decision(g, "cos:GetObject")["conditions"]


def test_anonymous_deny_overrides_bucket_acl_write():
    g, _ = fixture(
        [statement("deny", action="cos:PutObject", resource=PREFIX + "*")], [public_grant("WRITE")]
    )
    analyze(g)
    assert decision(g, "cos:PutObject")["decision"] == "explicit_deny"
    assert (
        decision(g, "cos:DeleteObject")["decision"] == "allow_from_collected_bucket_configuration"
    )


def test_authenticated_users_acl_is_not_anonymous_access():
    g, _ = fixture(
        [statement(principal={"qcs": ["qcs::cam::uin/100:uin/101"]})],
        [public_grant("FULL_CONTROL", "http://cam.qcloud.com/groups/global/AuthenticatedUsers")],
    )
    analyze(g)
    assert all(
        n["properties"]["decision"] == "implicit_deny_from_collected_bucket_configuration"
        for n in g.nodes.values()
        if n["kind"] == "cos.publicaccessdecision"
    )


@pytest.mark.parametrize("principal", ["*", {"qcs": ["*"]}, {"qcs": ["qcs::cam::anyone:anyone"]}])
def test_all_documented_anonymous_principal_forms(principal):
    g, _ = fixture([statement(principal=principal)])
    analyze(g)
    assert decision(g, "cos:GetObject")["decision"] == "allow_from_collected_bucket_configuration"


def test_partial_deny_of_object_prefix_is_conditional():
    g, _ = fixture(
        [
            statement(resource=PREFIX + "docs/*"),
            statement("deny", resource=PREFIX + "docs/private/*"),
        ]
    )
    analyze(g)
    assert decision(g, "cos:GetObject")["decision"] == "conditional"


def test_conditional_public_deny_is_retained():
    g, _ = fixture(
        [statement(), statement("deny", condition={"ip_not_equal": {"qcs:ip": "192.0.2.0/24"}})]
    )
    analyze(g)
    assert decision(g, "cos:GetObject")["decision"] == "conditional"
    assert "192.0.2.0/24" in decision(g, "cos:GetObject")["conditions"]


@pytest.mark.parametrize("missing", ["policy_collected", "acl_collected"])
def test_missing_policy_or_acl_is_incomplete(missing):
    g, bucket = fixture()
    bucket["properties"].pop(missing)
    analyze(g)
    assert decision(g, "cos:GetObject")["decision"] == "incomplete"
    assert g.snapshot()["status"] == "partial"


def test_wrong_bucket_account_region_and_appid_do_not_match():
    for resource in (
        PREFIX.replace("eu-frankfurt", "ap-singapore") + "docs/*",
        PREFIX.replace("uid/12345", "uin/100") + "docs/*",
        PREFIX.replace("demo-12345", "other-12345") + "docs/*",
    ):
        g, _ = fixture([statement(resource=resource)])
        analyze(g)
        assert (
            decision(g, "cos:GetObject")["decision"]
            == "implicit_deny_from_collected_bucket_configuration"
        )


def test_unknown_principal_and_unsupported_actions_remain_uncertain():
    g, _ = fixture([statement(principal={"unknown": ["*"]})])
    analyze(g)
    assert decision(g, "cos:GetObject")["decision"] == "conditional"
    g, _ = fixture([statement(action="permid/1")])
    analyze(g)
    assert (
        decision(g, "cos:GetObject")["decision"] == "incomplete"
        and g.coverage[-1]["status"] == "error"
    )


def test_capitalized_cos_policy_parses_without_changing_cam_rules():
    raw = json.dumps(
        dict(
            Version="2.0",
            Statement=[
                dict(
                    Effect="Allow",
                    Principal={"qcs": ["*"]},
                    Action=["cos:GetObject"],
                    Resource=[PREFIX + "*"],
                    Condition={"StringEquals": {"cos:prefix": "docs/"}},
                )
            ],
        )
    )
    normalized = parse_document(raw, cos=True)
    assert normalized["statement"][0]["effect"] == "allow"
    assert "StringEquals" in normalized["statement"][0]["condition"]
    with pytest.raises(CollectionError):
        parse_document(raw)


@pytest.mark.parametrize(
    "raw",
    [
        '{"version":"2.0","Version":"2.0","Statement":[]}',
        '{"version":"2.0","Statement":[{"Effect":"allow","effect":"deny"}]}',
        '{"version":"2.0","Statement":null}',
    ],
)
def test_case_collisions_and_malformed_cos_documents_fail_atomically(raw):
    with pytest.raises(CollectionError):
        parse_document(raw, cos=True)


def test_reanalysis_is_idempotent_and_preserves_identity_decisions():
    g, _ = fixture()
    nid = g.add("100", "eu-frankfurt", "cam.permissiondecision", "identity")
    analyze(g)
    first = g.dump()
    analyze(g)
    assert g.dump() == first and nid in g.nodes


def test_account_summary_reports_bucket_scope_and_no_fabricated_global_block_switch():
    from tencent_cloud_cartography.cos_account import analyze as summarize

    g = Graph()
    g.accounts["100"] = dict(id="100", name="fixture", display="fixture")
    g.add("100", "eu-frankfurt", "cos.bucket", "bucket-123")
    g.coverage.append(dict(account="100", service="cos", action="list_buckets", status="complete"))
    summarize(g)
    node = next(n for n in g.nodes.values() if n["kind"] == "cos.accountaccesssummary")
    assert node["properties"]["bucket_count"] == 1
    assert node["properties"]["evaluation_scope"] == "selected_region_bucket_configuration"
    assert not node["properties"]["global_block_state_verified"]
    assert node["properties"]["account_level_block_configuration"] == "no_equivalent_audited_api"
    before = g.dump()
    summarize(g)
    assert g.dump() == before
