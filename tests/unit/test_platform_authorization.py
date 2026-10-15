import json

import pytest
from test_role_assumption import result, setup

from tencent_cloud_cartography.authorization import conditions, context_values
from tencent_cloud_cartography.role_assumption import analyze
from tencent_cloud_cartography.session_policy import apply


@pytest.mark.parametrize(
    "operator,actual,expected,match",
    [
        ("numeric_equal", 10, "10", True),
        ("numeric_not_equal", 10, [9, 11], True),
        ("numeric_not_equal", 10, [9, 10], False),
        ("numeric_less_than", 9, 10, True),
        ("numeric_less_than_equal", 10, 10, True),
        ("numeric_greater_than", 11, 10, True),
        ("numeric_greater_than_equal", 10, 10, True),
        ("numeric_less_than", 10, 10, False),
    ],
)
def test_cos_numeric_conditions_use_exact_finite_values(operator, actual, expected, match):
    context = context_values({"cos:content-length": actual})
    assert conditions({operator: {"cos:content-length": expected}}, context) == (match, [])


@pytest.mark.parametrize("value", [True, False, "NaN", "Infinity", -1, 1.5, [], {}, "not-numeric"])
def test_invalid_content_length_context_is_rejected(value):
    with pytest.raises(ValueError):
        context_values({"cos:content-length": value})


def test_tls_and_cos_wildcard_types_are_not_guessed():
    assert (
        conditions(
            {"numeric_greater_than_equal": {"cos:tls-version": "1.2"}},
            context_values({"cos:tls-version": "1.3"}),
        )[0]
        is True
    )
    assert (
        conditions(
            {"string_like": {"cos:content-type": "image/*"}}, {"cos:content-type": "image/png"}
        )[0]
        is True
    )
    assert (
        conditions(
            {"string_like": {"cos:content-type": "image/*/png"}},
            {"cos:content-type": "image/foo/png"},
        )[0]
        is None
    )
    assert (
        conditions({"string_like": {"cos:prefix": "*docs*"}}, {"cos:prefix": "my-docs/"})[0] is True
    )
    assert conditions({"string_like": {"qcs:resource_tag": "env*"}}, {})[0] is None


@pytest.mark.parametrize(
    "operator,expected",
    [
        ("string_equal", False),
        ("string_not_equal", False),
        ("string_equal_if_exist", True),
        ("string_not_equal_if_exist", True),
    ],
)
def test_explicit_absence_is_distinct_from_unknown_request_context(operator, expected):
    condition = {operator: {"cos:versionid": "version-1"}}
    assert conditions(condition, {})[0] is None
    assert conditions(condition, context_values({"cos:versionid": None}))[0] is expected
    assert (
        conditions({"unknown_if_exist": {"cos:versionid": "v1"}}, {"cos:versionid": None})[0]
        is None
    )


def test_declared_session_restricts_assume_role_without_propagating_to_target_role():
    g, user, role = setup()
    n = g.nodes[user]
    apply(
        g,
        [
            dict(
                account=n["account"],
                kind=n["kind"],
                principal_id=n["resource_id"],
                policy=dict(
                    version="2.0",
                    statement=[dict(effect="deny", action="sts:AssumeRole", resource="*")],
                ),
            )
        ],
    )
    analyze(g)
    p = result(g, user, role)
    assert (
        p["decision"] == "denied"
        and p["session_constraints"] == "operator_declared_hypothetical_session"
    )
    assert p["resulting_session_policy"] == "unknown" and not p["effective_assumption_verified"]
    evidence = json.loads(p["authorization_evidence"])
    assert len(evidence) == 4 and evidence[-1]["decision"] == "denied"
    assert not any(
        e["source"] == role and e["relationship"] == "HAS_DECLARED_SESSION_POLICY"
        for e in g.edges.values()
    )
    apply(g, [])
    analyze(g)
    assert result(g, user, role)["decision"] == "allowed"


def test_tag_set_conditions_have_documented_quantifiers_and_no_empty_set_assumption():
    allowed = {"for_any_value:string_equal": {"qcs:request_tag": ["a&b", "c&d"]}}
    subset = {"for_all_value:string_equal": {"qcs:request_tag": ["a&b", "c&d"]}}
    ctx = context_values({"qcs:request_tag": ["a&b", "extra&value"]})
    assert conditions(allowed, ctx, "cos:PutBucket")[0] is True
    assert conditions(subset, ctx, "cos:PutBucket")[0] is False
    assert conditions(subset, {"qcs:request_tag": ["a&b"]}, "cos:PutBucket")[0] is True
    assert conditions(subset, {"qcs:request_tag": []}, "cos:PutBucket")[0] is None
    assert conditions(allowed, ctx, "ssm:GetSecretValue")[0] is None


def test_resource_tags_are_derived_only_from_exact_collected_tags_and_cannot_be_overridden():
    from tencent_cloud_cartography.authorization import resource_context

    with pytest.raises(ValueError):
        context_values({"qcs:resource_tag": ["env&prod"]})
    n = dict(
        properties=dict(
            tag_resolution="unresolved", tag_api_tags='[{"TagKey":"env","TagValue":"prod"}]'
        )
    )
    assert "qcs:resource_tag" not in resource_context({"qcs:resource_tag": ["forged&value"]}, n)
    n["properties"]["tag_resolution"] = "exact-collected-identity"
    attrs = resource_context({}, n)
    assert attrs["qcs:resource_tag"] == ["env&prod"]
    c = {"for_any_value:string_equal": {"qcs:resource_tag": ["env&prod"]}}
    assert conditions(c, attrs, "cvm:RebootInstances")[0] is True
    assert conditions(c, attrs, "cvm:DescribeInstances")[0] is None


@pytest.mark.parametrize(
    "tags", [["no-separator"], ["&empty-key"], ["a&b", "a&c"], ["a&${qcs:principal_tag_key}"]]
)
def test_ambiguous_tag_contexts_are_rejected(tags):
    with pytest.raises(ValueError):
        context_values({"qcs:request_tag": tags})


def test_tag_policy_can_accept_multiple_values_for_the_same_key():
    c = {"for_any_value:string_equal": {"qcs:request_tag": ["env&dev", "env&test"]}}
    assert conditions(c, {"qcs:request_tag": ["env&test"]}, "cos:PutBucket")[0] is True


def test_all_numeric_and_wildcard_values_are_validated_before_any_match():
    assert (
        conditions({"numeric_equal": {"cos:content-length": [10, {}]}}, {"cos:content-length": 10})[
            0
        ]
        is None
    )
    assert (
        conditions(
            {"string_like": {"cos:prefix": ["docs/*", "d*ocs/*"]}}, {"cos:prefix": "docs/a"}
        )[0]
        is None
    )
    assert conditions({"string_like": {"cos:prefix": ["**"]}}, {"cos:prefix": "docs/a"})[0] is None


@pytest.mark.parametrize(
    "key,operator,value",
    [
        ("cos:versionid", "string_equal_if_exist", {}),
        ("cos:prefix", "string_like_if_exist", "d*ocs/*"),
        ("cos:content-length", "numeric_equal_if_exist", "invalid"),
    ],
)
def test_absent_request_attribute_cannot_validate_invalid_policy_values(key, operator, value):
    assert conditions({operator: {key: value}}, {key: None})[0] is None


@pytest.mark.parametrize("key", ["cos:secure-transport", "cos:host"])
def test_always_present_request_identity_attributes_cannot_be_declared_absent(key):
    with pytest.raises(ValueError):
        context_values({key: None})
