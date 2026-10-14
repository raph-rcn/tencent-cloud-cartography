import json

import pytest

from tencent_cloud_cartography.authorization import (
    Gate,
    combine,
    conditions,
    context_values,
    evaluate,
    load_context,
)


@pytest.mark.parametrize(
    "condition,context,result",
    [
        (
            {"ip_equal": {"qcs:ip": ["192.0.2.0/24", "2001:db8::/32"]}},
            {"qcs:ip": "192.0.2.17"},
            True,
        ),
        (
            {"ip_not_equal": {"qcs:ip": ["192.0.2.0/24", "198.51.100.0/24"]}},
            {"qcs:ip": "198.51.100.4"},
            False,
        ),
        ({"ip_equal": {"qcs:ip": "2001:db8::/32"}}, {"qcs:ip": "2001:db8::7"}, True),
        ({"ip_equal": {"qcs:ip": "bad"}}, {"qcs:ip": "192.0.2.7"}, None),
        ({"ip_equal": {"qcs:ip": "192.0.2.0/24"}}, {}, None),
        (
            {"date_less_than": {"qcs:current_time": "2026-10-15T00:00:00Z"}},
            {"qcs:current_time": "2026-10-14T12:00:00+00:00"},
            True,
        ),
        (
            {"date_less_than": {"qcs:current_time": "2026-10-15T00:00:00Z"}},
            {"qcs:current_time": "2026-10-15T00:00:00Z"},
            False,
        ),
        (
            {"string_not_equal": {"cos:prefix": ["docs/", "images/"]}},
            {"cos:prefix": "docs/"},
            False,
        ),
        ({"string_equal_ignore_case": {"cos:prefix": "DOCS/"}}, {"cos:prefix": "docs/"}, True),
        ({"bool_equal": {"cos:secure-transport": "true"}}, {"cos:secure-transport": True}, True),
        ({"bool_equal": {"cos:secure-transport": "true"}}, {"cos:secure-transport": False}, False),
        ({"unsupported": {"cos:prefix": "docs/"}}, {"cos:prefix": "docs/"}, None),
        (
            {"ip_equal": {"qcs:ip": "192.0.2.0/24"}, "string_equal": {"sts:external_id": "unread"}},
            {"qcs:ip": "198.51.100.1"},
            False,
        ),
        (
            {"ip_equal": {"qcs:ip": "192.0.2.0/24"}, "string_equal": {"sts:external_id": "unread"}},
            {"qcs:ip": "192.0.2.1"},
            None,
        ),
    ],
)
def test_conditions_use_declared_attributes_and_negative_controls(condition, context, result):
    assert conditions(condition, context)[0] is result


@pytest.mark.parametrize(
    "context",
    [
        {"SecretKey": "NEVER_PRINT"},
        {"qcs:assume_principal_arn": "fake"},
        {"qcs:ip": "NEVER_PRINT"},
        {"qcs:ip": "192.0.2.0/24"},
        {"qcs:current_time": "2026-10-14"},
        {"cos:secure-transport": "true"},
    ],
)
def test_context_rejects_secrets_identity_overrides_and_invalid_values(context):
    with pytest.raises(ValueError) as error:
        context_values(context)
    assert "NEVER_PRINT" not in str(error.value)


def test_context_file_duplicates_and_large_inputs_fail(tmp_path):
    path = tmp_path / "context.json"
    path.write_text('{"qcs:ip":"192.0.2.1","qcs:ip":"198.51.100.1"}')
    with pytest.raises(ValueError):
        load_context(path)
    path.write_text(json.dumps({"cos:prefix": "x" * 20000}))
    with pytest.raises(ValueError):
        load_context(path)


def test_known_deny_overrides_missing_evidence_and_unknowns_cannot_allow():
    deny = Gate(deny=True, complete=False)
    assert combine([Gate(allow=True), deny]) == ("denied", "explicit_deny")
    assert combine([Gate(allow=True), Gate(complete=False)])[0] == "unknown"
    assert combine([Gate(allow=True), Gate(allow=None)])[0] == "allowed"
    assert combine([Gate(allow=True), Gate(deny=None)])[0] == "conditional"
    assert combine([Gate(allow=True), Gate()], True)[0] == "denied"
    assert Gate(deny=None).decision == "denied"
    assert combine([Gate(deny=None), Gate()])[0] == "denied"
    assert combine([Gate(deny=None), Gate(allow=True)])[0] == "conditional"


def test_action_case_function_sets_and_subset_denies_remain_unresolved():
    rows = [
        ("a", dict(effect="allow", action=["cos:GetObject"], resource=["*"])),
        (
            "d",
            dict(
                effect="deny", action=["cos:GetObject"], resource=["qcs::cos:r:uid/123:b/secret/*"]
            ),
        ),
    ]
    assert evaluate(rows, "cos:GetObject", "qcs::cos:r:uid/123:b/*").decision == "conditional"
    rows[1][1]["action"] = ["COS:getobject"]
    assert evaluate(rows, "cos:GetObject", "qcs::cos:r:uid/123:b/*").decision == "unknown"
    rows[1][1]["action"] = ["permid/1"]
    assert evaluate(rows, "cos:GetObject", "qcs::cos:r:uid/123:b/*").decision == "unknown"
