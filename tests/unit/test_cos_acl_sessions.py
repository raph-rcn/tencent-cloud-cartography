import copy
import json
from types import SimpleNamespace

import pytest
from authorization_fixtures import PREFIX, fixture, statement

from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.cos import ALL_USERS, acl
from tencent_cloud_cartography.cos_authorization import analyze as named_analysis
from tencent_cloud_cartography.cos_object_acls import analyze, collect, validate
from tencent_cloud_cartography.cos_transport import validate_scope
from tencent_cloud_cartography.permissions import analyze_snapshot
from tencent_cloud_cartography.session_policy import apply
from tencent_cloud_cartography.session_policy import validate as validate_sessions
from tencent_cloud_cartography.transport import CollectionError, TccliTransport

REGION = "eu-frankfurt"
OWNER = "qcs::cam::uin/100:uin/100"


def response(public=False, private=False):
    grants = []
    if private:
        grants.append(dict(Grantee=dict(ID=OWNER), Permission="FULL_CONTROL"))
    if public:
        grants.append(dict(Grantee=dict(URI=ALL_USERS), Permission="READ"))
    return dict(Owner=dict(ID=OWNER), AccessControlList=dict(Grant=grants))


def selections(g, bucket, rows):
    calls = []

    def call(service, action, region=None, **params):
        assert (service, action, region) == ("cos", "get_object_acl", REGION)
        assert set(params) <= {"Bucket", "Key", "VersionId"}
        calls.append(params)
        value = rows[params["Key"]]
        if isinstance(value, Exception):
            raise value
        return copy.deepcopy(value)

    runner = CollectorRunner(g, SimpleNamespace(call=call), "100", [REGION], lambda _: None)
    collect(
        runner,
        [dict(account="100", region=REGION, bucket=bucket["resource_id"], key=key) for key in rows],
    )
    return calls


def decision(g, key, action="cos:GetObject"):
    obj = next(
        n
        for n in g.nodes.values()
        if n["kind"] == "cos.objectacl" and n["properties"]["object_key"] == key
    )
    targets = {
        e["target"]
        for e in g.edges.values()
        if e["source"] == obj["id"] and e["relationship"] == "HAS_OBJECT_ACL_ANALYSIS"
    }
    return next(
        g.nodes[nid]["properties"]
        for nid in targets
        if g.nodes[nid]["properties"]["action"] == action
    )


@pytest.mark.parametrize(
    "public,private,expected",
    [(True, False, "allowed"), (False, True, "denied"), (False, False, "allowed")],
)
def test_explicit_object_acl_overrides_bucket_acl_and_empty_inherits(public, private, expected):
    g, _, bid = fixture()
    bucket = g.nodes[bid]
    acl(g, bucket, response(public=True), "fixture")
    selections(g, bucket, {"file.txt": response(public, private)})
    analyze(g)
    p = decision(g, "file.txt")
    assert p["decision"] == expected
    assert p["acl_inheritance"] == ("explicit_object" if public or private else "bucket_default")
    assert p["acl_inheritance_complete"] and not p["effective_access_verified"]
    before = g.dump()
    analyze(g)
    assert before == g.dump()


def test_unknown_directory_acl_does_not_inherit_public_bucket_and_denied_metadata_is_visible():
    g, _, bid = fixture()
    bucket = g.nodes[bid]
    acl(g, bucket, response(public=True), "fixture")
    selections(g, bucket, {"docs/file.txt": response(), "docs/": CollectionError("AccessDenied")})
    analyze(g)
    assert decision(g, "docs/file.txt")["decision"] == "unknown"
    assert decision(g, "docs/file.txt")["acl_inheritance"] == "uncollected_directory_acl"
    assert any(c["status"] == "denied" for c in g.coverage)


def test_nearest_explicit_directory_and_complete_default_directory_chain():
    g, _, bid = fixture()
    bucket = g.nodes[bid]
    acl(g, bucket, response(public=True), "fixture")
    selections(
        g,
        bucket,
        {
            "docs/file.txt": response(),
            "docs/": response(private=True),
            "open/file.txt": response(),
            "open/": response(),
        },
    )
    analyze(g)
    assert decision(g, "docs/file.txt")["decision"] == "denied"
    assert decision(g, "docs/file.txt")["acl_inheritance"] == "explicit_directory"
    assert decision(g, "open/file.txt")["decision"] == "allowed"


def test_bucket_explicit_policy_deny_overrides_public_object_acl():
    g, _, bid = fixture(resource=[statement("deny", principal="*")])
    bucket = g.nodes[bid]
    selections(g, bucket, {"file.txt": response(public=True)})
    analyze(g)
    assert decision(g, "file.txt")["decision"] == "denied"


def test_selected_object_version_and_only_fixed_metadata_api_sent(monkeypatch, frozen_session):
    import qcloud_cos

    calls = []

    def send(self, **params):
        calls.append(params)
        assert params["method"] == "GET"
        assert params["url"] == "https://assets-12345.cos.eu-frankfurt.myqcloud.com/docs/file.txt"
        assert params["params"] == {"acl": "", "versionId": "v1"}
        assert params["headers"] == {} and params["auth"] is not None
        return SimpleNamespace(
            content=b"<AccessControlPolicy><Owner><ID>qcs::cam::uin/100:uin/100</ID></Owner><AccessControlList/></AccessControlPolicy>",
            headers={"x-cos-acl": "default", "x-cos-request-id": "acl-1"},
        )

    monkeypatch.setattr(qcloud_cos.CosS3Client, "send_request", send)
    transport = TccliTransport(session=frozen_session)
    data = transport.call(
        "cos", "get_object_acl", REGION, Bucket="assets-12345", Key="docs/file.txt", VersionId="v1"
    )
    assert data["CannedACL"] == "default" and data["x-cos-request-id"] == "acl-1"
    from pathlib import Path

    inventory = json.loads(
        (Path(__file__).resolve().parents[2] / "docs/api-actions.json").read_text()
    )
    contract = next(
        row
        for row in inventory["actions"]
        if (row["service"], row["action"]) == ("cos", "get_object_acl")
    )
    assert contract["cam_action"] == "cos:GetObjectACL"
    assert contract["versioned_cam_action"] == "cos:GetObjectVersionACL"
    assert len(calls) == 1
    for forbidden in ("get_object", "list_objects", "put_object_acl"):
        with pytest.raises(CollectionError, match="metadata allowlist"):
            transport.call("cos", forbidden, REGION, Bucket="assets-12345", Key="docs/file.txt")


@pytest.mark.parametrize(
    "patch",
    [
        {"Key": ""},
        {"Key": None},
        {"Key": "/one.txt"},
        {"VersionId": None},
        {"Key": "a\n"},
        {"VersionId": ""},
        {"Headers": {}},
        {"Bucket": "invalid"},
        {"Endpoint": "https://other.test"},
    ],
)
def test_cos_acl_transport_rejects_scope_injection(patch):
    params = dict(Bucket="assets-12345", Key="one.txt")
    params.update(patch)
    with pytest.raises(CollectionError):
        validate_scope("get_object_acl", REGION, params)


@pytest.mark.parametrize(
    "patch",
    [
        {"account": "other"},
        {"key": "*"},
        {"key": ""},
        {"version_id": None},
        {"region": "aws-region"},
        {"token": "never-persist"},
    ],
)
def test_manifest_rejects_bad_scope(patch):
    row = dict(account="100", region=REGION, bucket="assets-12345", key="one.txt")
    row.update(patch)
    # aws-region is syntactically a Tencent-style region; planning handles validity.
    if patch == {"region": "aws-region"}:
        assert validate([row]) == [row]
    else:
        with pytest.raises(ValueError):
            validate([row])


def test_manifest_duplicates_budget_and_uncollected_bucket_fail_closed():
    row = dict(account="100", region=REGION, bucket="assets-12345", key="one.txt")
    with pytest.raises(ValueError):
        validate([row, row])
    with pytest.raises(ValueError):
        validate([row] * 257)
    g, _, bid = fixture()
    called = []
    runner = CollectorRunner(
        g, SimpleNamespace(call=lambda *a, **kw: called.append(kw)), "100", [REGION], lambda _: None
    )
    collect(runner, [row])
    assert not called and g.coverage[-1]["error"] == "CosAclBucketOutsideCollectedScope"


def declaration(g, uid, statements):
    principal = g.nodes[uid]
    return [
        dict(
            account=principal["account"],
            kind=principal["kind"],
            principal_id=principal["resource_id"],
            policy=dict(version="2.0", statement=statements),
        )
    ]


def named_result(g, uid):
    return next(
        n["properties"]
        for n in g.nodes.values()
        if n["kind"] == "cos.authorizationdecision"
        and n["properties"]["principal_id"] == g.nodes[uid]["resource_id"]
        and n["properties"]["action"] == "cos:GetObject"
        and n["properties"]["resource_scope"] == PREFIX + "*"
    )


@pytest.mark.parametrize(
    "rows,expected,reason",
    [
        ([statement()], "allowed", None),
        ([statement("deny")], "denied", "explicit_declared_session_deny"),
        ([statement(action="name/cos:GetBucket")], "denied", "declared_session_has_no_allow"),
        (
            [statement(condition={"ip_equal": {"qcs:ip": "192.0.2.1"}})],
            "conditional",
            "declared_session_conditions",
        ),
    ],
)
def test_declared_session_restricts_signed_identity_without_granting_or_live_auth(
    rows, expected, reason
):
    g, uid, _ = fixture()
    apply(g, declaration(g, uid, rows))
    named_analysis(g)
    p = named_result(g, uid)
    assert p["decision"] == expected
    if reason:
        assert p["decision_reason"] == reason
    assert p["session_constraints"] == "operator_declared_policy_evaluated"
    assert not p["live_session_verified"] and p["effective_access_decision"] == "unknown"
    assert not any(
        e["relationship"] == "HAS_POLICY" and g.nodes[e["target"]]["kind"] == "cam.sessionpolicy"
        for e in g.edges.values()
    )


def test_session_allow_never_creates_permission_and_missing_principal_fails_atomically():
    g, uid, _ = fixture(identity=[statement("deny")])
    rows = declaration(g, uid, [statement()])
    apply(g, rows)
    named_analysis(g)
    assert named_result(g, uid)["decision"] == "denied"
    before = g.dump()
    rows[0]["account"] = "999"
    with pytest.raises(ValueError, match="collected principal"):
        apply(g, rows)
    assert before == g.dump()


def test_offline_analysis_reuses_declared_session_idempotently():
    g, uid, _ = fixture()
    g.accounts = {"100": dict(id="100", name="fixture", display="fixture")}
    original = g.snapshot()
    updated = analyze_snapshot(original, session_policies=declaration(g, uid, [statement("deny")]))
    assert original["nodes"] == g.snapshot()["nodes"]
    assert any(n["kind"] == "cam.sessionpolicy" for n in updated["nodes"])
    again = analyze_snapshot(updated)
    a = {
        n["id"]: n["properties"]
        for n in updated["nodes"]
        if n["kind"] == "cos.authorizationdecision"
    }
    b = {
        n["id"]: n["properties"] for n in again["nodes"] if n["kind"] == "cos.authorizationdecision"
    }
    assert a == b


def test_session_manifest_rejects_duplicate_principal_and_secret_fields():
    g, uid, _ = fixture()
    rows = declaration(g, uid, [statement()])
    with pytest.raises(ValueError):
        validate_sessions(rows * 2)
    rows[0]["token"] = "never-persist"
    with pytest.raises(ValueError):
        validate_sessions(rows)


@pytest.mark.parametrize(
    "body",
    [
        b"invalid",
        b'<!DOCTYPE x [<!ENTITY x "expand">]><AccessControlPolicy>&x;</AccessControlPolicy>',
        b"<Other/>",
        b'<AccessControlPolicy xmlns="https://untrusted.test"/>',
        b"<AccessControlPolicy><Owner><ID>x</ID></Owner></AccessControlPolicy>",
    ],
)
def test_acl_xml_rejects_malformed_and_unsafe_documents(body):
    from tencent_cloud_cartography.cos_object_acls import parse_xml

    with pytest.raises(CollectionError):
        parse_xml(body)


def test_provider_default_header_controls_inheritance_even_if_owner_grant_returned():
    g, _, bid = fixture()
    bucket = g.nodes[bid]
    acl(g, bucket, response(public=True), "fixture")
    selections(g, bucket, {"one.txt": {**response(private=True), "CannedACL": "default"}})
    analyze(g)
    assert decision(g, "one.txt")["acl_inheritance"] == "bucket_default"
    assert decision(g, "one.txt")["decision"] == "allowed"


@pytest.mark.parametrize(
    "cross,public,identity,expected",
    [
        (False, False, True, "allowed"),
        (True, False, True, "denied"),
        (False, False, False, "denied"),
    ],
)
def test_named_current_object_scopes_use_collected_acl_completeness(
    cross, public, identity, expected
):
    g, uid, bid = fixture(
        identity=[statement()] if identity else [], owner="200" if cross else "100"
    )
    bucket = g.nodes[bid]

    # For cross-account collection the runner and object owner follow the bucket.
    def call(*args, **kwargs):
        data = response(public=public, private=True)
        data["Owner"]["ID"] = f"qcs::cam::uin/{bucket['account']}:uin/{bucket['account']}"
        data["AccessControlList"]["Grant"][0]["Grantee"]["ID"] = data["Owner"]["ID"]
        return data

    runner = CollectorRunner(
        g, SimpleNamespace(call=call), bucket["account"], [REGION], lambda _: None
    )
    collect(
        runner,
        [
            dict(
                account=bucket["account"],
                region=REGION,
                bucket=bucket["resource_id"],
                key="one.txt",
            )
        ],
    )
    named_analysis(g)
    p = next(
        n["properties"]
        for n in g.nodes.values()
        if n["kind"] == "cos.authorizationdecision"
        and n["properties"]["action"] == "cos:GetObject"
        and n["properties"]["resource_scope"] == PREFIX + "one.txt"
    )
    assert p["decision"] == expected
    assert p["object_acls_collected"] and p["selected_acl_inheritance_complete"]
    assert p["effective_access_decision"] == "unknown"


def test_object_full_control_is_acl_metadata_not_write_or_delete_permission():
    g, _, bid = fixture(identity=[])
    bucket = g.nodes[bid]
    data = response()
    data["AccessControlList"] = dict(
        Grant=[dict(Grantee=dict(URI=ALL_USERS), Permission="FULL_CONTROL")]
    )
    selections(g, bucket, {"one.txt": data})
    analyze(g)
    assert decision(g, "one.txt", "cos:GetObjectACL")["decision"] == "allowed"
    assert decision(g, "one.txt", "cos:PutObjectACL")["decision"] == "allowed"
    assert {
        n["properties"]["action"] for n in g.nodes.values() if n["kind"] == "cos.objectacldecision"
    } == {"cos:GetObject", "cos:GetObjectACL", "cos:PutObjectACL"}


def test_selected_object_analysis_budget_stays_partial_without_dropping_source_acls():
    g, _, bid = fixture()
    selections(
        g, g.nodes[bid], {"one.txt": response(public=True), "two.txt": response(public=True)}
    )
    analyze(g, max_decisions=1)
    assert len([n for n in g.nodes.values() if n["kind"] == "cos.objectacldecision"]) == 1
    assert len([n for n in g.nodes.values() if n["kind"] == "cos.objectacl"]) == 2
    assert any(c.get("error") == "AuthorizationDecisionLimitExceeded" for c in g.coverage)


def test_empty_session_manifest_explicitly_clears_declarations():
    g, uid, _ = fixture()
    apply(g, declaration(g, uid, [statement("deny")]))
    named_analysis(g)
    assert named_result(g, uid)["decision"] == "denied"
    apply(g, [])
    named_analysis(g)
    assert named_result(g, uid)["decision"] == "allowed"
    assert not any(n["kind"].startswith("cam.sessionpolicy") for n in g.nodes.values())
