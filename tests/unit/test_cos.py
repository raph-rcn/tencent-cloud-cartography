import json
from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.auth_source import load_source
from tencent_cloud_cartography.catalog import ALLOWED_ACTIONS
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.cos import ALL_USERS, collect_bucket
from tencent_cloud_cartography.cos_transport import COS_ACTIONS
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.transport import CollectionError, TccliTransport

REGION = "eu-frankfurt"
KEY = "11111111-2222-3333-4444-555555555555"


def responses():
    return {
        "get_bucket_acl": {
            "Owner": {"ID": "appid-owner"},
            "AccessControlList": {
                "Grant": [
                    {
                        "Grantee": {"URI": ALL_USERS, "Type": "Group", "SecretKey": "exclude-me"},
                        "Permission": "READ",
                    },
                    {
                        "Grantee": {"ID": "qcs::cam::uin/999:uin/999", "Type": "CanonicalUser"},
                        "Permission": "FULL_CONTROL",
                    },
                ]
            },
        },
        "get_bucket_policy": {
            "Policy": json.dumps(
                {
                    "version": "2.0",
                    "statement": [
                        {
                            "effect": "deny",
                            "principal": {"qcs": ["*"]},
                            "action": ["name/cos:GetObject"],
                            "resource": ["qcs::cos:eu-frankfurt:uid/12345:assets-12345/*"],
                            "condition": {"ip_not_equal": {"qcs:ip": "192.0.2.0/24"}},
                        },
                    ],
                }
            )
        },
        "get_bucket_encryption": {
            "Rule": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "KMS",
                        "KMSMasterKeyID": KEY,
                        "KeyMaterial": "exclude-me",
                    }
                }
            ]
        },
        "get_bucket_notification": {},
        "get_bucket_versioning": {"Status": "Suspended"},
        "get_bucket_logging": {
            "LoggingEnabled": {"TargetBucket": "logs-12345", "TargetPrefix": "audit/"}
        },
    }


def run(data):
    graph = Graph()
    nid = graph.add("100", REGION, "cos.bucket", "assets-12345", source="cos.list_buckets")
    calls = []

    def call(service, action, region, **params):
        calls.append((service, action, region, params))
        value = data[action]
        if isinstance(value, Exception):
            raise value
        return value

    collect_bucket(
        CollectorRunner(graph, SimpleNamespace(call=call), "100", [REGION], lambda _: None), nid
    )
    return graph, graph.nodes[nid], calls


def test_cos_configuration_and_typed_relations():
    graph, bucket, calls = run(responses())
    assert len(calls) == 6 and all(c[2:] == (REGION, {"Bucket": "assets-12345"}) for c in calls)
    assert bucket["account"] == "100" and bucket["properties"]["acl_owner_id"] == "appid-owner"
    assert bucket["properties"]["versioning_status"] == "Suspended"
    grants = [n for n in graph.nodes.values() if n["kind"] == "cos.aclgrant"]
    assert len(grants) == 2 and sum(n["properties"]["all_users"] for n in grants) == 1
    assert all(n["properties"]["access_evaluated"] is False for n in grants)
    statements = [n for n in graph.nodes.values() if n["kind"] == "cam.policystatement"]
    assert len(statements) == 1 and statements[0]["properties"]["effect"] == "deny"
    assert "ip_not_equal" in statements[0]["properties"]["condition"]
    assert "exclude-me" not in graph.dump()
    edges = {e["relationship"] for e in graph.edges.values()}
    assert {
        "CONFIGURED_LOG_DESTINATION",
        "CONFIGURED_ENCRYPTION_KEY",
        "HAS_ACL_GRANT",
        "HAS_STATEMENT",
    } <= edges
    assert all(icon_for(n["kind"]) != "unmapped.svg" for n in graph.nodes.values())
    assert all(c["status"] == "complete" for c in graph.coverage)


@pytest.mark.parametrize("action", sorted(COS_ACTIONS))
def test_denied_scopes_do_not_prevent_other_details(action):
    data = responses()
    data[action] = CollectionError("AccessDenied")
    graph, _, calls = run(data)
    assert len(calls) == 6
    assert [c["action"] for c in graph.coverage if c["status"] == "denied"] == [action]
    assert sum(c["status"] == "complete" for c in graph.coverage) == 5


def test_empty_versioning_logging_and_no_false_absence():
    data = responses()
    data.update(
        get_bucket_versioning={},
        get_bucket_logging={},
        get_bucket_policy=CollectionError("NoSuchBucketPolicy"),
    )
    graph, bucket, _ = run(data)
    assert bucket["properties"]["versioning_status"] == "Unconfigured"
    assert bucket["properties"]["logging_configured"] is False
    assert "policy_collected" not in bucket["properties"]
    assert any(
        c.get("error") == "NoSuchBucketPolicy" and c["status"] == "error" for c in graph.coverage
    )


@pytest.mark.parametrize("algorithm", ["AES256", "SM4", "KMS"])
def test_encryption_enums_and_opaque_key_not_assigned_account(algorithm):
    data = responses()
    data["get_bucket_encryption"] = {
        "Rule": {
            "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": algorithm,
                "KMSMasterKeyID": "qcs::kms:other:uin/999:key/foreign",
            }
        }
    }
    graph, bucket, _ = run(data)
    assert algorithm in bucket["properties"]["default_encryption_rules"]
    assert not any(n["kind"] == "kms.key" for n in graph.nodes.values())


@pytest.mark.parametrize(
    "action,bad",
    [
        (
            "get_bucket_acl",
            {
                "Owner": {"ID": "x"},
                "AccessControlList": {
                    "Grant": [
                        {"Grantee": {"URI": ALL_USERS}, "Permission": "READ"},
                        {"Permission": "unknown"},
                    ]
                },
            },
        ),
        ("get_bucket_policy", {"Policy": '{"version":"2.0","statement":[],"statement":[]}'}),
        (
            "get_bucket_encryption",
            {"Rule": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "cos/kms"}}]},
        ),
        ("get_bucket_logging", {"LoggingEnabled": {"TargetBucket": "https://attacker.invalid/"}}),
        ("get_bucket_versioning", {"Status": "unrecognized"}),
    ],
)
def test_invalid_details_are_partial(action, bad):
    data = responses()
    data[action] = bad
    graph, bucket, _ = run(data)
    assert [c["action"] for c in graph.coverage if c["status"] == "error"] == [action]
    if action == "get_bucket_acl":
        assert "acl_collected" not in bucket["properties"]
        assert not any(n["kind"] == "cos.aclgrant" for n in graph.nodes.values())


@pytest.fixture
def isolated_profile(tmp_path, monkeypatch):
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    for variable in ("TENCENTCLOUD_SECRET_ID", "TENCENTCLOUD_SECRET_KEY", "TENCENTCLOUD_TOKEN"):
        monkeypatch.delenv(variable, raising=False)
    path = tmp_path / ".tccli" / "test.credential"
    path.parent.mkdir()
    return path


def test_profile_credentials_conflicts_dynamic_and_incomplete(isolated_profile, monkeypatch):
    path = isolated_profile
    path.write_text(
        json.dumps(dict(secretId="fixture-id", secretKey="fixture-key", token="fixture-token"))
    )
    assert load_source("test").material().token == "fixture-token"
    monkeypatch.setenv("TENCENTCLOUD_SECRET_ID", "env-id")
    assert load_source("test").material().secret_id == "fixture-id"
    path.unlink()
    with pytest.raises(CollectionError) as exc:
        load_source("test")
    assert exc.value.code == "MissingProfile"
    monkeypatch.delenv("TENCENTCLOUD_SECRET_ID")
    path.write_text(json.dumps(dict(type="oauth", secretId="cached-id", secretKey="cached-key")))
    with pytest.raises(CollectionError) as exc:
        load_source("test")
    assert exc.value.code == "InvalidCredentialConfiguration"


def test_sdk_dispatch_tls_errors_and_no_raw_error_text(
    isolated_profile, monkeypatch, frozen_session
):
    import qcloud_cos

    isolated_profile.write_text(json.dumps(dict(secretId="fixture-id", secretKey="fixture-key")))
    transport = TccliTransport(profile="test", session=frozen_session)
    calls = []

    def client(config, retry):
        assert retry == 0 and config._scheme == "https"

        def get_bucket_logging(**params):
            calls.append(params)
            return {}

        return SimpleNamespace(get_bucket_logging=get_bucket_logging)

    monkeypatch.setattr(qcloud_cos, "CosS3Client", client)
    assert transport.call("cos", "get_bucket_logging", REGION, Bucket="assets-12345") == {}
    assert calls == [{"Bucket": "assets-12345"}]

    def denied(*args, **kwargs):
        raise qcloud_cos.CosServiceError(
            "GET", {"code": "AccessDenied", "message": "secret-error"}, 403
        )

    monkeypatch.setattr(qcloud_cos, "CosS3Client", denied)
    with pytest.raises(CollectionError) as exc:
        transport.call("cos", "get_bucket_logging", REGION, Bucket="assets-12345")
    assert exc.value.code == "AccessDenied" and "secret-error" not in str(exc.value)


@pytest.mark.parametrize(
    "action,region,params",
    [
        ("get_object", REGION, {"Bucket": "assets-12345"}),
        ("get_bucket_acl", REGION, {"Bucket": "assets-12345", "Endpoint": "attacker.invalid"}),
        ("get_bucket_acl", "https://attacker.invalid", {"Bucket": "assets-12345"}),
        ("get_bucket_acl", REGION, {"Bucket": "../bad"}),
    ],
)
def test_scope_allowlist_before_credentials(action, region, params, monkeypatch):
    monkeypatch.setattr(
        "tencent_cloud_cartography.cos_transport.credentials",
        lambda _: pytest.fail("read credentials"),
    )
    with pytest.raises(CollectionError):
        TccliTransport().call("cos", action, region, **params)
    assert all(("cos", action) in ALLOWED_ACTIONS for action in COS_ACTIONS)


def test_real_sdk_xml_parsing_without_network(isolated_profile, monkeypatch, frozen_session):
    import qcloud_cos

    isolated_profile.write_text(json.dumps(dict(secretId="fixture-id", secretKey="fixture-key")))
    payloads = {
        "acl": '<AccessControlPolicy><Owner><ID>owner-appid</ID></Owner><AccessControlList><Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="Group"><URI>'
        + ALL_USERS
        + "</URI></Grantee><Permission>READ</Permission></Grant></AccessControlList></AccessControlPolicy>",
        "policy": None,
        "encryption": "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>KMS</SSEAlgorithm><KMSMasterKeyID>"
        + KEY
        + "</KMSMasterKeyID></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>",
        "versioning": "<VersioningConfiguration/>",
        "logging": "<BucketLoggingStatus/>",
        "notification": "<NotificationConfiguration/>",
    }
    requests = []

    def send(self, **kwargs):
        assert kwargs["method"] == "GET"
        assert kwargs["url"] == "https://assets-12345.cos.eu-frankfurt.myqcloud.com/"
        assert kwargs["bucket"] == "assets-12345"
        key = next(iter(kwargs["params"]))
        requests.append(key)
        return SimpleNamespace(
            content=(payloads[key] or "").encode(),
            json=lambda: json.loads(responses()["get_bucket_policy"]["Policy"]),
        )

    monkeypatch.setattr(qcloud_cos.CosS3Client, "send_request", send)
    graph = Graph()
    nid = graph.add("100", REGION, "cos.bucket", "assets-12345")
    collect_bucket(
        CollectorRunner(
            graph,
            TccliTransport(profile="test", session=frozen_session),
            "100",
            [REGION],
            lambda _: None,
        ),
        nid,
    )
    assert set(requests) == set(payloads)
    assert all(c["status"] == "complete" for c in graph.coverage)
    assert graph.nodes[nid]["properties"]["versioning_status"] == "Unconfigured"
    assert graph.nodes[nid]["properties"]["logging_configured"] is False
    assert any(e["relationship"] == "CONFIGURED_ENCRYPTION_KEY" for e in graph.edges.values())
