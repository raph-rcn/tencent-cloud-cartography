import json
from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.catalog import ALLOWED_ACTIONS, COLLECTORS
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.secrets import collect_secrets, link_resources
from tencent_cloud_cartography.tags import collect_tags, link_tags
from tencent_cloud_cartography.transport import CollectionError

SPEC = next(s for s in COLLECTORS if s.kind == "ssm.secret")
REGION = "eu-frankfurt"
KEY = "6cdf26d1-44ff-11eb-841c-5254006d0810"


def secret(i=1, kind=0, encryption=0):
    return dict(
        SecretName=f"secret-{i}",
        SecretType=kind,
        EncryptType=encryption,
        Status="PendingDelete",
        CreateUin=321,
        CreateUinString="321",
        CreateTime=1700000000,
        DeleteTime=1800000000,
        RotationStatus=0,
        NextRotationTime=0,
        RotationFrequency=30,
        KmsKeyId=KEY if not encryption else "",
        KmsKeyType="CUSTOMER",
        Description="Metadata description",
    )


def run(inventories=None, versions=None, rotation=None, mutate=None):
    graph, calls = Graph(), []
    inventories = {(0, 0): [secret()]} if inventories is None else inventories

    def call(service, action, **params):
        assert service == "ssm"
        calls.append((action, params))
        if action == "ListSecrets":
            assert params["State"] == 0
            assert not {"ProductName", "TagFilters", "SearchSecretName"} & params.keys()
            rows = inventories.get((params["SecretType"], params["EncryptType"]), [])
            if isinstance(rows, Exception):
                raise rows
            value = dict(
                SecretMetadatas=rows[params["Offset"] : params["Offset"] + params["Limit"]],
                TotalCount=len(rows),
            )
        elif action == "ListSecretVersionIds":
            assert set(params) == {"region", "SecretName"}
            value = (
                dict(
                    SecretName=params["SecretName"],
                    Versions=[
                        dict(VersionId="v1", CreateTime=1700000001),
                        dict(VersionId="v2", CreateTime=1700000002),
                    ],
                )
                if versions is None
                else versions
            )
        elif action == "DescribeRotationDetail":
            value = (
                dict(
                    EnableRotation=False,
                    Frequency=None,
                    LatestRotateTime=None,
                    NextRotateBeginTime=None,
                )
                if rotation is None
                else rotation
            )
        else:
            raise AssertionError(action)
        if isinstance(value, Exception):
            raise value
        value = {**value, "RequestId": str(len(calls))}
        return mutate(action, params, value) if mutate else value

    runner = CollectorRunner(graph, SimpleNamespace(call=call), "100", [REGION], lambda _: None)
    collect_secrets(runner, SPEC, REGION)
    return graph, calls


def nodes(graph, kind):
    return [n for n in graph.nodes.values() if n["kind"] == kind]


def test_all_type_and_encryption_scopes_versions_and_kms_configuration():
    graph, calls = run()
    lists = [p for a, p in calls if a == "ListSecrets"]
    assert {(p["SecretType"], p["EncryptType"]) for p in lists} == {
        (t, e) for t in range(4) for e in range(2)
    }
    assert all(p["region"] == REGION for _, p in calls)
    assert len(graph.coverage) == 10 and graph.coverage[-2]["count"] == 2
    parent = nodes(graph, "ssm.secret")[0]
    assert parent["properties"]["state"] == "PendingDelete"
    assert parent["properties"]["Description"] == "Metadata description"
    assert parent["account"] == "100"  # creator is a sub-user, not the owner
    assert not parent["properties"]["secret_value_collected"]
    assert not parent["properties"]["rotation_verified"]
    assert len(nodes(graph, "ssm.version")) == 2
    assert {e["relationship"] for e in graph.edges.values()} == {"VERSION_OF", "CONFIGURED_KMS_KEY"}
    assert all(
        e["source"] == parent["id"]
        for e in graph.edges.values()
        if e["relationship"] == "CONFIGURED_KMS_KEY"
    )
    assert all(
        icon_for(n["kind"]) == "en-secrets-manager.svg"
        for n in graph.nodes.values()
        if n["kind"].startswith("ssm.")
    )
    assert {a for s, a in ALLOWED_ACTIONS if s == "ssm"} == {
        "ListSecrets",
        "ListSecretVersionIds",
        "DescribeRotationDetail",
        "DescribeRotationHistory",
        "DescribeSupportedProducts",
    }


def test_each_family_software_encryption_and_redis_cloud_product_are_retained():
    inventories = {(t, e): [secret(f"{t}-{e}", t, e)] for t in range(4) for e in range(2)}
    inventories[1, 1].append(secret("redis", 4, 1))
    graph, _ = run(inventories)
    assert len(nodes(graph, "ssm.secret")) == 9
    assert len(nodes(graph, "ssm.version")) == 18
    assert len({n["id"] for n in nodes(graph, "ssm.version")}) == 18
    assert all(
        graph.nodes[e["source"]]["properties"]["EncryptType"] == 0
        for e in graph.edges.values()
        if e["relationship"] == "CONFIGURED_KMS_KEY"
    )


def test_offset_pagination_and_all_status_inventory():
    graph, calls = run({(0, 0): [secret(i) for i in range(21)]})
    assert [
        p["Offset"]
        for a, p in calls
        if a == "ListSecrets" and p["SecretType"] == p["EncryptType"] == 0
    ] == [0, 20]
    assert len(nodes(graph, "ssm.secret")) == 21


def test_ssh_associations_require_ssh_type_and_do_not_infer_key_id_from_name():
    raw = {
        **secret(kind=2),
        "AssociatedInstanceIDs": ["ins-host1"],
        "ResourceName": "Named SSH key",
    }
    graph, _ = run({(2, 0): [raw]})
    assert nodes(graph, "cvm.instance")[0]["resource_id"] == "ins-host1"
    assert not nodes(graph, "cvm.keypair")
    graph, _ = run({(0, 0): [{**raw, "SecretType": 0}]})
    assert not nodes(graph, "cvm.instance")


def test_product_and_user_links_need_same_account_region_collected_identity():
    raw = {**secret(kind=1), "ProductName": "Mysql", "ResourceID": "cdb-test"}
    graph, _ = run({(1, 0): [raw]})
    graph.add("100", "ap-beijing", "cdb.instance", "cdb-test")
    graph.add("200", REGION, "cdb.instance", "cdb-test")
    link_resources(graph)
    assert not any(e["relationship"] == "CREDENTIAL_FOR" for e in graph.edges.values())
    target = graph.add("100", REGION, "cdb.instance", "cdb-test")
    link_resources(graph)
    assert [e["target"] for e in graph.edges.values() if e["relationship"] == "CREDENTIAL_FOR"] == [
        target
    ]
    graph, _ = run({(3, 0): [{**secret(kind=3), "TargetUin": 555, "TargetUinString": "555"}]})
    target = graph.add("100", "global", "cam.user", "555")
    link_resources(graph)
    assert any(
        e["target"] == target and e["relationship"] == "CREDENTIAL_FOR"
        for e in graph.edges.values()
    )


@pytest.mark.parametrize(
    "patch,error",
    [
        ({"SecretName": ""}, "InvalidSecretIdentity"),
        ({"SecretType": 1}, "SecretFilterMismatch"),
        ({"EncryptType": 1}, "SecretFilterMismatch"),
        ({"EncryptType": None}, "SecretFilterMismatch"),
        ({"RotationStatus": True}, "InvalidSecretField"),
        ({"RotationStatus": 2}, "InvalidSecretRotationStatus"),
        ({"CreateTime": -1}, "InvalidSecretField"),
        ({"CreateUinString": "999"}, "SecretUinMismatch"),
        ({"CreateUinString": "user"}, "InvalidSecretUin"),
        ({"AssociatedInstanceIDs": ["subnet-bad"]}, "InvalidSecretInstanceIds"),
        ({"AssociatedInstanceIDs": ["ins-a", "ins-a"]}, "DuplicateSecretInstance"),
    ],
)
def test_invalid_metadata_fails_before_any_graph_mutation(patch, error):
    graph, _ = run({(0, 0): [{**secret(), **patch}]})
    assert not graph.nodes
    assert graph.coverage[0]["error"] == error
    assert graph.coverage[0]["count"] == 0


@pytest.mark.parametrize(
    "versions,error",
    [
        ({"SecretName": "other", "Versions": []}, "SecretIdentityMismatch"),
        ({"Versions": []}, "SecretIdentityMismatch"),
        ({"SecretName": "secret-1", "Versions": None}, "InvalidSecretVersions"),
        (
            {"SecretName": "secret-1", "Versions": [{"VersionId": "v", "CreateTime": True}]},
            "InvalidSecretVersionTime",
        ),
        (
            {"SecretName": "secret-1", "Versions": [{"VersionId": "v", "CreateTime": 1}] * 2},
            "DuplicateSecretVersion",
        ),
        (CollectionError("ResourceNotFound"), "ResourceNotFound"),
    ],
)
def test_invalid_versions_are_partial_without_hiding_secret_or_rotation(versions, error):
    graph, _ = run(versions=versions)
    assert len(nodes(graph, "ssm.secret")) == 1 and not nodes(graph, "ssm.version")
    assert graph.coverage[-2]["error"] == error
    assert graph.coverage[-1]["status"] == "complete"


def test_rotation_changes_are_preserved_without_claiming_success():
    graph, _ = run(
        rotation=dict(
            EnableRotation=True,
            Frequency=30,
            LatestRotateTime="2026-10-01 10:00:00",
            NextRotateBeginTime="2026-10-31 10:00:00",
        )
    )
    props = nodes(graph, "ssm.secret")[0]["properties"]
    assert props["rotation_changed_since_list"] and props["RotationStatus"] == 0
    assert json.loads(props["rotation_detail"])["EnableRotation"] is True
    assert props["rotation_verified"] is False


@pytest.mark.parametrize(
    "raw,error",
    [
        ({"EnableRotation": 1}, "InvalidSecretRotation"),
        ({"EnableRotation": True, "Frequency": "30"}, "InvalidSecretRotation"),
        ({"EnableRotation": False, "SecretName": "wrong"}, "SecretIdentityMismatch"),
        (CollectionError("AccessDenied"), "AccessDenied"),
    ],
)
def test_failed_rotation_does_not_remove_version_metadata(raw, error):
    graph, _ = run(rotation=raw)
    assert len(nodes(graph, "ssm.version")) == 2
    assert graph.coverage[-1]["error"] == error
    assert "rotation_detail" not in nodes(graph, "ssm.secret")[0]["properties"]


def test_duplicate_secrets_missing_total_and_denied_family_are_visible():
    graph, _ = run({(0, 0): [secret(), secret()], (1, 1): CollectionError("AccessDenied")})
    assert graph.coverage[0]["error"] == "DuplicateSecret" and graph.coverage[0]["count"] == 1
    assert graph.coverage[3]["status"] == "denied"
    graph, _ = run(mutate=lambda a, p, r: {**r, "TotalCount": None} if a == "ListSecrets" else r)
    assert graph.coverage[0]["error"] == "InvalidTotal"


def test_no_secret_values_or_opaque_extra_payloads_are_persisted():
    raw = {
        **secret(),
        "SecretString": "never-persist",
        "SecretBinary": "never-persist",
        "AdditionalConfig": "never-persist",
    }
    graph, _ = run({(0, 0): [raw]})
    assert "never-persist" not in graph.dump()


def test_tag_creator_qualified_secret_identifier_matches_collected_creator():
    graph, _ = run()
    raw = dict(
        PaginationToken="",
        ResourceTagMappingList=[
            dict(
                Resource="qcs::ssm:eu-frankfurt:uin/100:secret/creatorUin/321/secret-1",
                Tags=[dict(TagKey="team", TagValue="security")],
            )
        ],
    )
    runner = CollectorRunner(
        graph, SimpleNamespace(call=lambda *a, **kw: raw), "100", [REGION], lambda _: None
    )
    collect_tags(runner)
    link_tags(graph)
    assert not nodes(graph, "tag.resource")
    assert any(
        e["relationship"] == "TAGGED" and graph.nodes[e["source"]]["kind"] == "ssm.secret"
        for e in graph.edges.values()
    )
