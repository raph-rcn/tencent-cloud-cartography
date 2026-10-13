import json

import pytest

from tencent_cloud_cartography.cam import add_document, parse_document
from tencent_cloud_cartography.catalog import COLLECTORS
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.kms import collect_keys, link_policy_resources
from tencent_cloud_cartography.model import Graph, stable_id
from tencent_cloud_cartography.topology import topology
from tencent_cloud_cartography.transport import CollectionError

KEY_A = "11111111-2222-3333-4444-555555555555"
KEY_B = "66666666-7777-8888-9999-aaaaaaaaaaaa"
SPEC = next(s for s in COLLECTORS if s.service == "kms")


def metadata(key_id, **extra):
    return dict(
        KeyId=key_id,
        Alias="disk-encryption",
        KeyState="Enabled",
        KeyUsage="ENCRYPT_DECRYPT",
        ResourceId=f"creatorUin/101/{key_id}",
        CreatorUin=101,
        CreatorUinString="101",
        **extra,
    )


def test_both_creator_categories_metadata_aliases_and_no_key_material():
    graph, calls = Graph(), []

    class Transport:
        def call(self, service, action, region=None, **params):
            calls.append((service, action, region, params))
            if action == "ListKeys":
                assert params["Role"] in {0, 1}
                return dict(
                    Keys=[dict(KeyId=KEY_A if params["Role"] == 0 else KEY_B)], TotalCount=1
                )
            assert action == "DescribeKey"
            return dict(
                KeyMetadata=metadata(
                    params["KeyId"],
                    KeyRotationEnabled=False,
                    NextRotateTime=0,
                    ValidTo=0,
                    Origin="EXTERNAL",
                    SecretKey="do-not-store",
                    KeyMaterial="do-not-store",
                    AccountUin=100,
                ),
                RequestId=params["KeyId"],
            )

    collect_keys(
        CollectorRunner(graph, Transport(), "100", ["eu-frankfurt"], lambda _: None),
        SPEC,
        "eu-frankfurt",
    )
    assert [c[3]["Role"] for c in calls if c[1] == "ListKeys"] == [0, 1]
    keys = [n for n in graph.nodes.values() if n["kind"] == "kms.key"]
    aliases = [n for n in graph.nodes.values() if n["kind"] == "kms.alias"]
    assert len(keys) == len(aliases) == 2
    assert len({n["id"] for n in aliases}) == 2  # Identical names cannot conflate keys.
    assert all(n["properties"]["KeyRotationEnabled"] is False for n in keys)
    assert all(n["properties"]["NextRotateTime"] == 0 for n in keys)
    assert all(n["properties"]["CreatorUin"] == 101 and n["account"] == "100" for n in keys)
    assert "do-not-store" not in graph.dump()
    assert all(icon_for(n["kind"]) != "unmapped.svg" for n in graph.nodes.values())
    assert len(graph.coverage) == 4 and all(c["status"] == "complete" for c in graph.coverage)
    assert topology(graph.snapshot())["stats"]["resources"] == 0
    assert topology(graph.snapshot(), view="full")["stats"]["relationships"] == 2


@pytest.mark.parametrize(
    "bad,error",
    [
        (dict(KeyId="wrong"), "IdentityMismatch"),
        (metadata(KEY_A, AccountUin=999), "AccountMismatch"),
        (dict(KeyId=KEY_A), "InvalidResponse"),
        (CollectionError("UnauthorizedOperation"), "UnauthorizedOperation"),
    ],
)
def test_detail_errors_preserve_listed_key_and_coverage(bad, error):
    graph = Graph()

    class Transport:
        def call(self, service, action, region=None, **params):
            if action == "ListKeys":
                keys = [dict(KeyId=KEY_A)] if params["Role"] == 0 else []
                return dict(Keys=keys, TotalCount=len(keys))
            if isinstance(bad, Exception):
                raise bad
            return dict(KeyMetadata=bad, RequestId="mismatch")

    collect_keys(
        CollectorRunner(graph, Transport(), "100", [], lambda _: None), SPEC, "eu-frankfurt"
    )
    assert len(graph.nodes) == 1 and not graph.edges
    assert next(iter(graph.nodes.values()))["properties"]["metadata_status"] == "listed"
    assert graph.coverage[-1]["error"] == error
    assert graph.snapshot()["status"] == "partial"


def test_denied_customer_category_still_collects_service_keys():
    graph = Graph()

    class Transport:
        def call(self, service, action, region=None, **params):
            if action == "ListKeys":
                if params["Role"] == 0:
                    raise CollectionError("UnauthorizedOperation")
                return dict(Keys=[dict(KeyId=KEY_B)], TotalCount=1)
            return dict(KeyMetadata=metadata(KEY_B, Owner="cbs"))

    collect_keys(
        CollectorRunner(graph, Transport(), "100", [], lambda _: None), SPEC, "eu-frankfurt"
    )
    assert graph.coverage[0]["status"] == "denied"
    assert (
        graph.nodes[stable_id("100", "eu-frankfurt", "kms.key", KEY_B)]["properties"]["Owner"]
        == "cbs"
    )


def native(graph, kind, raw, account="100", region="eu-frankfurt"):
    spec = next(s for s in COLLECTORS if s.kind == kind)
    return graph.native(account, region, spec, raw, f"{spec.service}.{spec.action}")


def test_explicit_encryption_links_and_negative_controls():
    graph = Graph()
    disk = native(graph, "cbs.disk", dict(DiskId="disk-1", Encrypt=True, KmsKeyId=KEY_A))
    secret = native(
        graph,
        "ssm.secret",
        dict(
            SecretName="db-credentials",
            KmsKeyId=KEY_A,
            RotationStatus=0,
            RotationFrequency=30,
            EncryptType=0,
            EncryptSwitching=True,
            SecretString="do-not-store",
        ),
    )
    native(graph, "cbs.disk", dict(DiskId="disk-default", Encrypt=True))
    conflict = native(
        graph, "cbs.disk", dict(DiskId="disk-conflict", Encrypt=False, KmsKeyId=KEY_B)
    )
    native(graph, "ssm.secret", dict(SecretName="soft-key", EncryptType=1, KmsKeyId=KEY_B))
    native(graph, "cbs.snapshot", dict(SnapshotId="snap-1", Encrypt=True, KmsKeyId=KEY_B))
    native(graph, "cvm.keypair", dict(KeyId=KEY_B))  # SSH keys are not KMS keys.
    unresolved = native(graph, "ssm.secret", dict(SecretName="alias", KmsKeyId="alias/not-an-id"))
    edges = [e for e in graph.edges.values() if e["relationship"] == "CONFIGURED_KMS_KEY"]
    assert {e["source"] for e in edges} == {disk, secret}
    assert len({e["target"] for e in edges}) == 1
    assert graph.nodes[conflict]["properties"]["kms_reference_status"] == "conflicting-metadata"
    assert graph.nodes[unresolved]["properties"]["kms_reference_status"] == "unresolved-format"
    assert graph.nodes[secret]["properties"]["RotationStatus"] == 0
    assert "do-not-store" not in graph.dump()


def test_key_references_keep_account_and_region_separate():
    graph = Graph()
    for account, region in [
        ("100", "eu-frankfurt"),
        ("100", "ap-guangzhou"),
        ("200", "eu-frankfurt"),
    ]:
        native(
            graph, "cbs.disk", dict(DiskId="disk-1", Encrypt=True, KmsKeyId=KEY_A), account, region
        )
    assert len([n for n in graph.nodes.values() if n["kind"] == "kms.key"]) == 3
    for edge in graph.edges.values():
        a, b = graph.nodes[edge["source"]], graph.nodes[edge["target"]]
        assert (a["account"], a["region"]) == (b["account"], b["region"])


def test_policy_resource_links_are_exact_and_do_not_imply_permissions():
    graph = Graph()
    key = graph.add("100", "eu-frankfurt", "kms.key", KEY_A)
    graph.nodes[key]["properties"]["ResourceId"] = f"creatorUin/101/{KEY_A}"
    parent = graph.add("100", "global", "cam.policy", "7")
    base = f"qcs::kms:eu-frankfurt:uin/100:key/creatorUin/101/{KEY_A}"
    resources = [
        base,
        base.replace("uin/100", "uin/200"),
        base.replace("eu-frankfurt", "*"),
        base.replace("uin/100", "uid/100"),
        base.replace("/101/", "/999/"),
        "*",
    ]
    document = parse_document(
        json.dumps(
            dict(
                version="2.0",
                statement=[
                    dict(
                        effect="deny",
                        action="name/kms:Decrypt",
                        resource=resources,
                        condition={"ip_equal": {"qcs:ip": "192.0.2.0/24"}},
                    )
                ],
            )
        )
    )
    add_document(graph, parent, document, "cam.GetPolicy")
    link_policy_resources(graph)
    edges = [e for e in graph.edges.values() if e["relationship"] == "NAMES_RESOURCE"]
    assert len(edges) == 1 and edges[0]["target"] == key
    assert graph.nodes[edges[0]["source"]]["properties"]["effect"] == "deny"
    assert not any(e["relationship"] in {"CAN_DECRYPT", "CAN_ACCESS"} for e in graph.edges.values())
