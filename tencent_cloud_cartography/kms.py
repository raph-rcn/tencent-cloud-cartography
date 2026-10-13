"""KMS metadata and explicit configuration links; never retrieve key material."""

import json
import re

from .transport import CollectionError

# Explicitly selected fields from the pinned KMS KeyMetadata response model.
KEY_FIELDS = {
    "Alias",
    "Description",
    "CreateTime",
    "KeyState",
    "KeyUsage",
    "Type",
    "CreatorUin",
    "CreatorUinString",
    "KeyRotationEnabled",
    "Owner",
    "NextRotateTime",
    "DeletionDate",
    "Origin",
    "ValidTo",
    "ResourceId",
    "HsmClusterId",
    "RotateDays",
    "LastRotateTime",
    "IsSyncReplica",
    "SourceRegion",
    "SyncStatus",
    "SourceHsmClusterId",
}
KEY_ID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
KEY_RESOURCE = re.compile(r"qcs::kms:([^:*?]+):uin/(\d+):key/(creatorUin/\d+/[^/*?:]+)")


def collect_keys(runner, spec, region):
    graph, owner = runner.graph, runner.account
    keys = {}
    for role in (0, 1):
        # Role=0 is customer-created, Role=1 is created by authorized services.
        # A denied category must not prevent discovery in the other category.
        for nid, item in runner.native(spec, region, {"Role": role}):
            keys[nid] = item
            graph.nodes[nid]["properties"].setdefault("metadata_status", "listed")
    for nid, item in keys.items():
        rid = item["KeyId"]

        def operation(record, nid=nid, rid=rid):
            response = runner.transport.call("kms", "DescribeKey", region, KeyId=rid)
            if response.get("RequestId"):
                record["request_ids"].append(response["RequestId"])
            detail = response.get("KeyMetadata")
            if not isinstance(detail, dict) or detail.get("KeyId") != rid:
                raise CollectionError("IdentityMismatch")
            if not all(
                isinstance(detail.get(k), str) and detail[k] for k in ("KeyState", "KeyUsage")
            ):
                raise CollectionError("InvalidResponse")
            # CreatorUin can be a sub-user. Only AccountUin asserts account ownership.
            account = detail.get("AccountUin")
            if account not in (None, 0, "0", "") and str(account) != owner:
                raise CollectionError("AccountMismatch")
            graph.add(owner, region, "kms.key", rid, detail.get("Alias"), source="kms.DescribeKey")
            props = graph.nodes[nid]["properties"]
            props.update(
                {
                    k: v
                    for k, v in detail.items()
                    if k in KEY_FIELDS and isinstance(v, (str, int, float, bool))
                }
            )
            props.update(metadata_status="described", state=detail.get("KeyState") or "")
            alias = detail.get("Alias")
            if isinstance(alias, str) and alias:
                # Tencent's alias is a key attribute, not AWS's standalone alias API.
                # Scope by key ID so equal display names never merge separate keys.
                aid = graph.add(
                    owner, region, "kms.alias", f"{rid}/alias", alias, source="kms.DescribeKey"
                )
                graph.edge(nid, aid, "HAS_ALIAS", "kms.DescribeKey")
            record["count"] = 1

        runner.scope("kms", "DescribeKey", region, operation, str(rid))


def configured_key(graph, nid, raw, source):
    node = graph.nodes[nid]
    key_id = raw.get("KmsKeyId")
    if not isinstance(key_id, str) or not key_id:
        return
    # Do not infer default keys from Encrypt=True or follow arbitrary nested KeyId
    # fields (CVM KeyIds are SSH keys). Unknown representations remain properties.
    if not KEY_ID.fullmatch(key_id):
        node["properties"]["kms_reference_status"] = "unresolved-format"
        return
    if (node["kind"] == "cbs.disk" and raw.get("Encrypt") is False) or (
        node["kind"] == "ssm.secret" and raw.get("EncryptType") == 1
    ):
        node["properties"]["kms_reference_status"] = "conflicting-metadata"
        return
    target = graph.add(node["account"], node["region"], "kms.key", key_id, status="reference")
    graph.edge(nid, target, "CONFIGURED_KMS_KEY", source)


def link_policy_resources(graph):
    """Link exact scoped policy references, including denies, without evaluating access."""
    index = {}
    for node in graph.nodes.values():
        if node["kind"] == "kms.key" and node["properties"].get("ResourceId"):
            identity = (node["account"], node["region"], node["properties"]["ResourceId"])
            index.setdefault(identity, []).append(node["id"])
    for node in list(graph.nodes.values()):
        if node["kind"] != "cam.policystatement":
            continue
        resources = json.loads(node["properties"].get("resource", "[]"))
        for expression in resources:
            match = KEY_RESOURCE.fullmatch(expression)
            if not match:
                continue
            region, account, resource = match.groups()
            targets = index.get((account, region, resource), [])
            if len(targets) == 1:
                graph.edge(
                    node["id"],
                    targets[0],
                    "NAMES_RESOURCE",
                    "CAM resource expression + kms.DescribeKey",
                )
