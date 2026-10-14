"""COS bucket configuration; no object reads or effective-access assertions."""

import json

from .cam import add_document, parse_document
from .cos_notifications import notification
from .cos_transport import BUCKET, COS_ACTIONS
from .kms import KEY_ID
from .model import stable_id
from .transport import CollectionError

ALL_USERS = "http://cam.qcloud.com/groups/global/AllUsers"


def sequence(value):
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list) and all(isinstance(item, dict) for item in value):
        return value
    raise CollectionError("InvalidResponse")


def acl(graph, bucket, data, source):
    owner = data.get("Owner")
    control = data.get("AccessControlList")
    if not isinstance(owner, dict) or not isinstance(owner.get("ID"), str):
        raise CollectionError("InvalidResponse")
    grants = [] if control is None else sequence(control.get("Grant"))
    selected = []
    for grant in grants:
        grantee, permission = grant.get("Grantee"), grant.get("Permission")
        if not isinstance(grantee, dict) or permission not in {
            "READ",
            "WRITE",
            "READ_ACP",
            "WRITE_ACP",
            "FULL_CONTROL",
        }:
            raise CollectionError("InvalidResponse")
        fields = {k: grantee[k] for k in ("ID", "URI", "Type", "type") if k in grantee}
        if not any(fields.get(k) for k in ("ID", "URI")) or not all(
            isinstance(value, str) for value in fields.values()
        ):
            raise CollectionError("InvalidResponse")
        selected.append(dict(**fields, permission=permission))
    props = bucket["properties"]
    props.update(acl_owner_id=owner["ID"], acl_collected=True, access_evaluated=False)
    # COS owner IDs may contain AppId; they are not a CAM account UIN assertion.
    for grant in selected:
        nid = graph.add(
            bucket["account"],
            bucket["region"],
            "cos.aclgrant",
            bucket["resource_id"] + "/" + stable_id(json.dumps(grant, sort_keys=True)),
            grant["permission"] + " · " + (grant.get("URI") or grant.get("ID")),
            source=source,
        )
        graph.nodes[nid]["properties"].update(
            grant, all_users=grant.get("URI") == ALL_USERS, access_evaluated=False
        )
        graph.edge(bucket["id"], nid, "HAS_ACL_GRANT", source)


def policy(graph, bucket, data, source):
    document = parse_document(data.get("Policy"), cos=True)
    if any("principal" not in statement for statement in document["statement"]):
        raise CollectionError("InvalidPolicyDocument")
    add_document(graph, bucket["id"], document, source)
    bucket["properties"]["policy_collected"] = True


def encryption(graph, bucket, data, source):
    rules = sequence(data.get("Rule"))
    selected = []
    for rule in rules:
        config = rule.get("ApplyServerSideEncryptionByDefault")
        if not isinstance(config, dict) or config.get("SSEAlgorithm") not in {
            "AES256",
            "SM4",
            "KMS",
        }:
            raise CollectionError("InvalidResponse")
        clean = {"SSEAlgorithm": config["SSEAlgorithm"]}
        if "KMSMasterKeyID" in config:
            if not isinstance(config["KMSMasterKeyID"], str):
                raise CollectionError("InvalidResponse")
            clean["KMSMasterKeyID"] = config["KMSMasterKeyID"]
        selected.append(clean)
    if not selected:
        raise CollectionError("InvalidResponse")
    bucket["properties"]["default_encryption_rules"] = json.dumps(selected, sort_keys=True)
    for config in selected:
        key = config.get("KMSMasterKeyID", "")
        if config["SSEAlgorithm"] == "KMS" and KEY_ID.fullmatch(key):
            nid = graph.add(
                bucket["account"],
                bucket["region"],
                "kms.key",
                key,
                source=source,
                status="reference",
            )
            graph.edge(bucket["id"], nid, "CONFIGURED_ENCRYPTION_KEY", source)


def versioning(graph, bucket, data, source):
    status = data.get("Status")
    if status not in {None, "Enabled", "Suspended"}:
        raise CollectionError("InvalidResponse")
    if status is None and data and data != {"VersioningConfiguration": None}:
        raise CollectionError("InvalidResponse")
    bucket["properties"]["versioning_status"] = status or "Unconfigured"


def logging(graph, bucket, data, source):
    config = data.get("LoggingEnabled")
    if config is None:
        if data and data not in ({"LoggingEnabled": None}, {"BucketLoggingStatus": None}):
            raise CollectionError("InvalidResponse")
        bucket["properties"]["logging_configured"] = False
        return
    if (
        not isinstance(config, dict)
        or not isinstance(config.get("TargetBucket"), str)
        or not BUCKET.fullmatch(config["TargetBucket"])
    ):
        raise CollectionError("InvalidResponse")
    prefix = config.get("TargetPrefix") or ""
    if not isinstance(prefix, str):
        raise CollectionError("InvalidResponse")
    bucket["properties"].update(logging_configured=True, logging_target_prefix=prefix)
    nid = graph.add(
        bucket["account"],
        bucket["region"],
        "cos.bucket",
        config["TargetBucket"],
        source=source,
        status="reference",
    )
    graph.edge(bucket["id"], nid, "CONFIGURED_LOG_DESTINATION", source)


HANDLERS = {
    "get_bucket_" + fn.__name__: fn for fn in (acl, policy, encryption, versioning, logging)
}

HANDLERS["get_bucket_notification"] = notification


def collect_bucket(runner, nid):
    bucket = runner.graph.nodes[nid]
    for action in sorted(COS_ACTIONS):

        def operation(record, action=action):
            response = runner.transport.call(
                "cos", action, bucket["region"], Bucket=bucket["resource_id"]
            )
            HANDLERS[action](runner.graph, bucket, response, "cos." + action)
            record["count"] = 1

        runner.scope("cos", action, bucket["region"], operation, bucket["resource_id"])
