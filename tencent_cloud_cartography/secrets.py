"""Secret lifecycle/version metadata. No value, SSH key, or credential retrieval."""

import json
import re

from .kms import configured_key
from .model import stable_id
from .transport import CollectionError, pages


def name(value):
    if not isinstance(value, str) or not value or any(ord(c) < 32 for c in value):
        raise CollectionError("InvalidSecretIdentity")
    return value


def metadata(raw, secret_type, encrypt_type):
    if not isinstance(raw, dict):
        raise CollectionError("InvalidSecretMetadata")
    name(raw.get("SecretName"))
    props = {}
    for typ, fields in (
        (
            str,
            "SecretName Description Status KmsKeyId KmsKeyType ProductName ResourceName ResourceID RotationBeginTime CreateUinString TargetUinString",
        ),
        (
            int,
            "CreateUin TargetUin SecretType EncryptType CreateTime DeleteTime NextRotationTime RotationStatus RotationFrequency ProjectID",
        ),
        (bool, "EncryptSwitching"),
    ):
        for field in fields.split():
            if raw.get(field) is not None:
                if type(raw[field]) is not typ or (typ is int and raw[field] < 0):
                    raise CollectionError("InvalidSecretField")
                props[field] = raw[field]
    allowed_types = {1, 4} if secret_type == 1 else {secret_type}
    if props.get("SecretType") not in allowed_types or props.get("EncryptType") != encrypt_type:
        raise CollectionError("SecretFilterMismatch")
    if not props.get("Status"):
        raise CollectionError("InvalidSecretState")
    if props.get("RotationStatus") not in (None, 0, 1):
        raise CollectionError("InvalidSecretRotationStatus")
    for field in ("CreateUin", "TargetUin"):
        string = props.get(field + "String")
        if string:
            if not re.fullmatch(r"[0-9]+", string):
                raise CollectionError("InvalidSecretUin")
            if field in props and int(string) != props[field]:
                raise CollectionError("SecretUinMismatch")
        elif field in props:
            props[field + "String"] = str(props[field])
    if raw.get("AssociatedInstanceIDs") is not None:
        ids = raw["AssociatedInstanceIDs"]
        if not isinstance(ids, list) or any(
            not isinstance(v, str) or not re.fullmatch(r"ins-[A-Za-z0-9]+", v) for v in ids
        ):
            raise CollectionError("InvalidSecretInstanceIds")
        if len(set(ids)) != len(ids):
            raise CollectionError("DuplicateSecretInstance")
        props["AssociatedInstanceIDs"] = json.dumps(ids)
    props.update(state=props["Status"], secret_value_collected=False, rotation_verified=False)
    return props


def collect_secrets(runner, spec, region):
    found, seen = [], set()
    for secret_type in (0, 1, 2, 3):
        for encrypt_type in (0, 1):

            def inventory(record, secret_type=secret_type, encrypt_type=encrypt_type):
                params = dict(SecretType=secret_type, EncryptType=encrypt_type, State=0)
                for rows, request_id in pages(runner.transport, spec, region, params):
                    if request_id:
                        record["request_ids"].append(request_id)
                    for raw in rows:
                        props = metadata(raw, secret_type, encrypt_type)
                        rid = props["SecretName"]
                        if rid in seen:
                            raise CollectionError("DuplicateSecret")
                        seen.add(rid)
                        nid = runner.graph.add(
                            runner.account, region, "ssm.secret", rid, rid, source="ssm.ListSecrets"
                        )
                        runner.graph.nodes[nid]["properties"].update(props)
                        configured_key(runner.graph, nid, props, "ssm.ListSecrets")
                        if props["SecretType"] == 2:
                            for instance in json.loads(props.get("AssociatedInstanceIDs", "[]")):
                                target = runner.graph.add(
                                    runner.account,
                                    region,
                                    "cvm.instance",
                                    instance,
                                    status="reference",
                                )
                                runner.graph.edge(nid, target, "ASSOCIATED_WITH", "ssm.ListSecrets")
                        found.append(nid)
                        record["count"] += 1

            runner.scope(
                "ssm",
                "ListSecrets",
                region,
                inventory,
                f"SecretType={secret_type} EncryptType={encrypt_type}",
            )
    for nid in found:
        collect_details(runner, nid)


def collect_details(runner, nid):
    node = runner.graph.nodes[nid]
    secret, region = node["resource_id"], node["region"]

    def request(action, record):
        response = runner.transport.call("ssm", action, region=region, SecretName=secret)
        if response.get("RequestId"):
            record["request_ids"].append(response["RequestId"])
        if response.get("SecretName") is not None and response["SecretName"] != secret:
            raise CollectionError("SecretIdentityMismatch")
        return response

    def versions(record):
        response = request("ListSecretVersionIds", record)
        if response.get("SecretName") != secret:
            raise CollectionError("SecretIdentityMismatch")
        rows = response.get("Versions")
        if not isinstance(rows, list):
            raise CollectionError("InvalidSecretVersions")
        selected, seen = [], set()
        for row in rows:
            if not isinstance(row, dict):
                raise CollectionError("InvalidSecretVersion")
            version = name(row.get("VersionId"))
            created = row.get("CreateTime")
            if type(created) is not int or created < 0:
                raise CollectionError("InvalidSecretVersionTime")
            if version in seen:
                raise CollectionError("DuplicateSecretVersion")
            seen.add(version)
            selected.append((version, created))
        for version, created in selected:
            vid = runner.graph.add(
                node["account"],
                region,
                "ssm.version",
                stable_id(secret, version),
                f"{secret} · {version}",
                source="ssm.ListSecretVersionIds",
            )
            runner.graph.nodes[vid]["properties"].update(
                secret_name=secret,
                version_id=version,
                CreateTime=created,
                secret_value_collected=False,
            )
            runner.graph.edge(vid, nid, "VERSION_OF", "ssm.ListSecretVersionIds")
            record["count"] += 1

    def rotation(record):
        raw = request("DescribeRotationDetail", record)
        if type(raw.get("EnableRotation")) is not bool:
            raise CollectionError("InvalidSecretRotation")
        selected = {"EnableRotation": raw["EnableRotation"]}
        for key, typ in (
            ("Frequency", int),
            ("LatestRotateTime", str),
            ("NextRotateBeginTime", str),
        ):
            if raw.get(key) is not None:
                if type(raw[key]) is not typ or (typ is int and raw[key] < 0):
                    raise CollectionError("InvalidSecretRotation")
                selected[key] = raw[key]
        node["properties"]["rotation_detail"] = json.dumps(selected, sort_keys=True)
        if "RotationStatus" in node["properties"]:
            node["properties"]["rotation_changed_since_list"] = raw["EnableRotation"] != bool(
                node["properties"]["RotationStatus"]
            )
        node["sources"] = sorted(set(node["sources"] + ["ssm.DescribeRotationDetail"]))
        record["count"] = 1

    runner.scope("ssm", "ListSecretVersionIds", region, versions, secret)
    runner.scope("ssm", "DescribeRotationDetail", region, rotation, secret)


def link_resources(graph):
    graph.edges = {
        i: e
        for i, e in graph.edges.items()
        if not (e["relationship"] == "CREDENTIAL_FOR" and e.get("provenance") == "ssm.ListSecrets")
    }
    index = {
        (n["account"], n["region"], n["kind"], n["resource_id"]): n
        for n in graph.nodes.values()
        if n["status"] == "enriched"
    }
    for node in list(graph.nodes.values()):
        if node["kind"] != "ssm.secret":
            continue
        props = node["properties"]
        target = None
        if props.get("SecretType") == 1:
            product = props.get("ProductName", "").lower()
            kind = {
                "mysql": "cdb.instance",
                "cdb": "cdb.instance",
                "postgresql": "postgres.dbinstanceid",
                "postgres": "postgres.dbinstanceid",
                "sqlserver": "sqlserver.instance",
                "mariadb": "mariadb.instance",
                "mongodb": "mongodb.instance",
            }.get(product)
            if kind:
                target = index.get((node["account"], node["region"], kind, props.get("ResourceID")))
            props["database_link_resolution"] = (
                "matched_native_product_and_resource_id"
                if target
                else "unresolved_or_unsupported_product"
            )

        elif props.get("SecretType") == 4:
            target = index.get(
                (node["account"], node["region"], "redis.instance", props.get("ResourceID"))
            )
        elif props.get("SecretType") == 3:
            target = index.get(
                (node["account"], "global", "cam.user", props.get("TargetUinString"))
            )
        if target:
            graph.edge(node["id"], target["id"], "CREDENTIAL_FOR", "ssm.ListSecrets")
