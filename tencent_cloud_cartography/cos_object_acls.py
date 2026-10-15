"""Bounded named-object ACL metadata and conservative default-endpoint inheritance."""

import json
import re
from pathlib import Path

from .authorization import (
    attach_evidence,
    context_values,
    evaluate,
    index,
    limit_record,
    replace_generated,
)
from .cam import _unique_object
from .cos import ALL_USERS, acl
from .cos_transport import BUCKET
from .model import Graph, stable_id
from .permissions import identities
from .public_access import statements
from .transport import CollectionError

SOURCE = "analysis.cos-object-acls"
MAX_OBJECTS = 256


def validate(rows):
    if not isinstance(rows, list) or len(rows) > MAX_OBJECTS:
        raise ValueError("COS ACL manifest must contain at most 256 named objects")
    seen = set()
    for row in rows:
        if (
            not isinstance(row, dict)
            or set(row) - {"account", "region", "bucket", "key", "version_id"}
            or not {"account", "region", "bucket", "key"} <= set(row)
        ):
            raise ValueError("Invalid COS ACL manifest entry")
        if (
            not isinstance(row["account"], str)
            or not re.fullmatch(r"[1-9][0-9]*", row["account"])
            or not isinstance(row["bucket"], str)
            or not BUCKET.fullmatch(row["bucket"])
            or not isinstance(row["region"], str)
            or not re.fullmatch(r"[a-z]+-[a-z0-9-]+", row["region"])
        ):
            raise ValueError("Invalid COS ACL scope")
        if not isinstance(row["key"], str) or not row["key"]:
            raise ValueError("Invalid COS object identity")
        if "version_id" in row and row["version_id"] is None:
            raise ValueError("Invalid COS object version")
        for key in ("key", "version_id"):
            value = row.get(key)
            if value is not None and (
                not isinstance(value, str)
                or not value
                or len(value.encode()) > 1024
                or any(ord(c) < 32 for c in value)
            ):
                raise ValueError("Invalid COS object identity")
        if row["key"].startswith("/") or any(part in {".", ".."} for part in row["key"].split("/")):
            raise ValueError("COS ACL selection requires a canonical object key")
        if any(c in row["key"] for c in "*?"):
            raise ValueError("COS ACL selection requires literal keys without policy wildcards")
        identity = tuple(
            row.get(k, "") for k in ("account", "region", "bucket", "key", "version_id")
        )
        if identity in seen:
            raise ValueError("Duplicate COS ACL selection")
        seen.add(identity)
    return rows


def load(path):
    raw = Path(path).read_bytes()
    if len(raw) > 524288:
        raise ValueError("COS ACL manifest exceeds 512 KiB")
    return validate(json.loads(raw, object_pairs_hook=_unique_object))


def collect(runner, selections):
    for row in validate(selections):
        if row["account"] != runner.account:
            continue

        def operation(record, row=row):
            bucket_id = stable_id(runner.account, row["region"], "cos.bucket", row["bucket"])
            bucket = runner.graph.nodes.get(bucket_id)
            if (
                not bucket
                or bucket["status"] != "enriched"
                or row["region"] not in runner.regions_for("cos")
            ):
                raise CollectionError("CosAclBucketOutsideCollectedScope")
            params = dict(Bucket=row["bucket"], Key=row["key"])
            if row.get("version_id"):
                params["VersionId"] = row["version_id"]
            response = runner.transport.call("cos", "get_object_acl", row["region"], **params)
            # Validate before publishing either the object or any grant.
            temp = Graph()
            oid = temp.add(
                runner.account,
                row["region"],
                "cos.objectacl",
                stable_id(row["bucket"], row["key"], row.get("version_id", "")),
                row["key"],
                source="cos.get_object_acl",
            )
            obj = temp.nodes[oid]
            response = dict(response)
            if response.get("AccessControlList") in (None, "", {}):
                response["AccessControlList"] = None
            acl(temp, obj, response, "cos.get_object_acl")
            if any(n["properties"].get("permission") == "WRITE" for n in temp.nodes.values()):
                raise CollectionError("UnsupportedCosObjectWriteAcl")
            grants = [n for n in temp.nodes.values() if n["kind"] == "cos.aclgrant"]
            obj["properties"].update(
                bucket_name=row["bucket"],
                object_key=row["key"],
                version_id=row.get("version_id", ""),
                acl_mode="default"
                if response.get("CannedACL") == "default" or not grants
                else "explicit",
                acl_mode_source="provider_default_header"
                if response.get("CannedACL") == "default"
                else "acl_document",
                object_body_collected=False,
                object_inventory_complete=False,
            )
            if not obj["properties"].get("acl_owner_id"):
                raise CollectionError("InvalidCosObjectOwner")
            runner.graph.nodes.update(temp.nodes)
            runner.graph.edges.update(temp.edges)
            runner.graph.edge(bucket_id, oid, "HAS_SELECTED_OBJECT_ACL", "cos.get_object_acl")
            record["count"] = 1
            if response.get("x-cos-request-id"):
                record["request_ids"].append(response["x-cos-request-id"])

        runner.scope(
            "cos", "get_object_acl", row["region"], operation, json.dumps(row, sort_keys=True)
        )


def inherited(graph, obj, bucket, objects):
    """Missing/denied directory ACL evidence stays unknown, including 404s."""
    if obj["properties"].get("acl_mode") == "explicit":
        return obj, "explicit_object", True
    key = obj["properties"]["object_key"]
    # Directory ACL evidence concerns the current directory configuration, even
    # when a selected object is a historical version.
    parts = key.rstrip("/").split("/")
    for i in range(len(parts) - 1, 0, -1):
        parent_key = "/".join(parts[:i]) + "/"
        parent = objects.get((obj["account"], obj["region"], bucket["resource_id"], parent_key, ""))
        if not parent or parent["properties"].get("acl_collected") is not True:
            return None, "uncollected_directory_acl", False
        if parent["properties"].get("acl_mode") == "explicit":
            return parent, "explicit_directory", True
    return bucket, "bucket_default", bucket["properties"].get("acl_collected") is True


def analyze(graph, context=None, max_decisions=25000):
    context = context_values(context)
    replace_generated(graph, {"cos.objectacldecision"}, {"AnalyzeSelectedCosObjectAcls"})
    outgoing = index(graph)
    objects = {
        (
            n["account"],
            n["region"],
            p.get("bucket_name"),
            p.get("object_key"),
            p.get("version_id", ""),
        ): n
        for n in graph.nodes.values()
        if n["kind"] == "cos.objectacl" and n["status"] == "enriched"
        for p in [n["properties"]]
    }
    count = 0
    for obj in objects.values():
        p = obj["properties"]
        bucket = graph.nodes.get(
            stable_id(obj["account"], obj["region"], "cos.bucket", p.get("bucket_name"))
        )
        if not bucket or bucket["status"] != "enriched" or not identities(bucket):
            continue
        selected, mode, complete = inherited(graph, obj, bucket, objects)
        policy_rows, _ = statements(graph, bucket, outgoing)
        # Bucket grants are replaced by the selected inheritance source. Policies
        # are retained; their explicit deny still takes precedence over object ACLs.
        policy_rows = [
            (sid, r) for sid, r in policy_rows if graph.nodes[sid]["kind"] == "cam.policystatement"
        ]
        policy_complete = bucket["properties"].get("policy_collected") is True
        if not bucket["properties"].get("policy_document") and not bucket["properties"].get(
            "policy_absent"
        ):
            policy_complete = False
        owners = [n["properties"].get("acl_owner_id", "") for n in (obj, bucket, selected) if n]
        conflict = any(
            owner.startswith("qcs::cam::uin/")
            and owner != f"qcs::cam::uin/{obj['account']}:uin/{obj['account']}"
            for owner in owners
        )
        canonical = identities(bucket)[0][:-1] + p["object_key"]
        for permission, action in (
            ("READ", "cos:GetObject"),
            ("READ_ACP", "cos:GetObjectACL"),
            ("WRITE_ACP", "cos:PutObjectACL"),
        ):
            if count >= max_decisions:
                limit_record(graph, "AnalyzeSelectedCosObjectAcls", count, max_decisions)
                return
            if p.get("version_id"):
                action = action.replace("Object", "ObjectVersion")
            rows = list(policy_rows)
            if selected:
                for edge in outgoing.get(selected["id"], ()):
                    if edge["relationship"] != "HAS_ACL_GRANT":
                        continue
                    grant = graph.nodes[edge["target"]]
                    gp = grant["properties"]
                    if gp.get("URI") != ALL_USERS and gp.get("ID") not in {
                        "qcs::cam::anyone:anyone",
                        "qcs::cam::anonymous:anonymous",
                    }:
                        continue
                    permitted = gp.get("permission") in {permission, "FULL_CONTROL"}
                    # Bucket ACP grants concern the bucket ACL, not an object ACL.
                    if selected["kind"] == "cos.bucket" and permission != "READ":
                        permitted = False
                    if permitted:
                        rows.append(
                            (
                                grant["id"],
                                dict(effect="allow", action=[action], resource=[canonical]),
                            )
                        )
            evaluated_context = dict(context)
            if p.get("version_id"):
                evaluated_context["cos:versionid"] = p["version_id"]
            gate = evaluate(
                rows,
                action,
                canonical,
                evaluated_context,
                policy_complete and complete and not conflict,
                bucket["account"],
                bucket,
            )
            nid = graph.add(
                obj["account"],
                obj["region"],
                "cos.objectacldecision",
                stable_id(obj["id"], action),
                f"Selected object {action}: {gate.decision}",
                source=SOURCE,
            )
            graph.nodes[nid]["properties"].update(
                action=action,
                resource_scope=canonical,
                version_id=p.get("version_id", ""),
                decision=gate.decision,
                acl_inheritance=mode,
                acl_inheritance_complete=complete,
                bucket_policy_complete=bool(policy_complete),
                owner_metadata_conflict=conflict,
                evaluation_scope="selected_object_anonymous_configuration_default_cos_endpoint",
                effective_access_verified=False,
                object_body_collected=False,
                evaluated_context=json.dumps(evaluated_context, sort_keys=True),
                authorization_evidence=attach_evidence(graph, nid, [gate], SOURCE),
            )
            graph.edge(obj["id"], nid, "HAS_OBJECT_ACL_ANALYSIS", SOURCE)
            if selected:
                graph.edge(nid, selected["id"], "USES_ACL_CONFIGURATION", SOURCE)
            graph.coverage.append(
                dict(
                    account=obj["account"],
                    region=obj["region"],
                    service="analysis",
                    action="AnalyzeSelectedCosObjectAcls",
                    detail=obj["id"] + "/" + action,
                    status="error" if gate.decision == "unknown" else "complete",
                    error="UnresolvedObjectAclEvidence" if gate.decision == "unknown" else "",
                    count=1,
                    request_ids=[],
                )
            )
            count += 1


def parse_xml(body):
    """Fixed ACL XML metadata with bounded UTF-8 parsing and no entity expansion."""
    import xml.etree.ElementTree as ET

    if not isinstance(body, bytes) or len(body) > 262144:
        raise CollectionError("InvalidCosAclXml")
    try:
        text = body.decode("utf-8")
        if "\x00" in text or "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
            raise ValueError
        root = ET.fromstring(text)
        namespace = root.tag.split("}")[0] + "}" if root.tag.startswith("{") else ""
        if (
            namespace
            not in (
                "",
                "{http://s3.amazonaws.com/doc/2006-03-01/}",
                "{http://www.qcloud.com/document/product/436/7751}",
                "{https://cloud.tencent.com/document/product/436}",
            )
            or root.tag != namespace + "AccessControlPolicy"
        ):
            raise ValueError
        count = 0

        def convert(element, depth=0):
            nonlocal count
            count += 1
            if depth > 6 or count > 2000:
                raise ValueError
            if not list(element):
                return element.text or ""
            result = {}
            for child in element:
                if namespace and not child.tag.startswith(namespace):
                    raise ValueError
                tag = child.tag.removeprefix(namespace)
                if "{" in tag or "}" in tag:
                    raise ValueError
                value = convert(child, depth + 1)
                if tag in result:
                    if tag != "Grant":
                        raise ValueError
                    result[tag] = (
                        result[tag] + [value]
                        if isinstance(result[tag], list)
                        else [result[tag], value]
                    )
                else:
                    result[tag] = value
            return result

        data = convert(root)
        if (
            not isinstance(data, dict)
            or not isinstance(data.get("Owner"), dict)
            or not data["Owner"].get("ID")
            or "AccessControlList" not in data
        ):
            raise ValueError
        return data
    except (ValueError, ET.ParseError):
        raise CollectionError("InvalidCosAclXml") from None


def current_objects(graph, bucket):
    return {
        identities(bucket)[0][:-1] + n["properties"]["object_key"]: n
        for n in graph.nodes.values()
        if n["kind"] == "cos.objectacl"
        and n["status"] == "enriched"
        and (n["account"], n["region"]) == (bucket["account"], bucket["region"])
        and n["properties"].get("bucket_name") == bucket["resource_id"]
        and not n["properties"].get("version_id")
    }


def scoped_rows(graph, bucket, obj, principal, outgoing, rows, anonymous=False):
    """Replace bucket ACL grants with proven current-object inheritance evidence."""
    from .authorization import ANONYMOUS, principal_match

    objects = {
        (
            n["account"],
            n["region"],
            n["properties"].get("bucket_name"),
            n["properties"].get("object_key"),
            n["properties"].get("version_id", ""),
        ): n
        for n in graph.nodes.values()
        if n["kind"] == "cos.objectacl" and n["status"] == "enriched"
    }
    selected, _, complete = inherited(graph, obj, bucket, objects)
    result = [(sid, row) for sid, row in rows if graph.nodes[sid]["kind"] == "cam.policystatement"]
    if selected:
        for edge in outgoing.get(selected["id"], ()):
            if edge["relationship"] != "HAS_ACL_GRANT":
                continue
            grant = graph.nodes[edge["target"]]
            p = grant["properties"]
            is_public = p.get("URI") == ALL_USERS or p.get("ID") in ANONYMOUS
            if anonymous != is_public:
                continue
            match = (
                True
                if anonymous
                else True
                if p.get("URI") == "http://cam.qcloud.com/groups/global/AuthenticatedUsers"
                else principal_match({"qcs": [p["ID"]]}, principal, graph, outgoing)
                if p.get("ID")
                else None
            )
            if match is False:
                continue
            permissions = (
                {"READ", "READ_ACP", "WRITE_ACP"}
                if p.get("permission") == "FULL_CONTROL"
                else {p.get("permission")}
            )
            if selected["kind"] == "cos.bucket":
                permissions &= {"READ"}
            actions = [
                {
                    "READ": "cos:GetObject",
                    "READ_ACP": "cos:GetObjectACL",
                    "WRITE_ACP": "cos:PutObjectACL",
                }[v]
                for v in permissions
                if v in {"READ", "READ_ACP", "WRITE_ACP"}
            ]
            if not actions:
                continue
            selector = p.get("ID", "")
            delegated = not anonymous and selector in {
                f"qcs::cam::uin/{principal['account']}:root",
                f"qcs::cam::uin/{principal['account']}:uin/{principal['account']}",
            }
            result.append(
                (
                    grant["id"],
                    dict(
                        effect="allow",
                        action=actions,
                        resource=[identities(bucket)[0][:-1] + obj["properties"]["object_key"]],
                        _principal_match=match,
                        _account_delegation=delegated,
                    ),
                )
            )
    owners = [n["properties"].get("acl_owner_id", "") for n in (bucket, obj, selected) if n]
    if any(
        owner.startswith("qcs::cam::uin/")
        and owner != f"qcs::cam::uin/{bucket['account']}:uin/{bucket['account']}"
        for owner in owners
    ):
        complete = False
    return result, complete
