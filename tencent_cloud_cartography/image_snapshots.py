"""Owned and in-use image/snapshot metadata, with explicit sharing provenance."""

import json
import re
from dataclasses import replace

from .catalog import COLLECTORS
from .transport import CollectionError, pages

SPECS = {s.kind: s for s in COLLECTORS if s.kind in {"cvm.image", "cbs.snapshot"}}


def identity(value, prefix):
    if not isinstance(value, str) or not re.fullmatch(prefix + r"-[A-Za-z0-9]+", value):
        raise CollectionError("InvalidImageSnapshotIdentity")
    return value


def properties(raw, kind):
    if not isinstance(raw, dict):
        raise CollectionError("InvalidImageSnapshotMetadata")
    image = kind == "cvm.image"
    prefix, id_field, type_field = (
        ("img", "ImageId", "ImageType") if image else ("snap", "SnapshotId", "SnapshotType")
    )
    rid = identity(raw.get(id_field), prefix)
    allowed = (
        {"PRIVATE_IMAGE", "SHARED_IMAGE", "PUBLIC_IMAGE"}
        if image
        else {"PRIVATE_SNAPSHOT", "SHARED_SNAPSHOT"}
    )
    if raw.get(type_field) not in allowed:
        raise CollectionError("InvalidImageSnapshotType")
    strings = (
        (
            "OsName",
            "ImageName",
            "ImageDescription",
            "Architecture",
            "ImageState",
            "Platform",
            "ImageCreator",
            "ImageSource",
            "CreatedTime",
            "LicenseType",
            "ImageFamily",
            "CdcCacheStatus",
        )
        if image
        else (
            "SnapshotName",
            "SnapshotState",
            "DeadlineTime",
            "DiskUsage",
            "CreateTime",
            "TimeStartShare",
            "LatestModifyTime",
            "SnapshotMode",
        )
    )
    integers = (
        ("ImageSize", "SyncPercent")
        if image
        else ("Percent", "ShareReference", "DiskSize", "ImageCount")
    )
    booleans = (
        ("IsSupportCloudinit", "ImageDeprecated")
        if image
        else ("CopyFromRemote", "IsPermanent", "Encrypt", "IsLocked")
    )
    props = {
        id_field: rid,
        type_field: raw[type_field],
        "owned_by_collected_account": raw[type_field].startswith("PRIVATE_"),
        "account_scope": "queried-account",
        "public_access_evaluated": False,
    }
    for fields, typ in ((strings, str), (integers, int), (booleans, bool)):
        for key in fields:
            value = raw.get(key)
            if value is not None:
                if type(value) is not typ or (typ is int and value < 0):
                    raise CollectionError("InvalidImageSnapshotMetadata")
                props[key] = value
    props["state"] = props.get("ImageState" if image else "SnapshotState", "")
    refs = []
    if image:
        snapshots = raw.get("SnapshotSet", [])
        if snapshots is None:
            snapshots = []
        if not isinstance(snapshots, list):
            raise CollectionError("InvalidImageSnapshots")
        ids = [
            identity(s.get("SnapshotId"), "snap") if isinstance(s, dict) else identity(None, "snap")
            for s in snapshots
        ]
        if len(ids) != len(set(ids)):
            raise CollectionError("DuplicateImageSnapshot")
        props["snapshot_ids"] = json.dumps(ids)
        # A foreign image does not identify the owner of its backing snapshots.
        if props["owned_by_collected_account"]:
            refs = [("cbs.snapshot", i, "USES_SNAPSHOT") for i in ids]
    else:
        if raw.get("DiskId"):
            props["DiskId"] = identity(raw["DiskId"], "disk")
            if props["owned_by_collected_account"]:
                refs = [("cbs.disk", props["DiskId"], "SNAPSHOT_OF")]
    return rid, props, refs


def add(runner, spec, region, prepared):
    rid, props, refs = prepared
    source = f"{spec.service}.{spec.action}"
    nid = runner.graph.add(
        runner.account, region, spec.kind, rid, props.get(spec.names[0]), source=source
    )
    runner.graph.nodes[nid]["properties"].update(props)
    for kind, target, relation in refs:
        other = runner.graph.add(
            runner.account, region, kind, target, source=source, status="reference"
        )
        runner.graph.edge(nid, other, relation, source)
    return nid


def collect_shares(runner, nid):
    node = runner.graph.nodes[nid]
    image = node["kind"] == "cvm.image"
    service, action, field, kind = (
        ("cvm", "DescribeImageSharePermission", "ImageId", "cvm.imageshare")
        if image
        else ("cbs", "DescribeSnapshotSharePermission", "SnapshotId", "cbs.snapshotshare")
    )
    source = f"{service}.{action}"

    def operation(record):
        response = runner.transport.call(
            service, action, region=node["region"], **{field: node["resource_id"]}
        )
        if response.get("RequestId"):
            record["request_ids"].append(response["RequestId"])
        if response.get(field) is not None and response[field] != node["resource_id"]:
            raise CollectionError("ShareResourceMismatch")
        rows = response.get("SharePermissionSet")
        if not isinstance(rows, list):
            raise CollectionError("InvalidSharePermissions")
        clean, seen = [], set()
        for row in rows:
            if not isinstance(row, dict):
                raise CollectionError("InvalidSharePermissions")
            account = row.get("AccountId")
            if not isinstance(account, str) or not re.fullmatch(r"[1-9][0-9]*", account):
                raise CollectionError("InvalidShareRecipient")
            if account in seen:
                raise CollectionError("DuplicateShareRecipient")
            seen.add(account)
            time = row.get("CreatedTime")
            if time is not None and not isinstance(time, str):
                raise CollectionError("InvalidShareTime")
            clean.append((account, time))
        for account, time in clean:
            sid = runner.graph.add(
                runner.account,
                node["region"],
                kind,
                node["resource_id"] + "/" + account,
                "Share to " + account,
                source=source,
            )
            runner.graph.nodes[sid]["properties"].update(
                recipient_account=account, access_verified=False
            )
            if time is not None:
                runner.graph.nodes[sid]["properties"]["CreatedTime"] = time
            target = runner.graph.add(
                account, "global", "cam.rootprincipal", account, source=source, status="reference"
            )
            runner.graph.edge(nid, sid, "HAS_SHARE", source)
            runner.graph.edge(sid, target, "SHARE_RECIPIENT", source)
        node["properties"].update(sharing_metadata_collected=True, share_count=len(clean))
        if "ShareReference" in node["properties"]:
            node["properties"]["sharing_changed_since_list"] = node["properties"][
                "ShareReference"
            ] != len(clean)
        node["sources"] = sorted(set(node["sources"] + [source]))
        record["count"] = len(clean)

    runner.scope(service, action, node["region"], operation, node["resource_id"])


def collect_owned(runner, spec, region):
    image = spec.kind == "cvm.image"
    filter_name, filter_value = (
        ("image-type", "PRIVATE_IMAGE") if image else ("snapshot-type", "PRIVATE_SNAPSHOT")
    )
    added = []

    def operation(record):
        seen = set()
        for rows, request_id in pages(
            runner.transport,
            replace(spec, require_total=True),
            region,
            {"Filters": [{"Name": filter_name, "Values": [filter_value]}]},
        ):
            if request_id:
                record["request_ids"].append(request_id)
            prepared = [properties(r, spec.kind) for r in rows]
            ids = [r[0] for r in prepared]
            if len(set(ids)) != len(ids) or seen.intersection(ids):
                raise CollectionError("DuplicateImageSnapshot")
            if any(not r[1]["owned_by_collected_account"] for r in prepared):
                raise CollectionError("ImageSnapshotOwnershipMismatch")
            seen.update(ids)
            for item in prepared:
                added.append(add(runner, spec, region, item))
                record["count"] += 1

    runner.scope(spec.service, spec.action, region, operation, "Owned resources only")
    for nid in added:
        collect_shares(runner, nid)


def collect_in_use(runner, services=None):
    # Run after native collectors so template/image references are available.
    # Images precede snapshots: owned in-use images can add backing references.
    for kind, spec in SPECS.items():
        if services and spec.service not in services:
            continue
        referenced = {
            e["target"]
            for e in runner.graph.edges.values()
            if e["relationship"] in {"USES_IMAGE", "USES_SNAPSHOT"}
        }
        candidates = [
            n
            for n in runner.graph.nodes.values()
            if n["account"] == runner.account
            and n["kind"] == kind
            and n["region"] in runner.regions_for(spec.service)
            and (
                n["status"] == "reference"
                or (n["status"] == "inventory-only" and n["id"] in referenced)
            )
        ]
        for node in candidates:

            def operation(record, node=node, spec=spec):
                field = spec.ids[0]
                source_id = identity(
                    node["resource_id"], "img" if spec.kind == "cvm.image" else "snap"
                )
                collected = []
                for rows, request_id in pages(
                    runner.transport,
                    replace(spec, require_total=True),
                    node["region"],
                    {field + "s": [source_id]},
                ):
                    if request_id:
                        record["request_ids"].append(request_id)
                    collected.extend(properties(r, spec.kind) for r in rows)
                if len(collected) != 1 or collected[0][0] != source_id:
                    raise CollectionError("InUseResourceUnavailable")
                add(runner, spec, node["region"], collected[0])
                record["count"] = 1

            scope = runner.scope(
                spec.service,
                spec.action,
                node["region"],
                operation,
                "In use: " + node["resource_id"],
            )
            if scope["status"] == "complete" and node["properties"].get(
                "owned_by_collected_account"
            ):
                collect_shares(runner, node["id"])
