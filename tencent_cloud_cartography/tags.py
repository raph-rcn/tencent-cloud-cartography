"""Account-scoped tag inventory and exact QCS-to-resource reconciliation."""

import json
import re
from collections import defaultdict

from .model import stable_id
from .transport import CollectionError

SOURCE = "tag.GetResources"
# Explicit Tag API resource prefixes, not names inferred from native API services.
# https://cloud.tencent.com/document/product/651/89122
RESOURCE_TYPES = {
    ("cvm", "instance"): "cvm.instance",
    ("cvm", "volume"): "cbs.disk",
    ("cvm", "snapshot"): "cbs.snapshot",
    ("cvm", "image"): "cvm.image",
    ("cvm", "keypair"): "cvm.keypair",
    ("vpc", "vpc"): "vpc.vpc",
    ("vpc", "subnet"): "vpc.subnet",
    ("vpc", "rtb"): "vpc.routetable",
    ("vpc", "eni"): "vpc.networkinterface",
    ("vpc", "sg"): "vpc.securitygroup",
    ("vpc", "eip"): "vpc.eip",
    ("vpc", "ccn"): "vpc.ccn",
    ("vpc", "pcx"): "vpc.peeringconnection",
    ("vpc", "nat"): "vpc.nat",
    ("vpc", "acl"): "vpc.networkacl",
    ("as", "auto-scaling-group"): "as.auto-scaling-group",
    ("apigw", "service"): "apigateway.service",
    ("emr", "emr-instance"): "emr.cluster",
    ("emr", "emr-vm"): "emr.node",
    ("tdmq", "cmqqueue"): "tdmq.cmqqueue",
    ("tdmq", "cmqtopic"): "tdmq.cmqtopic",
    ("eb", "eventbusid"): "eb.bus",
    ("cls", "topic"): "cls.topic",
    ("cls", "logset"): "cls.logset",
    ("cls", "alarm"): "cls.alarm",
    ("cls", "alarmNotice"): "cls.alarmnotice",
    ("monitor", "cm-policy"): "monitor.policy",
    ("privatedns", "zone"): "privatedns.zone",
    ("ssm", "secret"): "ssm.secret",
    ("ses", "senderdomain"): "ses.domain",
    ("es", "instance"): "es.instance",
    ("lighthouse", "instance"): "lighthouse.instance",
    ("cfs", "filesystem"): "cfs.filesystem",
    ("ckafka", "ckafkaId"): "ckafka.instance",
    ("clb", "clb"): "clb.clb",
    ("ssl", "certificate"): "ssl.certificate",
    ("cam", "uin"): "cam.user",
    ("cam", "role"): "cam.role",
    # These contracts are also documented in the international resource table
    # and TKE/CAM resource-level authorization references.
    ("tke", "cluster"): "tke.cluster",
    ("cdb", "instanceId"): "cdb.instance",
}
GLOBAL_TYPES = {
    "vpc.ccn",
    "ssl.certificate",
    "cam.user",
    "cam.role",
    "monitor.policy",
    "privatedns.zone",
}


def text(value, empty=False):
    if not isinstance(value, str) or (not value and not empty) or any(ord(c) < 32 for c in value):
        raise CollectionError("InvalidTagField")
    return value


def tag_pairs(rows):
    if not isinstance(rows, list):
        raise CollectionError("InvalidTagArray")
    result, keys = [], set()
    for row in rows:
        if not isinstance(row, dict):
            raise CollectionError("InvalidTagField")
        key, value = text(row.get("TagKey")), text(row.get("TagValue"), empty=True)
        if key in keys:
            raise CollectionError("DuplicateTagKey")
        keys.add(key)
        result.append({"TagKey": key, "TagValue": value})
    return sorted(result, key=lambda t: (t["TagKey"], t["TagValue"]))


def identity(qcs, account):
    qcs = text(qcs)
    match = re.fullmatch(r"qcs::([a-z0-9-]+):([^:]*):(uin|uid)/([0-9]+):(.+)", qcs)
    if not match or any(c in qcs for c in "*?"):
        raise CollectionError("InvalidTagResource")
    service, region, owner_type, owner, path = match.groups()
    if region and not re.fullmatch(r"[a-z]+-[a-z0-9-]+|global", region):
        raise CollectionError("InvalidTagRegion")
    if owner_type == "uid":
        # COS uses AppId. Only exact buckets already collected under this account
        # may resolve it. Never turn an AppId into an account UIN.
        if service != "cos" or not region:
            raise CollectionError("InvalidTagOwner")
        if path.startswith("prefix//"):
            parts = path[len("prefix//") :].split("/")
            if len(parts) != 2 or parts[0] != owner:
                raise CollectionError("InvalidTagBucket")
            bucket = parts[1] + "-" + owner
        elif path.startswith("prefix/"):
            bucket = path[len("prefix/") :] + "-" + owner
        else:
            bucket = path
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*-" + re.escape(owner), bucket):
            raise CollectionError("InvalidTagBucket")
        return {
            "target_kind": "cos.bucket",
            "target_id": bucket,
            "target_region": region,
            "owner_type": owner_type,
            "owner_id": owner,
            "resource_qcs": qcs,
        }
    if owner != account:
        raise CollectionError("TagAccountMismatch")
    prefix, separator, rid = path.partition("/")
    if not separator or not prefix or not rid:
        raise CollectionError("InvalidTagResource")
    kind = RESOURCE_TYPES.get((service, prefix), "")
    # Compound resource IDs remain intact. No suffix-only/name matching.
    return {
        "target_kind": kind,
        "target_id": rid,
        "target_region": region or ("global" if kind in GLOBAL_TYPES else "unknown"),
        "owner_type": owner_type,
        "owner_id": owner,
        "resource_qcs": qcs,
    }


def collect_tags(runner, max_pages=10000):
    def operation(record):
        token, tokens, resources = "", set(), set()
        record.update(scanned_count=0, out_of_scope_count=0)
        for _ in range(max_pages):
            response = runner.transport.call(
                "tag", "GetResources", region="global", PaginationToken=token, MaxResults=200
            )
            if response.get("RequestId"):
                record["request_ids"].append(response["RequestId"])
            rows = response.get("ResourceTagMappingList")
            if not isinstance(rows, list):
                raise CollectionError("InvalidTagResponse")
            for row in rows:
                if not isinstance(row, dict):
                    raise CollectionError("InvalidTagResponse")
                parsed = identity(row.get("Resource"), runner.account)
                pairs = tag_pairs(row.get("Tags"))
                qcs, region = parsed["resource_qcs"], parsed["target_region"]
                if qcs in resources:
                    raise CollectionError("DuplicateTagResource")
                resources.add(qcs)
                record["scanned_count"] += 1
                if region not in {*runner.regions, "global", "unknown"}:
                    record["out_of_scope_count"] += 1
                    continue
                nid = runner.graph.add(
                    runner.account,
                    region,
                    "tag.resource",
                    qcs,
                    parsed["target_id"],
                    source=SOURCE,
                    status="inventory-only",
                )
                runner.graph.nodes[nid]["properties"].update(
                    parsed,
                    tag_api_tags=json.dumps(pairs, ensure_ascii=False),
                    tag_resolution="unresolved",
                    metadata_only=True,
                )
                for tag in pairs:
                    key, value = tag["TagKey"], tag["TagValue"]
                    tid = runner.graph.add(
                        runner.account,
                        "global",
                        "tag.tag",
                        stable_id(key, value),
                        f"{key}={value}",
                        source=SOURCE,
                    )
                    runner.graph.nodes[tid]["properties"].update(
                        tag_key=key, tag_value=value, metadata_only=True
                    )
                    runner.graph.edge(nid, tid, "TAGGED", SOURCE)
                record["count"] += 1
            token = response.get("PaginationToken")
            if not isinstance(token, str):
                raise CollectionError("InvalidTagPaginationToken")
            if not token:
                return
            if token in tokens:
                raise CollectionError("PaginationStalled")
            tokens.add(token)
        raise CollectionError("PageLimit")

    runner.scope("tag", "GetResources", "global", operation)


def link_tags(graph):
    """Resolve exact collected identities; retain unknown bindings as inventory-only."""
    index, resolved = defaultdict(list), defaultdict(list)
    bindings = [n for n in graph.nodes.values() if n["kind"] == "tag.resource"]
    for node in graph.nodes.values():
        if node["kind"].startswith("tag.") or node["status"] == "reference":
            continue
        rid = node["resource_id"]
        if node["kind"] == "emr.node":
            rid = node["properties"].get("EmrResourceId")
            if not rid:
                continue
        index[node["account"], node["region"], node["kind"], rid].append(node)
    for binding in bindings:
        p = binding["properties"]
        matches = index.get(
            (binding["account"], p["target_region"], p["target_kind"], p["target_id"]), []
        )
        if len(matches) != 1:
            p["tag_resolution"] = "ambiguous" if matches else "unresolved"
            continue
        # A COS tag alone is insufficient ownership evidence for an AppId mapping.
        if p["owner_type"] == "uid" and matches[0]["status"] != "enriched":
            continue
        resolved[matches[0]["id"]].append(binding)
    replacements = {}
    for target, observations in resolved.items():
        if len({n["properties"]["tag_api_tags"] for n in observations}) != 1:
            for n in observations:
                n["properties"]["tag_resolution"] = "conflicting-observations"
            continue
        node = graph.nodes[target]
        node["properties"].update(
            tag_api_tags=observations[0]["properties"]["tag_api_tags"],
            tag_api_resources=json.dumps(sorted(n["resource_id"] for n in observations)),
            tag_resolution="exact-collected-identity",
        )
        node["sources"] = sorted(set(node["sources"] + [SOURCE]))
        for binding in observations:
            replacements[binding["id"]] = target
            del graph.nodes[binding["id"]]
    for eid, edge in list(graph.edges.items()):
        if edge["source"] in replacements:
            del graph.edges[eid]
            graph.edge(
                replacements[edge["source"]],
                edge["target"],
                edge["relationship"],
                edge["provenance"],
            )
