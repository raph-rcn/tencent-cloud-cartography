"""Audit/log delivery configuration and relationships, never event or log contents."""

import json
import re

from .kms import KEY_ID
from .transport import CollectionError


def string(value):
    if not isinstance(value, str) or not value or any(ord(c) < 32 for c in value):
        raise CollectionError("InvalidObservabilityIdentity")
    return value


def strings(value):
    if not isinstance(value, list) or not all(isinstance(s, str) for s in value):
        raise CollectionError("InvalidResponse")
    return value


def retain(props, raw, keys):
    props.update({k: raw[k] for k in keys if type(raw.get(k)) in (str, int, bool)})


def configuration(graph, nid, raw, source):
    node = graph.nodes[nid]
    props = node["properties"]
    kind = node["kind"]
    if kind == "cloudaudit.track":
        retain(
            props, raw, ("ActionType", "ResourceType", "Status", "CreateTime", "TrackForAllMembers")
        )
        if "EventNames" in raw:
            props["EventNames"] = json.dumps(strings(raw["EventNames"]))
        storage = raw.get("Storage")
        if storage is not None:
            if not isinstance(storage, dict):
                raise CollectionError("InvalidResponse")
            clean = {}
            retain(
                clean,
                storage,
                (
                    "StorageType",
                    "StorageRegion",
                    "StorageName",
                    "StoragePrefix",
                    "StorageAccountId",
                    "StorageAppId",
                    "Compress",
                ),
            )
            for key in ("StorageType", "StorageRegion", "StorageName"):
                string(clean.get(key))
            props["storage_configuration"] = json.dumps(clean, sort_keys=True)
        filters = raw.get("Filters")
        if filters is not None:
            if not isinstance(filters, dict) or not isinstance(filters.get("ResourceFields"), list):
                raise CollectionError("InvalidResponse")
            selected = []
            for f in filters["ResourceFields"]:
                selected.append(
                    dict(
                        ResourceType=string(f.get("ResourceType")),
                        ActionType=string(f.get("ActionType")),
                        EventNames=strings(f.get("EventNames")),
                    )
                )
            props["event_filters"] = json.dumps(selected, sort_keys=True)
    elif kind == "cls.logset":
        retain(props, raw, ("CreateTime", "TopicCount", "MetricTopicCount", "RoleName"))
    elif kind == "cls.topic":
        retain(
            props,
            raw,
            (
                "CreateTime",
                "PartitionCount",
                "Index",
                "Status",
                "AutoSplit",
                "MaxSplitPartitions",
                "StorageType",
                "Period",
                "HotPeriod",
                "BizType",
                "IsWebTracking",
                "BillingMode",
                "NewBillingMode",
                "RoleName",
            ),
        )
        if raw.get("LogsetId"):
            target = graph.add(
                node["account"],
                node["region"],
                "cls.logset",
                string(raw["LogsetId"]),
                status="reference",
                source=source,
            )
            graph.edge(target, nid, "HAS_TOPIC", source)
        config = raw.get("CustomKmsInfo")
        if config is not None:
            if not isinstance(config, dict):
                raise CollectionError("InvalidResponse")
            clean = {}
            retain(clean, config, ("KmsRegion", "KmsKeyId"))
            props["kms_configuration"] = json.dumps(clean, sort_keys=True)
            region, key = clean.get("KmsRegion", ""), clean.get("KmsKeyId", "")
            if re.fullmatch(r"[a-z]+-[a-z0-9-]+", region) and KEY_ID.fullmatch(key):
                target = graph.add(
                    node["account"], region, "kms.key", key, status="reference", source=source
                )
                graph.edge(nid, target, "CONFIGURED_ENCRYPTION_KEY", source)
    elif kind == "cls.shipper":
        retain(
            props,
            raw,
            (
                "TopicId",
                "Bucket",
                "Prefix",
                "Interval",
                "MaxSize",
                "Status",
                "CreateTime",
                "FilenameMode",
                "StorageType",
                "RoleArn",
                "TaskStatus",
                "TimeZone",
            ),
        )
        target = graph.add(
            node["account"],
            node["region"],
            "cls.topic",
            string(raw.get("TopicId")),
            status="reference",
            source=source,
        )
        graph.edge(target, nid, "HAS_SHIPPER", source)
    props["delivery_verified"] = False


def collect_track_details(runner, collected):
    for nid, listed in collected:
        node = runner.graph.nodes[nid]

        def operation(record, node=node, listed=listed):
            data = runner.transport.call(
                "cloudaudit", "DescribeAuditTrack", node["region"], TrackId=int(node["resource_id"])
            )
            if data.get("RequestId"):
                record["request_ids"].append(data["RequestId"])
            # This detail API does not echo TrackId. Detect contradictory list/detail names.
            if not isinstance(data.get("Name"), str) or data["Name"] != listed.get("Name"):
                raise CollectionError("AuditTrackChanged")
            configuration(runner.graph, node["id"], data, "cloudaudit.DescribeAuditTrack")
            node["properties"]["detail_collected"] = True
            record["count"] = 1

        runner.scope(
            "cloudaudit", "DescribeAuditTrack", node["region"], operation, node["resource_id"]
        )


def link_destinations(graph):
    collected = [n for n in graph.nodes.values() if n["status"] == "enriched"]
    buckets = [n for n in collected if n["kind"] == "cos.bucket"]
    for node in list(graph.nodes.values()):
        props = node["properties"]
        candidates = []
        source = "configured log delivery"
        if node["kind"] == "cloudaudit.track" and "storage_configuration" in props:
            config = json.loads(props["storage_configuration"])
            name, region = config["StorageName"], config["StorageRegion"]
            owner = config.get("StorageAccountId") or node["account"]
            if not isinstance(owner, str) or not owner.isdigit():
                props["destination_resolution"] = "invalid-account"
                continue
            if config["StorageType"] == "cos":
                # StorageName omits AppId. Resolve only a unique collected bucket;
                # StorageAppId is a suffix constraint, never an account UIN.
                appid = config.get("StorageAppId")
                candidates = [
                    n["id"]
                    for n in buckets
                    if n["account"] == owner
                    and n["region"] == region
                    and n["resource_id"].rsplit("-", 1)[0] == name
                    and (not appid or n["resource_id"].rsplit("-", 1)[-1] == appid)
                ]
            elif config["StorageType"] == "cls":
                candidates = [
                    graph.add(owner, region, "cls.topic", name, status="reference", source=source)
                ]
            elif config["StorageType"] == "ckafka":
                instance, sep, topic = name.partition("/")
                if sep and instance.startswith("ckafka-") and topic:
                    # Topic names are not topic IDs. Require a matching collected child.
                    candidates = [
                        n["id"]
                        for n in collected
                        if n["kind"] == "ckafka.topic"
                        and n["account"] == owner
                        and n["region"] == region
                        and n["name"] == topic
                        and any(
                            e["target"] == n["id"]
                            and graph.nodes[e["source"]]["resource_id"] == instance
                            and e["relationship"] in {"HAS_TOPIC", "CONTAINS"}
                            and graph.nodes[e["source"]]["kind"] == "ckafka.instance"
                            and graph.nodes[e["source"]]["account"] == owner
                            and graph.nodes[e["source"]]["region"] == region
                            and graph.nodes[e["source"]]["status"] == "enriched"
                            for e in graph.edges.values()
                        )
                    ]
            else:
                props["destination_resolution"] = "unsupported-type"
                continue
        elif node["kind"] == "cls.shipper" and props.get("Bucket"):
            # Full bucket names are globally unique; use the collected bucket's
            # actual owner/region rather than copying the CLS topic's placement.
            candidates = [n["id"] for n in buckets if n["resource_id"] == props["Bucket"]]
        else:
            continue
        props["destination_resolution"] = (
            "resolved" if len(candidates) == 1 else "ambiguous" if candidates else "unresolved"
        )
        if len(candidates) == 1:
            if graph.nodes[candidates[0]]["status"] != "enriched":
                props["destination_resolution"] = "reference"
            graph.edge(node["id"], candidates[0], "CONFIGURED_LOG_DESTINATION", source)
