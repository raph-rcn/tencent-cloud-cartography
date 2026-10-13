"""EventBridge buses, rules and target configuration; no events or connection secrets."""

import json
import re

from .catalog import Collector
from .observability import retain
from .transport import CollectionError

RULES = Collector(
    "eb", "ListRules", "Rules", "eb.rule", ("RuleResourceId",), ("RuleName",), require_total=True
)
TARGETS = Collector(
    "eb",
    "ListTargets",
    "Targets",
    "eb.target",
    ("TargetResourceId",),
    ("TargetId",),
    require_total=True,
)


def identity(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9_-]+", value):
        raise CollectionError("InvalidEventBridgeIdentity")
    return value


def prepare(kind, raw, params):
    bus = identity(raw.get("EventBusId"))
    if kind == "eb.bus":
        return raw
    if bus != params.get("EventBusId"):
        raise CollectionError("EventBridgeBusMismatch")
    rule = identity(raw.get("RuleId"))
    if kind == "eb.rule":
        return {**raw, "RuleResourceId": f"{bus}/{rule}"}
    if rule != params.get("RuleId"):
        raise CollectionError("EventBridgeRuleMismatch")
    target = identity(raw.get("TargetId"))
    return {**raw, "TargetResourceId": f"{bus}/{rule}/{target}"}


def selected(raw, keys):
    if not isinstance(raw, dict):
        raise CollectionError("InvalidEventBridgeConfiguration")
    result = {}
    retain(result, raw, keys)
    return result


def configuration(graph, nid, raw, source):
    node = graph.nodes[nid]
    props = node["properties"]
    props["delivery_verified"] = False
    retain(
        props,
        raw,
        (
            "EventBusId",
            "RuleId",
            "TargetId",
            "Description",
            "AddTime",
            "ModTime",
            "Enable",
            "Status",
            "Type",
            "PayMode",
        ),
    )
    if "Enable" in raw and raw["Enable"] is not None and type(raw["Enable"]) is not bool:
        raise CollectionError("InvalidEventBridgeEnable")
    if raw.get("Status"):
        props["state"] = raw["Status"]
    if node["kind"] == "eb.bus":
        retain(
            props,
            raw,
            ("SaveDays", "EnableStore", "LinkMode", "LogTopicId", "ClsTopicId", "ClsLogsetId"),
        )
        # Safe summaries have no connection IDs; do not invent resource identities.
        if raw.get("ConnectionBriefs") is not None:
            if not isinstance(raw["ConnectionBriefs"], list):
                raise CollectionError("InvalidEventBridgeConnections")
            props["connection_summaries"] = json.dumps(
                [selected(c, ("Type", "Status")) for c in raw["ConnectionBriefs"]], sort_keys=True
            )
        for field, kind, relation in (
            ("ClsTopicId", "cls.topic", "CONFIGURED_LOG_TOPIC"),
            ("ClsLogsetId", "cls.logset", "CONFIGURED_LOGSET"),
        ):
            if raw.get(field):
                other = graph.add(
                    node["account"],
                    node["region"],
                    kind,
                    identity(raw[field]),
                    status="reference",
                    source=source,
                )
                graph.edge(nid, other, relation, source)
    elif node["kind"] == "eb.rule":
        if raw.get("EventPattern") is not None:
            pattern = raw["EventPattern"]
            if not isinstance(pattern, str) or len(pattern) > 262144:
                raise CollectionError("InvalidEventBridgePattern")
            try:
                parsed = json.loads(pattern)
                json.dumps(parsed, allow_nan=False)
            except (ValueError, RecursionError) as exc:
                raise CollectionError("InvalidEventBridgePattern") from exc
            if not isinstance(parsed, dict):
                raise CollectionError("InvalidEventBridgePattern")
            props["EventPattern"] = pattern
        if raw.get("DeadLetterConfig") is not None:
            config = selected(raw["DeadLetterConfig"], ("DisposeMethod",))
            if config.get("DisposeMethod") not in {"DLQ", "DROP", "IGNORE_ERROR"}:
                raise CollectionError("InvalidEventBridgeDisposeMethod")
            if config["DisposeMethod"] == "DLQ":
                config["CkafkaDeliveryParams"] = selected(
                    raw["DeadLetterConfig"].get("CkafkaDeliveryParams"),
                    ("TopicName", "ResourceDescription"),
                )
                if not all(
                    config["CkafkaDeliveryParams"].get(k)
                    for k in ("TopicName", "ResourceDescription")
                ):
                    raise CollectionError("InvalidEventBridgeDeadLetter")
            props["DeadLetterConfig"] = json.dumps(config, sort_keys=True)
    elif node["kind"] == "eb.target":
        retain(props, raw, ("EnableBatchDelivery", "BatchTimeout", "BatchEventCount"))
        desc = raw.get("TargetDescription")
        if not isinstance(desc, dict) or not isinstance(desc.get("ResourceDescription"), str):
            raise CollectionError("InvalidEventBridgeTarget")
        props["ResourceDescription"] = desc["ResourceDescription"]
        for field, keys in (
            ("SCFParams", ("BatchTimeout", "BatchEventCount", "EnableBatchDelivery")),
            ("CkafkaTargetParams", ("TopicName", "EventDeliveryFormat")),
            (
                "ESTargetParams",
                (
                    "NetMode",
                    "IndexPrefix",
                    "RotationInterval",
                    "OutputMode",
                    "IndexSuffixMode",
                    "IndexTemplateType",
                ),
            ),
        ):
            if desc.get(field) is not None:
                config = selected(desc[field], keys)
                if field == "CkafkaTargetParams" and desc[field].get("RetryPolicy") is not None:
                    config["RetryPolicy"] = selected(
                        desc[field]["RetryPolicy"], ("RetryInterval", "MaxRetryAttempts")
                    )
                props[field] = json.dumps(config, sort_keys=True)


def collect_bus(runner, nid):
    bus = runner.graph.nodes[nid]

    def bus_detail(record):
        response = runner.transport.call(
            "eb", "GetEventBus", region=bus["region"], EventBusId=bus["resource_id"]
        )
        if response.get("RequestId"):
            record["request_ids"].append(response["RequestId"])
        if response.get("EventBusId") != bus["resource_id"]:
            raise CollectionError("EventBridgeBusMismatch")
        configuration(runner.graph, nid, response, "eb.GetEventBus")
        bus["properties"]["detail_collected"] = True
        record["count"] = 1

    runner.scope("eb", "GetEventBus", bus["region"], bus_detail, bus["resource_id"])
    rules = runner.native(RULES, bus["region"], {"EventBusId": bus["resource_id"]}, nid, "HAS_RULE")
    for rid, raw in rules:
        params = dict(EventBusId=bus["resource_id"], RuleId=raw["RuleId"])

        def rule_detail(record, rid=rid, params=params):
            response = runner.transport.call("eb", "GetRule", region=bus["region"], **params)
            if response.get("RequestId"):
                record["request_ids"].append(response["RequestId"])
            if any(response.get(k) != v for k, v in params.items()):
                raise CollectionError("EventBridgeRuleMismatch")
            configuration(runner.graph, rid, response, "eb.GetRule")
            runner.graph.nodes[rid]["properties"]["detail_collected"] = True
            record["count"] = 1

        runner.scope(
            "eb", "GetRule", bus["region"], rule_detail, json.dumps(params, sort_keys=True)
        )
        runner.native(TARGETS, bus["region"], params, rid, "HAS_TARGET")


def parse_qcs(value):
    if not isinstance(value, str):
        return None
    match = re.fullmatch(
        r"qcs::([a-z0-9-]+):([a-z]+-[a-z0-9-]+):(?:appid/[0-9]+/)?uin/([0-9]+):(.+)", value
    )
    return match.groups() if match else None


def link_targets(graph):
    def resolve(node, resource, expected, topic=None):
        parsed = parse_qcs(resource)
        if not parsed:
            return [], "unsupported-resource-format"
        service, region, owner, path = parsed
        if service != expected:
            return [], "resource-type-mismatch"
        source = "EventBridge configured resource"
        if service in {"cls", "es"}:
            match = re.fullmatch(
                r"topic/([a-zA-Z0-9_-]+)" if service == "cls" else r"instance/(es-[a-zA-Z0-9-]+)",
                path,
            )
            if match:
                kind = "cls.topic" if service == "cls" else "es.instance"
                return [
                    graph.add(owner, region, kind, match[1], source=source, status="reference")
                ], "explicit-reference"
        elif service == "ckafka":
            match = re.fullmatch(r"ckafkaId/uin/([0-9]+)/(ckafka-[a-zA-Z0-9-]+)", path)
            if match and match[1] != owner:
                return [], "conflicting-owner"
            if match and isinstance(topic, str) and topic:
                parents = {
                    n["id"]
                    for n in graph.nodes.values()
                    if n["kind"] == "ckafka.instance"
                    and n["account"] == owner
                    and n["region"] == region
                    and n["resource_id"] == match[2]
                    and n["status"] == "enriched"
                }
                candidates = [
                    n["id"]
                    for n in graph.nodes.values()
                    if n["kind"] == "ckafka.topic"
                    and n["account"] == owner
                    and n["region"] == region
                    and n["name"] == topic
                    and n["status"] == "enriched"
                    and any(
                        e["source"] in parents
                        and e["target"] == n["id"]
                        and e["relationship"] == "HAS_TOPIC"
                        for e in graph.edges.values()
                    )
                ]
                return (
                    (candidates, "resolved")
                    if len(candidates) == 1
                    else ([], "unresolved-or-ambiguous")
                )
        elif service == "scf":
            match = re.fullmatch(r"namespace/([^/]+)/function/([^/]+)(?:/([^/]+))?", path)
            if match:
                functions = [
                    n
                    for n in graph.nodes.values()
                    if n["kind"] == "scf.function"
                    and n["account"] == owner
                    and n["region"] == region
                    and n["properties"].get("Namespace") == match[1]
                    and n["name"] == match[2]
                    and n["status"] == "enriched"
                ]
                if len(functions) != 1:
                    return [], "unresolved-or-ambiguous"
                fn = functions[0]
                if match[3]:
                    qualifier = match[3]
                    kind = (
                        "scf.version"
                        if qualifier == "$LATEST" or qualifier.isdigit()
                        else "scf.alias"
                    )
                    target = graph.add(
                        owner,
                        region,
                        kind,
                        fn["resource_id"] + "/" + qualifier,
                        fn["name"] + ":" + qualifier,
                        status="reference",
                        source=source,
                    )
                    graph.edge(
                        fn["id"],
                        target,
                        "HAS_VERSION" if kind == "scf.version" else "HAS_ALIAS",
                        source,
                    )
                    return [target], "explicit-qualifier"
                return [fn["id"]], "resolved"
        return [], "unsupported-resource-format"

    for node in list(graph.nodes.values()):
        props = node["properties"]
        if node["kind"] == "eb.target":
            topic = json.loads(props.get("CkafkaTargetParams", "{}")).get("TopicName")
            matches, status = resolve(
                node, props.get("ResourceDescription"), props.get("Type"), topic
            )
            props["target_resolution"] = status
            for target in matches:
                graph.edge(
                    node["id"],
                    target,
                    "CONFIGURED_EVENT_TARGET",
                    "EventBridge target configuration",
                )
        elif node["kind"] == "eb.rule" and "DeadLetterConfig" in props:
            config = json.loads(props["DeadLetterConfig"])
            if config["DisposeMethod"] == "DLQ":
                params = config["CkafkaDeliveryParams"]
                matches, status = resolve(
                    node, params["ResourceDescription"], "ckafka", params["TopicName"]
                )
                props["dead_letter_resolution"] = status
                for target in matches:
                    graph.edge(
                        node["id"],
                        target,
                        "CONFIGURED_DEADLETTER_TOPIC",
                        "EventBridge dead-letter configuration",
                    )
