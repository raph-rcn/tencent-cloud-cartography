"""TDMQ for CMQ metadata, subscription routes and dead-letter configuration."""

import json
import re
from urllib.parse import urlsplit, urlunsplit

from .catalog import Collector
from .observability import retain, strings
from .transport import CollectionError

SUBSCRIPTIONS = Collector(
    "tdmq",
    "DescribeCmqSubscriptionDetail",
    "SubscriptionSet",
    "tdmq.cmqsubscription",
    ("SubscriptionResourceId",),
    ("SubscriptionName",),
    require_total=True,
    page_size=50,
)


def identity(value):
    if not isinstance(value, str) or not value or not re.fullmatch(r"[a-zA-Z0-9-]+", value):
        raise CollectionError("InvalidCmqIdentity")
    return value


def prepare(kind, raw, params, parent=None):
    if kind == "tdmq.cmqsubscription":
        if not parent or raw.get("TopicName") != params.get("TopicName"):
            raise CollectionError("CmqTopicMismatch")
        rid = identity(raw.get("SubscriptionId"))
        identity(raw.get("SubscriptionName"))
        return {
            **raw,
            "SubscriptionResourceId": f"{parent['resource_id']}/{rid}",
            "TopicId": parent["resource_id"],
        }
    field = "Queue" if kind == "tdmq.cmqqueue" else "Topic"
    identity(raw.get(field + "Id"))
    identity(raw.get(field + "Name"))
    return raw


def object_fields(raw, keys):
    if not isinstance(raw, dict):
        raise CollectionError("InvalidCmqConfiguration")
    props = {}
    retain(props, raw, keys)
    return props


def http_destination(value):
    if not isinstance(value, str) or any(ord(c) < 32 for c in value):
        raise CollectionError("InvalidCmqEndpoint")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise CollectionError("InvalidCmqEndpoint")
    # Store the origin only: webhook paths and queries can contain credentials.
    host = parsed.hostname
    host = f"[{host}]" if ":" in host else host
    port = parsed.port
    origin = urlunsplit((parsed.scheme, host + (f":{port}" if port else ""), "", "", ""))
    redacted = bool(
        parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    )
    return origin, redacted


def configuration(graph, nid, raw, source):
    node = graph.nodes[nid]
    props = node["properties"]
    kind = node["kind"]
    props["delivery_verified"] = False
    retain(
        props,
        raw,
        (
            "CreateTime",
            "LastModifyTime",
            "MsgCount",
            "Status",
            "Trace",
            "CreateUin",
            "TenantId",
            "NamespaceName",
        ),
    )
    if raw.get("Status") is not None:
        props["state"] = str(raw["Status"])
    if raw.get("Tags") is not None:
        if not isinstance(raw["Tags"], list):
            raise CollectionError("InvalidCmqTags")
        props["tags"] = json.dumps(
            [object_fields(t, ("TagKey", "TagValue")) for t in raw["Tags"]], sort_keys=True
        )
    if kind in {"tdmq.cmqqueue", "tdmq.cmqtopic"}:
        retain(props, raw, ("Qps", "Bps", "MsgRetentionSeconds", "MaxMsgSize"))
    if kind == "tdmq.cmqqueue":
        retain(
            props,
            raw,
            (
                "MaxDelaySeconds",
                "MaxMsgHeapNum",
                "PollingWaitSeconds",
                "VisibilityTimeout",
                "RewindSeconds",
                "ActiveMsgNum",
                "InactiveMsgNum",
                "DelayMsgNum",
                "RewindMsgNum",
                "MinMsgTime",
                "Transaction",
                "MaxUnackedMsgNum",
                "MaxMsgBacklogSize",
                "RetentionSizeInMB",
            ),
        )
        for field, keys in (
            ("DeadLetterPolicy", ("DeadLetterQueue", "Policy", "MaxTimeToLive", "MaxReceiveCount")),
            ("TransactionPolicy", ("FirstQueryInterval", "MaxQueryCount")),
        ):
            if field in raw:
                value = object_fields(raw[field], keys) if raw[field] is not None else {}
                if field == "DeadLetterPolicy":
                    state = "unavailable" if raw[field] is None else "disabled"
                    if value.get("DeadLetterQueue"):
                        identity(value["DeadLetterQueue"])
                        policy = value.get("Policy")
                        if type(policy) is not int or policy not in (0, 1):
                            raise CollectionError("InvalidCmqDeadLetterPolicy")
                        threshold = value.get("MaxReceiveCount" if policy == 0 else "MaxTimeToLive")
                        lower, upper = (1, 1000) if policy == 0 else (300, 43200)
                        if type(threshold) is not int or not lower <= threshold <= upper:
                            raise CollectionError("InvalidCmqDeadLetterThreshold")
                        state = "configured"
                    props["dead_letter_policy_state"] = state
                props[field] = json.dumps(value, sort_keys=True)
        if raw.get("DeadLetterSource") is not None:
            if not isinstance(raw["DeadLetterSource"], list):
                raise CollectionError("InvalidCmqDeadLetterSources")
            props["dead_letter_sources"] = json.dumps(
                [object_fields(s, ("QueueId", "QueueName")) for s in raw["DeadLetterSource"]],
                sort_keys=True,
            )
    elif kind == "tdmq.cmqtopic":
        retain(props, raw, ("FilterType", "BrokerType", "SubscriptionCount"))
    elif kind == "tdmq.cmqsubscription":
        retain(
            props,
            raw,
            (
                "TopicId",
                "TopicName",
                "SubscriptionId",
                "SubscriptionName",
                "TopicOwner",
                "Protocol",
                "NotifyStrategy",
                "NotifyContentFormat",
            ),
        )
        # TopicOwner is an AppId, not the account UIN. Preserve its meaning explicitly.
        if "TopicOwner" in props:
            props["owner_appid"] = props.pop("TopicOwner")
        for field in ("BindingKey", "FilterTags"):
            if raw.get(field) is not None:
                props[field] = json.dumps(strings(raw[field]))
        protocol = raw.get("Protocol")
        protocol = protocol.lower() if isinstance(protocol, str) else None
        if protocol == "queue":
            props["queue_name"] = identity(raw.get("Endpoint"))
        elif protocol in {"http", "https"}:
            origin, redacted = http_destination(raw.get("Endpoint"))
            props["endpoint_origin"] = origin
            props["endpoint_redacted"] = redacted
            endpoint = graph.add(
                node["account"],
                node["region"],
                "tdmq.httpendpoint",
                node["resource_id"] + "/endpoint",
                origin,
                source=source,
            )
            graph.nodes[endpoint]["properties"].update(
                origin=origin, endpoint_redacted=redacted, delivery_verified=False
            )
            graph.edge(nid, endpoint, "CONFIGURED_HTTP_DESTINATION", source)
        else:
            props["destination_resolution"] = "unsupported-protocol"


def collect_resource(runner, nid):
    node = runner.graph.nodes[nid]
    field = "Queue" if node["kind"] == "tdmq.cmqqueue" else "Topic"
    action = "DescribeCmq" + field + "Detail"

    def operation(record):
        response = runner.transport.call(
            "tdmq", action, region=node["region"], **{field + "Name": node["name"]}
        )
        if response.get("RequestId"):
            record["request_ids"].append(response["RequestId"])
        raw = response.get(field + "Describe")
        if (
            not isinstance(raw, dict)
            or raw.get(field + "Id") != node["resource_id"]
            or raw.get(field + "Name") != node["name"]
        ):
            raise CollectionError("CmqDetailIdentityMismatch")
        configuration(runner.graph, nid, raw, "tdmq." + action)
        node["properties"]["detail_collected"] = True
        record["count"] = 1

    runner.scope("tdmq", action, node["region"], operation, node["resource_id"])
    if field == "Topic":
        runner.native(
            SUBSCRIPTIONS,
            node["region"],
            {"TopicName": node["name"], "QueryType": "topic"},
            nid,
            "HAS_SUBSCRIPTION",
        )
        record = runner.graph.coverage[-1]
        expected = node["properties"].get("SubscriptionCount")
        if (
            type(expected) is int
            and expected >= 0
            and record["status"] in {"complete", "empty"}
            and record["count"] != expected
        ):
            record.update(status="error", error="CmqSubscriptionCountChanged")


def link_destinations(graph):
    queues = [
        n
        for n in graph.nodes.values()
        if n["kind"] == "tdmq.cmqqueue" and n["status"] == "enriched"
    ]

    def candidates(node, name, rid=None):
        return [
            q
            for q in queues
            if q["account"] == node["account"]
            and q["region"] == node["region"]
            and (not name or q["name"] == name)
            and (not rid or q["resource_id"] == rid)
        ]

    for node in list(graph.nodes.values()):
        props = node["properties"]
        if node["kind"] == "tdmq.cmqsubscription" and props.get("queue_name"):
            matches = candidates(node, props["queue_name"])
            props["destination_resolution"] = (
                "resolved" if len(matches) == 1 else "unresolved-or-ambiguous"
            )
            if len(matches) == 1:
                graph.edge(
                    node["id"],
                    matches[0]["id"],
                    "CONFIGURED_QUEUE_DESTINATION",
                    "CMQ subscription + collected queue",
                )
        elif node["kind"] == "tdmq.cmqqueue":
            policy = json.loads(props.get("DeadLetterPolicy", "{}"))
            if policy.get("DeadLetterQueue"):
                matches = candidates(node, policy["DeadLetterQueue"])
                matches = [q for q in matches if q["id"] != node["id"]]
                props["dead_letter_resolution"] = (
                    "resolved" if len(matches) == 1 else "unresolved-or-ambiguous"
                )
                if len(matches) == 1:
                    graph.edge(
                        node["id"],
                        matches[0]["id"],
                        "HAS_DEADLETTER_QUEUE",
                        "CMQ dead-letter policy + collected queue",
                    )
            unresolved = 0
            for source in json.loads(props.get("dead_letter_sources", "[]")):
                if not source.get("QueueName") and not source.get("QueueId"):
                    unresolved += 1
                    continue
                matches = candidates(node, source.get("QueueName"), source.get("QueueId"))
                if len(matches) != 1 or matches[0]["id"] == node["id"]:
                    unresolved += 1
                    continue
                other = matches[0]
                forward = json.loads(other["properties"].get("DeadLetterPolicy", "{}"))
                if other["properties"].get("dead_letter_policy_state") == "disabled" or (
                    forward.get("DeadLetterQueue") and forward["DeadLetterQueue"] != node["name"]
                ):
                    unresolved += 1
                    continue
                graph.edge(
                    other["id"],
                    node["id"],
                    "HAS_DEADLETTER_QUEUE",
                    "CMQ dead-letter source metadata",
                )
            if "dead_letter_sources" in props:
                props["unresolved_dead_letter_sources"] = unresolved
