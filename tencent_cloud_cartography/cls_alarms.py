"""CLS alarm query, schedule and notification configuration. No logs or callback bodies."""

import json
import re

from .observability import retain, string, strings
from .transport import CollectionError


def identity(value, kind):
    prefix = "alarm" if kind == "cls.alarm" else "notice"
    if not isinstance(value, str) or not re.fullmatch(prefix + r"-[a-zA-Z0-9-]+", value):
        raise CollectionError("InvalidClsAlarmIdentity")
    return value


def obj(value):
    if not isinstance(value, dict):
        raise CollectionError("InvalidClsAlarmConfiguration")
    return value


def array(value):
    if value is None:
        return []
    if not isinstance(value, list):
        raise CollectionError("InvalidClsAlarmConfiguration")
    return value


def clean(raw, fields):
    result = {}
    retain(result, obj(raw), fields)
    return result


def encoded(value):
    return json.dumps(value, sort_keys=True, allow_nan=False)


def recipients(raw):
    selected = []
    for recipient in array(raw):
        item = clean(
            recipient, ("ReceiverType", "NoticeContentId", "StartTime", "EndTime", "Index")
        )
        item["ReceiverChannels"] = strings(recipient.get("ReceiverChannels") or [])
        item["receiver_count"] = len(array(recipient.get("ReceiverIds")))
        selected.append(item)
    return selected


def callbacks(raw):
    return [
        clean(
            item,
            ("CallbackType", "WebCallbackId", "Method", "NoticeContentId", "RemindType", "Index"),
        )
        for item in array(raw)
    ]


def notice_config(raw, depth=0):
    if depth > 5:
        raise CollectionError("InvalidEscalationDepth")
    selected = clean(raw, ("Rule", "Escalate", "Type", "Interval"))
    selected["NoticeReceivers"] = recipients(raw.get("NoticeReceivers"))
    selected["WebCallbacks"] = callbacks(raw.get("WebCallbacks"))
    if raw.get("EscalateNotice") is not None:
        selected["EscalateNotice"] = notice_config(raw["EscalateNotice"], depth + 1)
    return selected


def reference(graph, node, kind, rid, source, region=None, name=None):
    return graph.add(
        node["account"],
        region or node["region"],
        kind,
        string(rid),
        name,
        source=source,
        status="reference",
    )


def configuration(graph, nid, raw, source):
    node = graph.nodes[nid]
    if node["kind"] == "cls.alarmnotice":
        return notice(graph, nid, raw, source)
    props = node["properties"]
    retain(
        props,
        raw,
        (
            "Status",
            "Condition",
            "TriggerCount",
            "AlarmPeriod",
            "CreateTime",
            "UpdateTime",
            "GroupTriggerStatus",
            "MonitorObjectType",
            "AlarmLevel",
        ),
    )
    props["evaluation_verified"] = False
    if raw.get("MonitorTime") is not None:
        props["schedule"] = encoded(clean(raw["MonitorTime"], ("Type", "Time", "CronExpression")))
    if raw.get("GroupTriggerCondition") is not None:
        props["group_trigger_conditions"] = encoded(strings(raw["GroupTriggerCondition"]))
    if raw.get("MultiConditions") is not None:
        props["multi_conditions"] = encoded(
            [clean(item, ("Condition", "AlarmLevel")) for item in array(raw["MultiConditions"])]
        )
    if raw.get("Classifications") is not None:
        props["classifications"] = encoded(
            [clean(item, ("Key", "Value")) for item in array(raw["Classifications"])]
        )
    numbers = set()
    for query in array(raw.get("AlarmTargets")):
        obj(query)
        number = query.get("Number")
        if type(number) is not int or number < 1 or number in numbers:
            raise CollectionError("InvalidClsAlarmQueryNumber")
        numbers.add(number)
        topic_id = string(query.get("TopicId"))
        query_config = clean(
            query,
            (
                "Query",
                "Number",
                "StartTimeOffset",
                "EndTimeOffset",
                "SyntaxRule",
                "BizType",
                "LogsetId",
                "TopicId",
            ),
        )
        qid = graph.add(
            node["account"],
            node["region"],
            "cls.alarmquery",
            f"{node['resource_id']}/{number}",
            f"Query {number} · {query.get('TopicName') or topic_id}",
            source=source,
        )
        graph.nodes[qid]["properties"].update(
            configuration=encoded(query_config), execution_verified=False
        )
        graph.edge(nid, qid, "HAS_ALARM_QUERY", source)
        target = reference(graph, node, "cls.topic", topic_id, source, name=query.get("TopicName"))
        graph.edge(qid, target, "QUERIES_TOPIC", source)
        if query.get("LogsetId"):
            logset = reference(
                graph, node, "cls.logset", query["LogsetId"], source, name=query.get("LogsetName")
            )
            graph.edge(logset, target, "HAS_TOPIC", source)
    for notice_id in strings(raw.get("AlarmNoticeIds") or []):
        identity(notice_id, "cls.alarmnotice")
        target = reference(graph, node, "cls.alarmnotice", notice_id, source)
        graph.edge(nid, target, "USES_ALARM_NOTICE", source)
    monitor = raw.get("MonitorNotice")
    if monitor is not None:
        bindings = []
        for rule in array(obj(monitor).get("Notices")):
            selected = clean(rule, ("NoticeId", "ContentTmplId"))
            levels = array(rule.get("AlarmLevels"))
            if any(type(level) is not int or level not in (0, 1, 2) for level in levels):
                raise CollectionError("InvalidClsAlarmLevel")
            selected["AlarmLevels"] = levels
            target = reference(
                graph, node, "monitor.notice", selected.get("NoticeId"), source, region="global"
            )
            graph.edge(nid, target, "USES_ALARM_NOTICE", source)
            bindings.append(selected)
        props["monitor_notice_bindings"] = encoded(bindings)


def notice(graph, nid, raw, source):
    node = graph.nodes[nid]
    props = node["properties"]
    retain(
        props,
        raw,
        (
            "Type",
            "AlarmShieldStatus",
            "SecureDetailStatus",
            "CreateTime",
            "UpdateTime",
            "DeliverStatus",
            "DeliverFlag",
            "CallbackPrioritize",
        ),
    )
    props["delivery_verified"] = False
    props["receivers"] = encoded(recipients(raw.get("NoticeReceivers")))
    props["callbacks"] = encoded(callbacks(raw.get("WebCallbacks")))
    for index, rule in enumerate(array(raw.get("NoticeRules"))):
        config = encoded(notice_config(rule))
        child = graph.add(
            node["account"],
            node["region"],
            "cls.noticerule",
            f"{node['resource_id']}/{index}",
            f"Notification rule {index + 1}",
            source=source,
        )
        graph.nodes[child]["properties"]["configuration"] = config
        graph.edge(nid, child, "HAS_NOTICE_RULE", source)
    delivery = raw.get("AlarmNoticeDeliverConfig")
    if delivery is not None and obj(delivery).get("DeliverConfig") is not None:
        config = clean(delivery["DeliverConfig"], ("Region", "TopicId", "Scope"))
        props["log_delivery_configuration"] = encoded(config)
        # Empty structures are returned when no delivery is configured.
        if config.get("TopicId"):
            region = config.get("Region")
            if not isinstance(region, str) or not re.fullmatch(r"[a-z]+-[a-z0-9-]+", region):
                raise CollectionError("InvalidClsDeliveryRegion")
            target = reference(graph, node, "cls.topic", config["TopicId"], source, region=region)
            graph.edge(nid, target, "CONFIGURED_LOG_DESTINATION", source)
