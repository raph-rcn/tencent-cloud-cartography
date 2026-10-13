"""Cloud Monitor configuration, never metric samples, alert history or callback secrets."""

import json
import re
from types import SimpleNamespace

from .catalog import Collector
from .observability import retain, string, strings
from .transport import CollectionError, pages

# Official instance-dimension abbreviations: product/248/50863. Unknown aliases
# remain unresolved; never guess a region from the policy's multi-region list.
REGIONS = {
    "gz": "ap-guangzhou",
    "sh": "ap-shanghai",
    "bj": "ap-beijing",
    "cd": "ap-chengdu",
    "nj": "ap-nanjing",
    "cq": "ap-chongqing",
    "hk": "ap-hongkong",
    "sg": "ap-singapore",
    "kr": "ap-seoul",
    "usw": "na-siliconvalley",
    "de": "eu-frankfurt",
    "in": "ap-mumbai",
    "use": "na-ashburn",
    "th": "ap-bangkok",
    "jp": "ap-tokyo",
    "szjr": "ap-shenzhen-fsi",
    "shjr": "ap-shanghai-fsi",
    "bjjr": "ap-beijing-fsi",
}
BINDINGS = Collector(
    "monitor",
    "DescribeBindingPolicyObjectList",
    "List",
    "monitor.binding",
    ("UniqueId",),
    total="Total",
    regional=False,
    require_total=True,
)
RULE_FIELDS = (
    "MetricName",
    "Period",
    "Operator",
    "Value",
    "ContinuePeriod",
    "NoticeFrequency",
    "IsPowerNotice",
    "Description",
    "Unit",
    "RuleType",
    "IsAdvanced",
    "IsOpen",
    "ProductId",
    "IsLatenessMetric",
)


def policy_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"policy-[a-zA-Z0-9-]+", value):
        raise CollectionError("InvalidAlarmPolicyId")
    return value


def object_value(value):
    if not isinstance(value, dict):
        raise CollectionError("InvalidResponse")
    return value


def array(value):
    if value is None:
        return []
    if not isinstance(value, list):
        raise CollectionError("InvalidResponse")
    return value


def encoded(value):
    return json.dumps(value, sort_keys=True, allow_nan=False)


def selected(raw, keys):
    clean = {}
    retain(clean, object_value(raw), keys)
    return clean


def dimensions(value):
    def unique(pairs):
        result = {}
        for k, v in pairs:
            if k in result:
                raise CollectionError("AmbiguousAlarmDimensions")
            result[k] = v
        return result

    if not isinstance(value, str):
        raise CollectionError("InvalidAlarmDimensions")
    parsed = json.loads(value, object_pairs_hook=unique)
    if not isinstance(parsed, dict) or not all(
        isinstance(k, str) and type(v) in (str, int, bool) for k, v in parsed.items()
    ):
        raise CollectionError("InvalidAlarmDimensions")
    return parsed


def configuration(graph, nid, raw, source):
    node = graph.nodes[nid]
    props = node["properties"]
    retain(
        props,
        raw,
        (
            "Remark",
            "MonitorType",
            "Enable",
            "UseSum",
            "ProjectId",
            "ProjectName",
            "Namespace",
            "ConditionTemplateId",
            "UpdateTime",
            "InsertTime",
            "IsDefault",
            "InstanceGroupId",
            "InstanceSum",
            "InstanceGroupName",
            "RuleType",
            "OriginId",
            "IsOneClick",
            "OneClickStatus",
            "IsBindAll",
            "TagOperation",
            "FilterDimensionsParam",
        ),
    )
    props["evaluation_verified"] = False
    if raw.get("Region") is not None:
        props["configured_regions"] = encoded(strings(raw["Region"]))
    if raw.get("Filter") is not None:
        props["filter_configuration"] = encoded(
            selected(raw["Filter"], ("Type", "Expression", "Dimensions"))
        )
    for key in ("GroupBy", "TagInstances"):
        # TagInstance has a different shape; only persist its selected metadata.
        fields = ("Id", "Name") if key == "GroupBy" else ("Key", "Value", "RegionId")
        if raw.get(key) is not None:
            props[key] = encoded([selected(v, fields) for v in array(raw[key])])
    for condition, category in (("Condition", "metric"), ("EventCondition", "event")):
        data = raw.get(condition)
        if data is None:
            continue
        object_value(data)
        props[condition] = encoded(selected(data, ("IsUnionRule", "ComplexExpression")))
        for index, raw_rule in enumerate(array(data.get("Rules"))):
            rule = selected(raw_rule, RULE_FIELDS)
            for key in ("ValueMax", "ValueMin"):
                if type(raw_rule.get(key)) in (int, float):
                    rule[key] = raw_rule[key]
            for key, fields in (
                ("Filter", ("Type", "Dimensions")),
                ("HierarchicalValue", ("Remind", "Warn", "Serious")),
            ):
                if raw_rule.get(key) is not None:
                    rule[key] = selected(raw_rule[key], fields)
            # Round-trip validates numeric JSON before graph mutation.
            config = encoded(rule)
            rid = f"{node['resource_id']}/{category}/{index}"
            child = graph.add(
                node["account"],
                "global",
                "monitor.rule",
                rid,
                f"{category}: {rule.get('MetricName', index)}",
                source=source,
            )
            graph.nodes[child]["properties"].update(category=category, configuration=config)
            graph.edge(nid, child, "HAS_ALARM_RULE", source)
    # Keep only metadata from embedded notification templates. URL paths/queries,
    # validation codes, phone details and opaque task configs never enter the graph.
    notices = {}
    for notice in array(raw.get("Notices")):
        object_value(notice)
        notice_id = string(notice.get("Id"))
        if notice_id in notices:
            raise CollectionError("DuplicateAlarmNotice")
        notices[notice_id] = notice
    notice_ids = set(strings(raw.get("NoticeIds") or []))
    levels = []
    for item in array(raw.get("HierarchicalNotices")):
        object_value(item)
        if item.get("PolicyId") not in (None, "", node["resource_id"]):
            raise CollectionError("AlarmPolicyMismatch")
        notice_id = string(item.get("NoticeId"))
        notice_ids.add(notice_id)
        levels.append(dict(NoticeId=notice_id, Classification=strings(item.get("Classification"))))
    if levels:
        props["hierarchical_notices"] = encoded(levels)
    for notice_id in sorted(notice_ids | notices.keys()):
        notice = notices.get(notice_id)
        target = graph.add(
            node["account"],
            "global",
            "monitor.notice",
            string(notice_id),
            (notice or {}).get("Name"),
            source=source,
            status="enriched" if notice else "reference",
        )
        graph.edge(nid, target, "USES_ALARM_NOTICE", source)
        if notice:
            target_props = graph.nodes[target]["properties"]
            retain(
                target_props,
                notice,
                (
                    "UpdatedAt",
                    "NoticeType",
                    "IsPreset",
                    "NoticeLanguage",
                    "IsLoginFree",
                    "TimeZoneName",
                ),
            )
            target_props["callback_count"] = len(array(notice.get("URLNotices")))
            channels = set()
            for recipient in array(notice.get("UserNotices")):
                object_value(recipient)
                channels.update(strings(recipient.get("NoticeWay") or []))
            target_props["channels"] = encoded(sorted(channels))
            target_props["delivery_verified"] = False
    props["trigger_task_types"] = encoded(
        [string(object_value(t).get("Type")) for t in array(raw.get("TriggerTasks"))]
    )


def collect_bindings(runner, collected):
    graph = runner.graph
    source = "monitor.DescribeBindingPolicyObjectList"
    for nid, _ in collected:
        node = graph.nodes[nid]

        def operation(record, nid=nid, node=node):
            seen = set()
            previous_group = []

            def call(service, action, region, **params):
                response = runner.transport.call(service, action, region=region, **params)
                group = response.get("InstanceGroup")
                clean = None
                if group is not None:
                    clean = selected(
                        group,
                        (
                            "InstanceGroupId",
                            "ViewName",
                            "GroupName",
                            "InstanceSum",
                            "UpdateTime",
                            "InsertTime",
                        ),
                    )
                    gid = clean.get("InstanceGroupId")
                    if type(gid) is not int or gid <= 0:
                        raise CollectionError("InvalidAlarmInstanceGroup")
                    if group.get("Regions") is not None:
                        clean["Regions"] = strings(group["Regions"])
                if previous_group and previous_group[0] != clean:
                    raise CollectionError("InventoryChanged")
                previous_group[:] = [clean]
                if clean:
                    child = graph.add(
                        node["account"],
                        "global",
                        "monitor.instancegroup",
                        str(clean["InstanceGroupId"]),
                        clean.get("GroupName"),
                        source=source,
                    )
                    graph.nodes[child]["properties"]["configuration"] = encoded(clean)
                    graph.edge(nid, child, "BINDS_INSTANCE_GROUP", source)
                if (
                    response.get("List") is None
                    and type(response.get("Total")) is int
                    and response["Total"] == 0
                ):
                    response = {**response, "List": []}
                return response

            for items, request_id in pages(
                SimpleNamespace(call=call),
                BINDINGS,
                "global",
                dict(Module="monitor", GroupId=0, PolicyId=node["resource_id"]),
            ):
                if request_id:
                    record["request_ids"].append(request_id)
                for item in items:
                    object_value(item)
                    uid = string(item.get("UniqueId"))
                    if uid in seen:
                        raise CollectionError("DuplicateAlarmBinding")
                    seen.add(uid)
                    dims = dimensions(item.get("Dimensions"))
                    region = string(item.get("Region"))
                    shielded = item.get("IsShielded")
                    if type(shielded) is not int or shielded not in (0, 1):
                        raise CollectionError("InvalidAlarmBinding")
                    child = graph.add(
                        node["account"],
                        "global",
                        "monitor.binding",
                        node["resource_id"] + "/" + uid,
                        uid,
                        source=source,
                    )
                    graph.nodes[child]["properties"].update(
                        dimensions=encoded(dims),
                        binding_region=region,
                        IsShielded=shielded,
                        Namespace=node["properties"].get("Namespace", ""),
                        MonitorType=node["properties"].get("MonitorType", ""),
                        resource_resolution="unresolved",
                        evaluation_verified=False,
                    )
                    graph.edge(nid, child, "HAS_ALARM_BINDING", source)
                    record["count"] += 1
            node["properties"]["bindings_collected"] = True

        runner.scope(
            "monitor", "DescribeBindingPolicyObjectList", "global", operation, node["resource_id"]
        )


def link_bindings(graph):
    # Only CVM's documented cvm_device/unInstanceId mapping is currently audited.
    # Other product dimensions remain inspectable, without guessed target kinds.
    for nid, node in list(graph.nodes.items()):
        if node["kind"] != "monitor.binding":
            continue
        props = node["properties"]
        if props.get("MonitorType") != "MT_QCE" or props.get("Namespace") != "cvm_device":
            props["resource_resolution"] = "unsupported-namespace"
            continue
        region = props.get("binding_region", "")
        region = REGIONS.get(region, region if re.fullmatch(r"[a-z]+-[a-z0-9-]+", region) else "")
        if not region:
            props["resource_resolution"] = "unknown-region"
            continue
        dims = dimensions(props["dimensions"])
        rid = dims.get("unInstanceId")
        if not isinstance(rid, str) or not re.fullmatch(r"ins-[a-zA-Z0-9]+", rid):
            props["resource_resolution"] = "unsupported-dimensions"
            continue
        candidates = [
            n
            for n in graph.nodes.values()
            if n["kind"] == "cvm.instance"
            and n["account"] == node["account"]
            and n["region"] == region
            and n["resource_id"] == rid
            and n["status"] == "enriched"
        ]
        props["resource_resolution"] = "resolved" if len(candidates) == 1 else "unresolved"
        if len(candidates) == 1:
            graph.edge(
                nid,
                candidates[0]["id"],
                "CONFIGURED_ALARM_OBJECT",
                "monitor.DescribeBindingPolicyObjectList",
            )
