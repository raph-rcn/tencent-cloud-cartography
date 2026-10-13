"""CloudConfig settings and rule definitions; no resource snapshots or remediation."""

import json
import re

from .transport import CollectionError


def text(value):
    if not isinstance(value, str) or len(value) > 32768:
        raise CollectionError("InvalidConfigValue")
    return value


def selected(raw, schema):
    if not isinstance(raw, dict):
        raise CollectionError("InvalidConfigObject")
    result = {}
    for key, kind in schema.items():
        value = raw.get(key)
        if value is not None:
            if type(value) is not kind:
                raise CollectionError("InvalidConfigField")
            result[key] = text(value) if kind is str else value
    return result


def rows(value, schema):
    if not isinstance(value, list):
        raise CollectionError("InvalidConfigArray")
    return [selected(row, schema) for row in value]


def resource_type(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"QCS::[A-Za-z0-9_-]+::[A-Za-z0-9_-]+", value, re.I
    ):
        raise CollectionError("InvalidConfigResourceType")
    return value.lower()


def rule_properties(raw):
    props = selected(
        raw,
        dict.fromkeys(
            (
                "Identifier",
                "RuleName",
                "Description",
                "ServiceFunction",
                "CreateTime",
                "Status",
                "ComplianceResult",
                "ConfigRuleInvokedTime",
                "IdentifierType",
                "CompliancePackId",
                "CompliancePackName",
                "AccountGroupId",
                "AccountGroupName",
            ),
            str,
        ),
    )
    if not isinstance(raw.get("ConfigRuleId"), str) or not re.fullmatch(
        r"cr-[A-Za-z0-9_-]+", raw["ConfigRuleId"]
    ):
        raise CollectionError("InvalidConfigRuleId")
    props["ConfigRuleId"] = raw["ConfigRuleId"]
    for key in ("RiskLevel", "RuleOwnerId"):
        if raw.get(key) is not None:
            if type(raw[key]) is not int or raw[key] < 0:
                raise CollectionError("InvalidConfigNumber")
            props[key] = raw[key]
    for key in (
        "ResourceType",
        "Labels",
        "RegionsScope",
        "ExcludeResourceIdsScope",
        "ManageTriggerType",
    ):
        if raw.get(key) is not None:
            if not isinstance(raw[key], list):
                raise CollectionError("InvalidConfigArray")
            values = [text(v) for v in raw[key]]
            if key == "ResourceType":
                normalized = [resource_type(v) for v in values]
                if len(normalized) != len(set(normalized)):
                    raise CollectionError("DuplicateConfigResourceType")
            props[key] = json.dumps(values)
    nested = {
        "InputParameter": dict.fromkeys(("ParameterKey", "Type", "Value"), str),
        "ManageInputParameter": dict.fromkeys(
            ("ValueType", "ParameterKey", "Type", "DefaultValue", "Description"), str
        ),
        "TagsScope": dict.fromkeys(("TagKey", "TagValue"), str),
        "TriggerType": dict.fromkeys(("MessageType", "MaximumExecutionFrequency"), str),
        "SourceCondition": {
            **dict.fromkeys(("EmptyAs", "SelectPath", "Operator", "DesiredValue"), str),
            "Required": bool,
        },
    }
    for key, schema in nested.items():
        if raw.get(key) is not None:
            props[key] = json.dumps(rows(raw[key], schema), sort_keys=True)
    props["compliance_independently_verified"] = False
    return props


def prepare(raw):
    rule_properties(raw)
    return raw


def type_node(graph, account, value, source):
    nid = graph.add(
        account, "global", "config.resourcetype", resource_type(value), value, source=source
    )
    graph.nodes[nid]["properties"].update(resource_type=value, definition_only=True)
    return nid


def configuration(graph, nid, raw, source):
    props = rule_properties(raw)
    node = graph.nodes[nid]
    previous_types = node["properties"].get("ResourceType")
    node["properties"].update(props)
    if props.get("Status"):
        node["properties"]["state"] = props["Status"]
    # A detail response may change scope since listing. Its explicit type list
    # replaces list-time type edges; absence means unavailable, never an empty scope.
    if "ResourceType" in props:
        if previous_types is not None and previous_types != props["ResourceType"]:
            for eid, edge in list(graph.edges.items()):
                if edge["source"] == nid and edge["relationship"] == "APPLIES_TO_RESOURCE_TYPE":
                    del graph.edges[eid]
        for value in raw["ResourceType"]:
            target = type_node(graph, node["account"], value, source)
            graph.edge(nid, target, "APPLIES_TO_RESOURCE_TYPE", source)


def collect_rule_details(runner, collected):
    for nid, raw in collected:
        rule = runner.graph.nodes[nid]

        def detail(record, rule=rule):
            response = runner.transport.call(
                "config", "DescribeConfigRule", region="global", RuleId=rule["resource_id"]
            )
            if response.get("RequestId"):
                record["request_ids"].append(response["RequestId"])
            value = response.get("ConfigRule")
            if not isinstance(value, dict) or value.get("ConfigRuleId") != rule["resource_id"]:
                raise CollectionError("ConfigRuleIdentityMismatch")
            props = rule_properties(value)
            for field in ("RuleOwnerId", "AccountGroupId"):
                if (
                    field in props
                    and field in rule["properties"]
                    and props[field] != rule["properties"][field]
                ):
                    raise CollectionError("ConfigRuleOwnerChanged")
            changes = [
                k for k in props if k in rule["properties"] and props[k] != rule["properties"][k]
            ]
            source = "config.DescribeConfigRule"
            configuration(runner.graph, rule["id"], value, source)
            rule["properties"].update(
                detail_collected=True, changed_since_list=json.dumps(sorted(changes))
            )
            rule["sources"] = sorted(set(rule["sources"] + [source]))
            record["count"] = 1

        runner.scope("config", "DescribeConfigRule", "global", detail, rule["resource_id"])


def status(raw):
    if type(raw.get("Status")) is not int or raw["Status"] not in (0, 1):
        raise CollectionError("InvalidConfigStatus")
    return raw["Status"]


def collect_settings(runner):
    graph, account = runner.graph, runner.account

    def recorder(record):
        source = "config.DescribeConfigRecorder"
        raw = runner.transport.call("config", "DescribeConfigRecorder", region="global")
        if raw.get("RequestId"):
            record["request_ids"].append(raw["RequestId"])
        enabled = status(raw)
        props = selected(
            raw, dict(CreateTime=str, TriggerCount=int, OpenCount=int, UpdateCount=int)
        )
        items = raw.get("Items")
        clean = (
            None
            if items is None
            else rows(
                items,
                dict.fromkeys(
                    ("Product", "ProductName", "ResourceType", "ResourceTypeName", "UpdateTime"),
                    str,
                ),
            )
        )
        if clean is not None:
            types = [resource_type(row.get("ResourceType")) for row in clean]
            if len(types) != len(set(types)):
                raise CollectionError("DuplicateConfigResourceType")
        nid = graph.add(
            account,
            "global",
            "config.recorder",
            "account-recorder",
            "Resource recorder",
            source=source,
        )
        graph.nodes[nid]["properties"].update(
            props,
            Status=enabled,
            resource_types_known=clean is not None,
            identity_basis="account-singleton",
            recording_verified=False,
        )
        record["count"] = 1
        if clean is None:
            raise CollectionError("ConfigRecorderScopeUnavailable")
        graph.nodes[nid]["properties"]["monitored_resource_types"] = json.dumps(
            clean, sort_keys=True
        )
        for row in clean:
            tid = type_node(graph, account, row["ResourceType"], source)
            graph.edge(nid, tid, "CONFIGURED_RECORDING_TYPE", source)

    runner.scope("config", "DescribeConfigRecorder", "global", recorder)

    def delivery(record):
        source = "config.DescribeConfigDeliver"
        try:
            raw = runner.transport.call("config", "DescribeConfigDeliver", region="global")
        except CollectionError as exc:
            if exc.code == "ResourceNotFound.DeliverIsNotExist":
                return
            raise
        if raw.get("RequestId"):
            record["request_ids"].append(raw["RequestId"])
        enabled = status(raw)
        props = selected(
            raw,
            dict.fromkeys(
                ("DeliverName", "TargetArn", "CreateTime", "DeliverPrefix", "DeliverType"), str
            ),
        )
        if raw.get("DeliverContentType") is not None:
            if type(raw["DeliverContentType"]) is not int or raw["DeliverContentType"] not in (
                1,
                2,
                3,
            ):
                raise CollectionError("InvalidConfigDeliveryContent")
            props["DeliverContentType"] = raw["DeliverContentType"]
        nid = graph.add(
            account,
            "global",
            "config.delivery",
            "account-delivery",
            props.get("DeliverName") or "Configuration delivery",
            source=source,
        )
        graph.nodes[nid]["properties"].update(
            props, Status=enabled, identity_basis="account-singleton", delivery_verified=False
        )
        record["count"] = 1
        if enabled and (not props.get("TargetArn") or not props.get("DeliverType")):
            raise CollectionError("ConfigDeliveryTargetUnavailable")

    runner.scope("config", "DescribeConfigDeliver", "global", delivery)


def cos_target(qcs):
    match = re.fullmatch(r"qcs::cos:([a-z]+-[a-z0-9-]+):uid/([0-9]+):(.+)", qcs)
    if not match:
        return None
    region, appid, path = match.groups()
    if path.startswith("prefix//"):
        parts = path[len("prefix//") :].split("/")
        if len(parts) < 2 or parts[0] != appid:
            return None
        bucket = parts[1] + "-" + appid
    elif path.startswith("prefix/"):
        bucket = path[len("prefix/") :].split("/")[0] + "-" + appid
    else:
        bucket = path.split("/")[0]
        if not bucket.endswith("-" + appid):
            return None
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*-[0-9]+", bucket):
        return None
    return region, bucket


def link_delivery(graph):
    buckets = [
        n for n in graph.nodes.values() if n["kind"] == "cos.bucket" and n["status"] == "enriched"
    ]
    for node in list(graph.nodes.values()):
        if node["kind"] != "config.delivery":
            continue
        p = node["properties"]
        arn = p.get("TargetArn", "")
        kind = p.get("DeliverType", "").lower()
        matches = []
        p["destination_resolution"] = "unresolved"
        if not arn:
            p["destination_resolution"] = "not-configured" if p["Status"] == 0 else "unavailable"
            continue
        if kind == "cos":
            parsed = cos_target(arn)
            if not parsed:
                p["destination_resolution"] = "unsupported-resource-format"
                continue
            region, bucket = parsed
            matches = [
                n["id"] for n in buckets if n["region"] == region and n["resource_id"] == bucket
            ]
        elif kind == "cls":
            match = re.fullmatch(
                r"qcs::cls:([a-z]+-[a-z0-9-]+):uin/([0-9]+):topic/([A-Za-z0-9_-]+)", arn
            )
            if not match:
                p["destination_resolution"] = "unsupported-resource-format"
                continue
            region, owner, topic = match.groups()
            matches = [
                graph.add(
                    owner,
                    region,
                    "cls.topic",
                    topic,
                    status="reference",
                    source="config.DescribeConfigDeliver",
                )
            ]
        elif arn:
            p["destination_resolution"] = "unsupported-type"
        if len(matches) == 1:
            p["destination_resolution"] = (
                "resolved" if graph.nodes[matches[0]]["status"] == "enriched" else "reference"
            )
            graph.edge(
                node["id"], matches[0], "CONFIGURED_LOG_DESTINATION", "config.DescribeConfigDeliver"
            )
        elif len(matches) > 1:
            p["destination_resolution"] = "ambiguous"
