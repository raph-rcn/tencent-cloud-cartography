"""Scheduled SQL configuration and declared metric outputs, never executed queries."""

import re

from .cls_alarms import array, clean, encoded, obj
from .model import stable_id
from .observability import retain, string, strings
from .transport import CollectionError


def region(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z]+-[a-z0-9-]+", value):
        raise CollectionError("InvalidScheduledSqlRegion")
    return value


def configuration(graph, nid, raw, source):
    node = graph.nodes[nid]
    props = node["properties"]
    retain(
        props,
        raw,
        (
            "CreateTime",
            "UpdateTime",
            "Status",
            "EnableFlag",
            "ScheduledSqlContent",
            "ProcessStartTime",
            "ProcessEndTime",
            "ProcessType",
            "ProcessPeriod",
            "ProcessTimeWindow",
            "ProcessDelay",
            "SyntaxRule",
            "HasServicesLog",
            "FullQuery",
            "ProcessPeriodUnit",
            "SrcTopicId",
            "SrcTopicRegion",
        ),
    )
    props["execution_verified"] = False
    destination = obj(raw.get("DstResource"))
    selected = clean(destination, ("TopicId", "Region", "BizType", "MetricName", "CustomTime"))
    for field in ("MetricNames", "MetricLabels"):
        if destination.get(field) is not None:
            selected[field] = strings(destination[field])
    if destination.get("CustomMetricLabels") is not None:
        labels = []
        keys = set()
        for label in array(destination["CustomMetricLabels"]):
            item = clean(label, ("Key", "Value"))
            key = string(item.get("Key"))
            if key in keys or not isinstance(item.get("Value"), str):
                raise CollectionError("InvalidScheduledMetricLabels")
            keys.add(key)
            labels.append(item)
        selected["CustomMetricLabels"] = labels
    props["destination_configuration"] = encoded(selected)
    # Validate both endpoints before creating any dependency edges. The response
    # must supply the actual topic regions; never borrow the task/CLI region.
    src_region = region(raw.get("SrcTopicRegion"))
    dst_region = region(selected.get("Region"))
    src_topic = string(raw.get("SrcTopicId"))
    dst_topic = string(selected.get("TopicId"))
    biz_type = selected.get("BizType")
    if type(biz_type) is not int or biz_type not in (0, 1):
        raise CollectionError("InvalidScheduledSqlTopicType")
    metric_names = []
    if biz_type == 1:
        # SDK contract: nonempty MetricNames takes precedence over MetricName.
        metric_names = selected.get("MetricNames") or [selected.get("MetricName")]
        if not metric_names or any(not isinstance(v, str) or not v for v in metric_names):
            raise CollectionError("MissingScheduledMetricName")
        for name in metric_names:
            string(name)
        if len(set(metric_names)) != len(metric_names):
            raise CollectionError("DuplicateScheduledMetricName")
    src = graph.add(
        node["account"],
        src_region,
        "cls.topic",
        src_topic,
        raw.get("SrcTopicName"),
        source=source,
        status="reference",
    )
    dst = graph.add(
        node["account"], dst_region, "cls.topic", dst_topic, source=source, status="reference"
    )
    graph.edge(nid, src, "READS_TOPIC", source)
    graph.edge(nid, dst, "CONFIGURED_OUTPUT_TOPIC", source)
    for name in metric_names:
        metric = graph.add(
            node["account"],
            dst_region,
            "cls.metric",
            stable_id(dst_topic, name),
            name,
            source=source,
        )
        # Labels and time/value expressions belong to each task's configuration,
        # so two producers do not overwrite each other's output mapping.
        graph.nodes[metric]["properties"].update(
            MetricName=name,
            TopicId=dst_topic,
            configuration_only=True,
            samples_observed=False,
        )
        graph.edge(nid, metric, "DECLARES_METRIC_OUTPUT", source)
        graph.edge(metric, dst, "IN_METRIC_TOPIC", source)
