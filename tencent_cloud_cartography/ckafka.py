"""CKafka topology/configuration metadata; no messages, offsets or credentials."""

import json
import re

from .catalog import Collector
from .observability import retain, strings
from .transport import CollectionError

TOPICS = Collector(
    "ckafka",
    "DescribeTopic",
    "Result.TopicList",
    "ckafka.topic",
    ("TopicResourceId",),
    ("TopicName",),
    "Result.TotalCount",
    require_total=True,
    page_size=50,
)


def identity(value, prefix):
    if not isinstance(value, str) or not re.fullmatch(prefix + r"-[a-zA-Z0-9-]+", value):
        raise CollectionError("InvalidKafkaIdentity")
    return value


def prepare(kind, raw, params):
    if kind == "ckafka.instance":
        identity(raw.get("InstanceId"), "ckafka")
    elif kind == "ckafka.topic":
        instance = identity(params.get("InstanceId"), "ckafka")
        if raw.get("InstanceId") not in (None, instance):
            raise CollectionError("KafkaInstanceMismatch")
        topic = identity(raw.get("TopicId"), "topic")
        name = raw.get("TopicName")
        if not isinstance(name, str) or not name or any(ord(c) < 32 for c in name):
            raise CollectionError("InvalidKafkaTopicName")
        return {**raw, "InstanceId": instance, "TopicResourceId": f"{instance}/{topic}"}
    return raw


def selected_object(value, keys):
    if not isinstance(value, dict):
        raise CollectionError("InvalidKafkaConfiguration")
    selected = {}
    retain(selected, value, keys)
    return selected


def configuration(graph, nid, raw, source):
    node = graph.nodes[nid]
    props = node["properties"]
    props["access_verified"] = False
    if node["kind"] == "ckafka.instance":
        retain(
            props,
            raw,
            (
                "Status",
                "Bandwidth",
                "DiskSize",
                "ZoneId",
                "Healthy",
                "CreateTime",
                "MsgRetentionTime",
                "Version",
                "MaxGroupNum",
                "InstanceType",
                "MaxConnection",
                "PublicNetwork",
                "MaxMessageByte",
                "InstanceChargeType",
                "ClusterType",
                "UncleanLeaderElectionEnable",
                "DeleteProtectionEnable",
                "RetentionBytes",
                "TransactionalIdExpirationMs",
                "Vip",
                "Vport",
            ),
        )
        if raw.get("Status") is not None:
            props["state"] = str(raw["Status"])
        for field, prefix, kind, relation, region in (
            ("VpcId", "vpc", "vpc.vpc", "IN_VPC", node["region"]),
            ("SubnetId", "subnet", "vpc.subnet", "IN_SUBNET", node["region"]),
        ):
            if raw.get(field):
                target = graph.add(
                    node["account"],
                    region,
                    kind,
                    identity(raw[field], prefix),
                    status="reference",
                    source=source,
                )
                graph.edge(nid, target, relation, source)
        if raw.get("CustomCertId"):
            cert = raw["CustomCertId"]
            if not isinstance(cert, str) or not re.fullmatch(r"[a-zA-Z0-9-]+", cert):
                raise CollectionError("InvalidKafkaCertificateId")
            target = graph.add(
                node["account"],
                "global",
                "ssl.certificate",
                cert,
                status="reference",
                source=source,
            )
            graph.edge(nid, target, "USES_CERTIFICATE", source)
        for field in ("ZoneIds",):
            if raw.get(field) is not None:
                values = raw[field]
                if not isinstance(values, list) or any(type(v) is not int for v in values):
                    raise CollectionError("InvalidKafkaZones")
                props[field] = json.dumps(values)
        if raw.get("VipList") is not None:
            if not isinstance(raw["VipList"], list):
                raise CollectionError("InvalidKafkaEndpoints")
            props["endpoints"] = json.dumps(
                [selected_object(v, ("Vip", "Vport")) for v in raw["VipList"]], sort_keys=True
            )
        if raw.get("Config") is not None:
            props["default_topic_configuration"] = json.dumps(
                selected_object(
                    raw["Config"],
                    (
                        "AutoCreateTopicsEnable",
                        "DefaultNumPartitions",
                        "DefaultReplicationFactor",
                    ),
                ),
                sort_keys=True,
            )
    elif node["kind"] == "ckafka.topic":
        retain(
            props,
            raw,
            (
                "InstanceId",
                "TopicId",
                "TopicName",
                "Note",
                "CreateTime",
                "PartitionNum",
                "ReplicaNum",
                "EnableWhiteList",
                "EnableAclRule",
            ),
        )
        if raw.get("IpWhiteList") is not None:
            props["ip_allowlist"] = json.dumps(strings(raw["IpWhiteList"]))
        for field, keys in (
            (
                "Config",
                (
                    "Retention",
                    "MinInsyncReplicas",
                    "CleanUpPolicy",
                    "SegmentMs",
                    "UncleanLeaderElectionEnable",
                    "SegmentBytes",
                    "MaxMessageBytes",
                    "RetentionBytes",
                    "LogMsgTimestampType",
                ),
            ),
            ("QuotaConfig", ("QuotaConsumerByteRate", "QuotaProducerByteRate")),
        ):
            if raw.get(field) is not None:
                props[field] = json.dumps(selected_object(raw[field], keys), sort_keys=True)
        partitions = raw.get("Partitions")
        if partitions is not None:
            if not isinstance(partitions, list):
                raise CollectionError("InvalidKafkaPartitions")
            ids = set()
            for partition in partitions:
                number = partition.get("Partition") if isinstance(partition, dict) else None
                if type(number) is not int or number < 0 or number in ids:
                    raise CollectionError("InvalidKafkaPartitionId")
                ids.add(number)
            count = raw.get("PartitionNum")
            if type(count) is not int or count < 0 or len(ids) != count:
                raise CollectionError("KafkaPartitionCountMismatch")
            for partition in partitions:
                number = partition["Partition"]
                pid = graph.add(
                    node["account"],
                    node["region"],
                    "ckafka.partition",
                    f"{node['resource_id']}/{number}",
                    f"Partition {number}",
                    source=source,
                )
                retain(
                    graph.nodes[pid]["properties"],
                    partition,
                    ("Partition", "LeaderStatus", "IsrNum", "ReplicaNum"),
                )
                graph.edge(nid, pid, "HAS_PARTITION", source)
        # Preset rules are not a complete effective ACL assessment.
        if raw.get("AclRuleList") is not None:
            rules = raw["AclRuleList"]
            if not isinstance(rules, list):
                raise CollectionError("InvalidKafkaAclRules")
            selected = []
            for rule in rules:
                if not isinstance(rule, dict) or rule.get("InstanceId") not in (
                    None,
                    props["InstanceId"],
                ):
                    raise CollectionError("KafkaInstanceMismatch")
                selected.append(
                    selected_object(
                        rule,
                        (
                            "RuleName",
                            "PatternType",
                            "Pattern",
                            "ResourceType",
                            "IsApplied",
                            "CreateTimeStamp",
                            "UpdateTimeStamp",
                            "TopicCount",
                        ),
                    )
                )
            props["acl_rule_summaries"] = json.dumps(selected, sort_keys=True)
            props["acl_entries_collected"] = False


def detail(runner, nid, action, params, match_field, expected):
    node = runner.graph.nodes[nid]

    def operation(record):
        response = runner.transport.call("ckafka", action, region=node["region"], **params)
        if response.get("RequestId"):
            record["request_ids"].append(response["RequestId"])
        raw = response.get("Result")
        if not isinstance(raw, dict) or raw.get(match_field) != expected:
            raise CollectionError("KafkaDetailIdentityMismatch")
        if node["kind"] == "ckafka.topic":
            if raw.get("Partitions") is None:
                raise CollectionError("InvalidKafkaPartitions")
            if raw.get("InstanceId") not in (None, params["InstanceId"]) or raw.get(
                "TopicName"
            ) not in (None, params["TopicName"]):
                raise CollectionError("KafkaDetailIdentityMismatch")
            raw = {**raw, "InstanceId": params["InstanceId"]}
        configuration(runner.graph, nid, raw, "ckafka." + action)
        node["properties"]["detail_collected"] = True
        record["count"] = 1

    runner.scope("ckafka", action, node["region"], operation, json.dumps(params, sort_keys=True))


def collect_instance(runner, nid):
    node = runner.graph.nodes[nid]
    instance = node["resource_id"]
    detail(
        runner, nid, "DescribeInstanceAttributes", {"InstanceId": instance}, "InstanceId", instance
    )
    topics = runner.native(TOPICS, node["region"], {"InstanceId": instance}, nid, "HAS_TOPIC")
    for tid, raw in topics:
        detail(
            runner,
            tid,
            "DescribeTopicAttributes",
            {"InstanceId": instance, "TopicName": raw["TopicName"]},
            "TopicId",
            raw["TopicId"],
        )
