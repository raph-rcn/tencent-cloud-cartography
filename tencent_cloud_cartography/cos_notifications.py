"""V2 bucket notification rules; no object reads or destination requests."""

import json
import re

from .model import stable_id
from .transport import CollectionError


def string(value):
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4096
        or any(ord(c) < 32 for c in value)
    ):
        raise CollectionError("InvalidNotificationConfiguration")
    return value


def rows(value):
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    if not isinstance(value, list) or not all(isinstance(v, dict) for v in value):
        raise CollectionError("InvalidNotificationConfiguration")
    return value


def notification(graph, bucket, data, source):
    if data == {"NotificationConfiguration": None}:
        data = {}
    if set(data) - {"CloudFunctionConfiguration", "CkafkaConfiguration"}:
        raise CollectionError("UnsupportedNotificationConfiguration")
    prepared = []
    seen = set()
    for category in ("CloudFunctionConfiguration", "CkafkaConfiguration"):
        for raw in rows(data.get(category)):
            rid = string(raw.get("Id"))
            if rid in seen:
                raise CollectionError("DuplicateNotificationRule")
            seen.add(rid)
            events = raw.get("Event")
            events = [events] if isinstance(events, str) else events
            if (
                not isinstance(events, list)
                or not events
                or any(
                    not isinstance(e, str) or not re.fullmatch(r"cos:[A-Za-z0-9:*]+", e)
                    for e in events
                )
            ):
                raise CollectionError("InvalidNotificationEvents")
            filters = []
            if raw.get("Filter") is not None:
                f = raw["Filter"]
                if not isinstance(f, dict) or not isinstance(f.get("Key"), dict):
                    raise CollectionError("InvalidNotificationFilter")
                for r in rows(f["Key"].get("FilterRule")):
                    if r.get("Name") not in ("Prefix", "Suffix") or not isinstance(
                        r.get("Value"), str
                    ):
                        raise CollectionError("InvalidNotificationFilter")
                    filters.append({"Name": r["Name"], "Value": r["Value"]})
                if len({r["Name"] for r in filters}) != len(filters):
                    raise CollectionError("DuplicateNotificationFilter")
            props = dict(
                Id=rid,
                destination_type=category,
                events=json.dumps(events),
                filters=json.dumps(filters, sort_keys=True),
                delivery_verified=False,
            )
            if category == "CloudFunctionConfiguration":
                props["CloudFunction"] = string(raw.get("CloudFunction"))
            else:
                target = raw.get("Ckafka")
                if not isinstance(target, dict) or not re.fullmatch(
                    r"ckafka-[a-z0-9]+", string(target.get("InstanceId"))
                ):
                    raise CollectionError("InvalidNotificationTarget")
                props.update(
                    InstanceId=target["InstanceId"], TopicName=string(target.get("TopicName"))
                )
                if raw.get("RoleArn"):
                    props["RoleArn"] = string(raw["RoleArn"])
            prepared.append(props)
    # Validate the whole response before publishing any rules.
    for props in prepared:
        nid = graph.add(
            bucket["account"],
            bucket["region"],
            "cos.notification",
            bucket["resource_id"] + "/" + stable_id(props["Id"]),
            props["Id"],
            source=source,
        )
        graph.nodes[nid]["properties"].update(
            props, bucket_appid=bucket["resource_id"].rsplit("-", 1)[1]
        )
        graph.edge(bucket["id"], nid, "HAS_NOTIFICATION", source)
    bucket["properties"].update(notification_collected=True, notification_rule_count=len(prepared))


def link_destinations(graph):
    for rule in list(graph.nodes.values()):
        if rule["kind"] != "cos.notification":
            continue
        p = rule["properties"]
        candidates = [
            n
            for n in graph.nodes.values()
            if n["account"] == rule["account"]
            and n["region"] == rule["region"]
            and n["status"] == "enriched"
        ]
        targets = []
        if p["destination_type"] == "CkafkaConfiguration":
            targets = [
                n
                for n in candidates
                if n["kind"] == "ckafka.topic"
                and n["properties"].get("InstanceId") == p["InstanceId"]
                and n["properties"].get("TopicName") == p["TopicName"]
            ]
        else:
            m = re.fullmatch(
                r"qcs:0:scf:([^:]+):appid/(\d+):([^.]+)\.([^.]+)\.([^.]+)", p["CloudFunction"]
            )
            if m and m[1] == rule["region"] and m[2] == p["bucket_appid"]:
                targets = [
                    n
                    for n in candidates
                    if n["kind"] == "scf.function"
                    and n["name"] == m[4]
                    and n["properties"].get("Namespace") == m[3]
                ]
                p["scf_qualifier"] = m[5]
        p["destination_resolved"] = len(targets) == 1
        if len(targets) == 1:
            graph.edge(
                rule["id"],
                targets[0]["id"],
                "CONFIGURED_NOTIFICATION_DESTINATION",
                "COS V2 rule + uniquely collected destination",
            )
        role = re.fullmatch(r"qcs::cam::uin/(\d+):roleName/(.+)", p.get("RoleArn", ""))
        if role and role[1] == rule["account"]:
            roles = [
                n
                for n in graph.nodes.values()
                if n["kind"] == "cam.role"
                and n["account"] == rule["account"]
                and n["status"] == "enriched"
                and n["properties"].get("RoleName") == role[2]
            ]
            if len(roles) == 1:
                graph.edge(rule["id"], roles[0]["id"], "CONFIGURED_DELIVERY_ROLE", "COS RoleArn")


def parse_xml(body):
    """Parse fixed notification XML without SDK eval, DTDs or external entities."""
    import xml.etree.ElementTree as ET

    if not isinstance(body, bytes) or len(body) > 1_000_000:
        raise CollectionError("InvalidNotificationXml")
    try:
        text = body.decode("utf-8")
        if "\x00" in text or "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
            raise ValueError
        root = ET.fromstring(text)
        namespace = root.tag.split("}")[0] + "}" if root.tag.startswith("{") else ""
        if (
            namespace
            not in (
                "",
                "{http://www.qcloud.com/document/product/436/7751}",
                "{https://cloud.tencent.com/document/product/436}",
                "{http://s3.amazonaws.com/doc/2006-03-01/}",
            )
            or root.tag != namespace + "NotificationConfiguration"
        ):
            raise ValueError
        count = 0

        def convert(element, depth=0):
            nonlocal count
            count += 1
            if depth > 10 or count > 10000:
                raise ValueError
            children = list(element)
            if not children:
                return element.text or ""
            result = {}
            for child in children:
                if namespace and not child.tag.startswith(namespace):
                    raise ValueError
                tag = child.tag.removeprefix(namespace)
                if "{" in tag or "}" in tag:
                    raise ValueError
                value = convert(child, depth + 1)
                if tag in result:
                    result[tag] = (
                        result[tag] + [value]
                        if isinstance(result[tag], list)
                        else [result[tag], value]
                    )
                else:
                    result[tag] = value
            return result

        return convert(root) if list(root) else {}
    except (ValueError, ET.ParseError):
        raise CollectionError("InvalidNotificationXml") from None
