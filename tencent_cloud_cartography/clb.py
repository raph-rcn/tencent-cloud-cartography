"""CLB listeners, routing rules and explicit server/client certificate references."""

import json

from .transport import CollectionError


def identity(value, prefix=""):
    if (
        not isinstance(value, str)
        or not value
        or not value.startswith(prefix)
        or any(c in value for c in "/\\\n\r")
    ):
        raise CollectionError("InvalidClbIdentity")
    return value


def retain(node, raw, fields):
    node["properties"].update({k: raw[k] for k in fields if type(raw.get(k)) in (str, int, bool)})


def listener(graph, lb, raw, source):
    rid = lb["resource_id"] + "/" + identity(raw.get("ListenerId"), "lbl-")
    nid = graph.add(
        lb["account"],
        lb["region"],
        "clb.listener",
        rid,
        raw.get("ListenerName") or f"{raw.get('Protocol', '')}:{raw.get('Port', '')}",
        source=source,
    )
    retain(
        graph.nodes[nid],
        raw,
        (
            "ListenerId",
            "Protocol",
            "Port",
            "EndPort",
            "SniSwitch",
            "Scheduler",
            "SessionExpireTime",
            "TargetType",
            "KeepaliveEnable",
        ),
    )
    graph.edge(lb["id"], nid, "HAS_LISTENER", source)
    return nid


def rule(graph, parent, raw, source):
    rid = parent["resource_id"] + "/" + identity(raw.get("LocationId"), "loc-")
    nid = graph.add(
        parent["account"],
        parent["region"],
        "clb.rule",
        rid,
        (raw.get("Domain") or raw["LocationId"]) + " " + (raw.get("Url") or "").split("?")[0],
        source=source,
    )
    retain(
        graph.nodes[nid],
        raw,
        (
            "LocationId",
            "Domain",
            "Scheduler",
            "SessionExpireTime",
            "DefaultServer",
            "Http2",
            "ForwardType",
            "TargetType",
        ),
    )
    if isinstance(raw.get("Url"), str):
        graph.nodes[nid]["properties"]["Url"] = raw["Url"].split("?")[0].split("#")[0]
    if raw.get("Domains") is not None:
        if not isinstance(raw["Domains"], list) or not all(
            isinstance(s, str) for s in raw["Domains"]
        ):
            raise CollectionError("InvalidResponse")
        graph.nodes[nid]["properties"]["Domains"] = json.dumps(raw["Domains"])
    graph.edge(parent["id"], nid, "HAS_RULE", source)
    return nid


def flat_listener(graph, lb, raw, source):
    lid = listener(graph, lb, raw, source)
    return rule(graph, graph.nodes[lid], raw, source) if raw.get("LocationId") else lid


def certificates(graph, node, raw, source):
    config = raw.get("Certificate")
    if config is None:
        return
    if not isinstance(config, dict):
        raise CollectionError("InvalidResponse")
    extra = config.get("ExtCertIds") or []
    if not isinstance(extra, list):
        raise CollectionError("InvalidResponse")
    refs = [(value, "CONFIGURED_SERVER_CERTIFICATE") for value in extra]
    refs += [
        (config.get("CertId"), "CONFIGURED_SERVER_CERTIFICATE"),
        (config.get("CertCaId"), "CONFIGURED_CLIENT_CA_CERTIFICATE"),
    ]
    for value, relation in refs:
        if value:
            identity(value)
    retain(node, config, ("SSLMode", "SSLVerifyClient"))
    for value, relation in refs:
        if value:
            cid = graph.add(
                node["account"],
                "global",
                "ssl.certificate",
                value,
                source=source,
                status="reference",
            )
            graph.edge(node["id"], cid, relation, source)


def collect_listeners(runner):
    graph = runner.graph
    lbs = [
        n
        for n in graph.nodes.values()
        if n["kind"] == "clb.clb"
        and n["account"] == runner.account
        and n["region"] in runner.regions
        and n["status"] == "enriched"
    ]
    for lb in lbs:

        def operation(record, lb=lb):
            source = "clb.DescribeListeners"
            data = runner.transport.call(
                "clb", "DescribeListeners", lb["region"], LoadBalancerId=lb["resource_id"]
            )
            if data.get("RequestId"):
                record["request_ids"].append(data["RequestId"])
            items = data.get("Listeners")
            if (
                not isinstance(items, list)
                or type(data.get("TotalCount")) is not int
                or len(items) != data["TotalCount"]
            ):
                raise CollectionError("CountMismatch")
            ids = [identity(item.get("ListenerId"), "lbl-") for item in items]
            if len(set(ids)) != len(ids):
                raise CollectionError("DuplicateListener")
            for item in items:
                lid = listener(graph, lb, item, source)
                certificates(graph, graph.nodes[lid], item, source)
                rules = item.get("Rules") or []
                if not isinstance(rules, list):
                    raise CollectionError("InvalidResponse")
                seen = set()
                for raw in rules:
                    if raw.get("ListenerId") not in (None, "", item["ListenerId"]):
                        raise CollectionError("ListenerMismatch")
                    rid = identity(raw.get("LocationId"), "loc-")
                    if rid in seen:
                        raise CollectionError("DuplicateRule")
                    seen.add(rid)
                    rid = rule(graph, graph.nodes[lid], raw, source)
                    certificates(graph, graph.nodes[rid], raw, source)
                record["count"] += 1

        runner.scope("clb", "DescribeListeners", lb["region"], operation, lb["resource_id"])
