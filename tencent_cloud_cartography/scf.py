"""SCF version, alias, trigger and layer configuration without function code."""

import json
import math
import re
from urllib.parse import urlsplit, urlunsplit

from .catalog import SCF_DETAILS
from .model import stable_id
from .transport import CollectionError, pages

SUPPORTED_TRIGGER_TYPES = {"timer", "cos", "ckafka", "apigw", "http", "cmq"}


def text(value):
    if not isinstance(value, str) or not value or any(ord(c) < 32 for c in value):
        raise CollectionError("InvalidScfIdentity")
    return value


def retain(graph, nid, raw, fields):
    for field in fields:
        if field in raw and type(raw[field]) in (str, bool, int, float):
            graph.nodes[nid]["properties"][field] = raw[field]


def version(graph, fn, raw, source, status="enriched"):
    value = text(raw.get("Version"))
    if value != "$LATEST" and not value.isdigit():
        raise CollectionError("InvalidScfVersion")
    nid = graph.add(
        fn["account"],
        fn["region"],
        "scf.version",
        fn["resource_id"] + "/" + value,
        fn["name"] + ":" + value,
        source=source,
        status=status,
    )
    retain(graph, nid, raw, ("Version", "AddTime", "ModTime", "Status"))
    graph.edge(fn["id"], nid, "HAS_VERSION", source)
    return nid


def alias(graph, fn, raw, source):
    name, main = text(raw.get("Name")), text(raw.get("FunctionVersion"))
    routing = raw.get("RoutingConfig") or {}
    if not isinstance(routing, dict):
        raise CollectionError("InvalidAliasRouting")
    weights, matches = [], []
    seen = {main}
    for entry in routing.get("AdditionalVersionWeights") or []:
        value, weight = text(entry.get("Version")), entry.get("Weight")
        if (
            value in seen
            or type(weight) not in (int, float)
            or not math.isfinite(weight)
            or not 0 <= weight <= 1
        ):
            raise CollectionError("InvalidAliasRouting")
        seen.add(value)
        weights.append(dict(Version=value, Weight=weight))
    if sum(e["Weight"] for e in weights) > 1:
        raise CollectionError("InvalidAliasRouting")
    for entry in routing.get("AddtionVersionMatchs") or []:
        matches.append({k: text(entry.get(k)) for k in ("Version", "Key", "Method", "Expression")})
    for value in [main] + [e["Version"] for e in weights + matches]:
        if value != "$LATEST" and not value.isdigit():
            raise CollectionError("InvalidScfVersion")
    nid = graph.add(
        fn["account"],
        fn["region"],
        "scf.alias",
        fn["resource_id"] + "/" + name,
        fn["name"] + ":" + name,
        source=source,
    )
    retain(graph, nid, raw, ("Name", "FunctionVersion", "AddTime", "ModTime"))
    props = graph.nodes[nid]["properties"]
    props["weighted_versions"] = json.dumps(weights, sort_keys=True)
    props["matched_versions"] = json.dumps(matches, sort_keys=True)
    graph.edge(fn["id"], nid, "HAS_ALIAS", source)
    for value, relation in (
        [(main, "PRIMARY_VERSION")]
        + [(e["Version"], "WEIGHTED_VERSION") for e in weights]
        + [(e["Version"], "MATCHED_VERSION") for e in matches]
    ):
        vid = version(graph, fn, {"Version": value}, source, "reference")
        graph.edge(nid, vid, relation, source)
    return nid


def unique_object(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise CollectionError("DuplicateTriggerField")
        result[k] = v
    return result


def trigger_configuration(kind, value):
    if kind not in SUPPORTED_TRIGGER_TYPES:
        return {}
    if value in (None, ""):
        return {}
    if kind == "timer":
        return {"cron": text(value)}
    if not isinstance(value, str):
        raise CollectionError("InvalidTriggerConfiguration")
    raw = json.loads(value, object_pairs_hook=unique_object)
    if not isinstance(raw, dict):
        raise CollectionError("InvalidTriggerConfiguration")
    # Explicit fields only: CustomArgument and CKafka easConfig may carry payloads
    # or credentials. Never persist them or the unfiltered TriggerDesc string.
    paths = {
        "cos": ("event", "filter.Prefix", "filter.Suffix"),
        "ckafka": ("maxMsgNum", "offset", "retry", "timeOut", "consumerGroupName"),
        "apigw": (
            "api.authRequired",
            "api.isIntegratedResponse",
            "api.IsBase64Encoded",
            "api.requestConfig.method",
            "service.serviceId",
            "service.serviceName",
            "release.environmentName",
        ),
        "http": ("AuthType", "NetConfig.EnableIntranet", "NetConfig.EnableExtranet"),
        "cmq": ("filterType",),
    }.get(kind, ())
    result = {}
    for path in paths:
        current = raw
        for part in path.split("."):
            current = current.get(part) if isinstance(current, dict) else None
        if type(current) in (str, int, bool):
            result[path] = current
    if kind == "http":
        for key, value in (raw.get("NetConfig") or {}).items():
            if key not in {
                "IntranetUrl",
                "IntranetHTTPUrl",
                "ExtranetUrl",
                "ExtranetHTTPUrl",
                "WssIntranetUrl",
                "WsIntranetUrl",
                "WssExtranetUrl",
                "WsExtranetUrl",
            } or not isinstance(value, str):
                continue
            parsed = urlsplit(value)
            if (
                parsed.scheme in {"http", "https", "ws", "wss"}
                and parsed.hostname
                and not parsed.username
                and not parsed.password
            ):
                result["NetConfig." + key] = urlunsplit(
                    (parsed.scheme, parsed.netloc, parsed.path, "", "")
                )
    return result


def trigger(graph, fn, raw, source):
    name, kind = text(raw.get("TriggerName")), text(raw.get("Type")).lower()
    qualifier = raw.get("Qualifier") or ""
    if not isinstance(qualifier, str):
        raise CollectionError("InvalidScfIdentity")
    config = trigger_configuration(kind, raw.get("TriggerDesc"))
    # Qualifier and type are part of identity: trigger names may be reused.
    rid = stable_id(fn["resource_id"], kind, name, qualifier)
    nid = graph.add(fn["account"], fn["region"], "scf.trigger", rid, name, source=source)
    retain(
        graph,
        nid,
        raw,
        (
            "Enable",
            "Qualifier",
            "TriggerName",
            "Type",
            "AvailableStatus",
            "AddTime",
            "ModTime",
            "ResourceId",
            "BindStatus",
            "TriggerAttribute",
        ),
    )
    graph.nodes[nid]["properties"].update(
        trigger_type=kind,
        configuration=json.dumps(config, sort_keys=True),
        configuration_supported=kind in SUPPORTED_TRIGGER_TYPES,
    )
    if raw.get("Enable") in (0, 1):
        graph.nodes[nid]["properties"]["state"] = "enabled" if raw["Enable"] == 1 else "disabled"
    graph.edge(fn["id"], nid, "HAS_TRIGGER", source)
    if qualifier:
        if qualifier == "$LATEST" or qualifier.isdigit():
            target = version(graph, fn, {"Version": qualifier}, source, "reference")
        else:
            target = graph.add(
                fn["account"],
                fn["region"],
                "scf.alias",
                fn["resource_id"] + "/" + qualifier,
                fn["name"] + ":" + qualifier,
                source=source,
                status="reference",
            )
        graph.edge(nid, target, "CONFIGURED_TRIGGER_TARGET", source)
    return nid


def collect_rows(runner, key, region, params, add, detail, identity):
    spec = SCF_DETAILS[key]
    result = []

    def operation(record):
        seen = set()
        for rows, request_id in pages(runner.transport, spec, region, params):
            if request_id:
                record["request_ids"].append(request_id)
            for row in rows:
                rid = identity(row)
                if rid in seen:
                    raise CollectionError("DuplicateScfResource")
                nid = add(row, "scf." + spec.action)
                seen.add(rid)
                result.append(nid)
                record["count"] += 1

    runner.scope("scf", spec.action, region, operation, detail)
    return result


def collect_function(runner, fid, raw):
    fn = runner.graph.nodes[fid]
    retain(
        runner.graph,
        fid,
        raw,
        (
            "Type",
            "AddTime",
            "ModTime",
            "AsyncRunEnable",
            "TraceEnable",
            "ReservedConcurrencyMem",
            "TotalProvisionedConcurrencyMem",
        ),
    )
    params = dict(FunctionName=raw["FunctionName"], Namespace=raw["Namespace"])
    for key, add, identity in [
        ("version", version, lambda r: r.get("Version")),
        ("alias", alias, lambda r: r.get("Name")),
        (
            "trigger",
            trigger,
            lambda r: (r.get("Type"), r.get("TriggerName"), r.get("Qualifier") or ""),
        ),
    ]:
        collect_rows(
            runner,
            key,
            fn["region"],
            params,
            lambda row, src: add(runner.graph, fn, row, src),
            fn["resource_id"],
            identity,
        )


def layer_version(graph, account, region, raw, source, expected=None):
    name = text(raw.get("LayerName"))
    value = raw.get("LayerVersion")
    if expected is not None and name != expected:
        raise CollectionError("ScfLayerMismatch")
    if type(value) is not int or value <= 0:
        raise CollectionError("InvalidLayerVersion")
    runtimes = raw.get("CompatibleRuntimes") or []
    if not isinstance(runtimes, list) or not all(isinstance(r, str) for r in runtimes):
        raise CollectionError("InvalidResponse")
    lid = graph.add(account, region, "scf.layer", name, name, source=source)
    vid = graph.add(
        account, region, "scf.layerversion", f"{name}/{value}", f"{name}:{value}", source=source
    )
    retain(graph, vid, raw, ("LayerName", "LayerVersion", "AddTime", "LicenseInfo", "Status"))
    graph.nodes[vid]["properties"]["compatible_runtimes"] = json.dumps(runtimes)
    graph.edge(lid, vid, "HAS_VERSION", source)
    return lid


def collect_layers(runner, region):
    layers = collect_rows(
        runner,
        "layer",
        region,
        {},
        lambda row, src: layer_version(runner.graph, runner.account, region, row, src),
        "",
        lambda r: r.get("LayerName"),
    )
    for lid in layers:
        name = runner.graph.nodes[lid]["resource_id"]
        collect_rows(
            runner,
            "layerversion",
            region,
            {"LayerName": name},
            lambda row, src: layer_version(runner.graph, runner.account, region, row, src, name),
            name,
            lambda r: r.get("LayerVersion"),
        )


def link_trigger_sources(graph):
    for node in list(graph.nodes.values()):
        if node["kind"] != "scf.trigger":
            continue
        props = node["properties"]
        kind = props["trigger_type"]
        name = props["TriggerName"]
        config = json.loads(props["configuration"])
        resource = None
        if kind == "cos":
            match = re.fullmatch(
                r"([a-z0-9][a-z0-9-]+-\d+)\.cos\.([a-z]+-[a-z0-9-]+)\.myqcloud\.com", name
            )
            if match:
                resource = ("cos.bucket", match[1], match[2])
        elif kind == "ckafka":
            match = re.fullmatch(r"(ckafka-[a-z0-9]+)-(.+)", name)
            if match:
                resource = ("ckafka.instance", match[1], node["region"])
                props["topic_name"] = match[2]
        elif kind == "apigw" and isinstance(config.get("service.serviceId"), str):
            resource = ("apigateway.service", config["service.serviceId"], node["region"])
        if resource:
            matches = [
                n
                for n in graph.nodes.values()
                if (n["kind"], n["resource_id"], n["region"]) == resource
                and n["account"] == node["account"]
            ]
            for match in matches:
                graph.edge(
                    match["id"],
                    node["id"],
                    "CONFIGURED_EVENT_SOURCE",
                    "SCF trigger configuration + collected resource",
                )
            props["event_source_resolved"] = bool(matches)

            if kind == "ckafka":
                parents = {n["id"] for n in matches if n["status"] == "enriched"}
                topics = [
                    n
                    for n in graph.nodes.values()
                    if n["kind"] == "ckafka.topic"
                    and n["status"] == "enriched"
                    and n["account"] == node["account"]
                    and n["region"] == node["region"]
                    and n["name"] == props["topic_name"]
                    and any(
                        e["source"] in parents
                        and e["target"] == n["id"]
                        and e["relationship"] == "HAS_TOPIC"
                        for e in graph.edges.values()
                    )
                ]
                props["event_topic_resolved"] = len(topics) == 1
                if len(topics) == 1:
                    graph.edge(
                        topics[0]["id"],
                        node["id"],
                        "CONFIGURED_EVENT_SOURCE",
                        "SCF trigger configuration + collected Kafka topic",
                    )
