"""Native CLB backend identity, including non-CVM and SCF configuration."""

import json

from .clb import identity
from .model import stable_id
from .network_addresses import ip
from .transport import CollectionError
from .vpc import fields

SOURCE = "clb.DescribeTargets"


def array(raw, key):
    value = raw.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(v, dict) for v in value):
        raise CollectionError("InvalidClbBackendArray")
    return value


def backend(raw):
    props = fields(
        raw,
        ("Type", "InstanceId", "EniId", "InstanceName", "RegisteredTime", "Zone", "Tag"),
        integers=("Port", "Weight"),
    )
    identity(props.get("InstanceId"))
    if "Port" not in props or props["Port"] > 65535 or not props.get("Type"):
        raise CollectionError("InvalidClbBackend")
    for key, name in (
        ("PrivateIpAddresses", "private_addresses"),
        ("PublicIpAddresses", "public_addresses"),
    ):
        values = raw.get(key) or []
        if not isinstance(values, list):
            raise CollectionError("InvalidClbBackendAddress")
        props[name] = json.dumps([ip(value) for value in values])
    return props


def function(raw):
    props = fields(
        raw.get("Function"),
        ("FunctionNamespace", "FunctionName", "FunctionQualifier", "FunctionQualifierType"),
    )
    for key in ("FunctionNamespace", "FunctionName", "FunctionQualifier"):
        identity(props.get(key))
    if props.get("FunctionQualifierType") not in (None, "VERSION", "ALIAS"):
        raise CollectionError("InvalidClbFunctionQualifier")
    props.update(fields(raw, integers=("Weight",)))
    return props


def collect(runner, lb):
    graph = runner.graph
    listeners = [
        graph.nodes[e["target"]]
        for e in list(graph.edges.values())
        if e["source"] == lb["id"] and e["relationship"] == "HAS_LISTENER"
    ]
    for listener in listeners:
        lid = listener["properties"].get("ListenerId")
        if not lid:
            continue

        def operation(record, listener=listener, lid=lid):
            response = runner.transport.call(
                "clb",
                "DescribeTargets",
                lb["region"],
                LoadBalancerId=lb["resource_id"],
                ListenerIds=[lid],
            )
            if response.get("RequestId"):
                record["request_ids"].append(response["RequestId"])
            rows = response.get("Listeners")
            if not isinstance(rows, list) or len(rows) > 1:
                raise CollectionError("ClbBackendListenerMismatch")
            prepared, seen = [], set()
            for row in rows:
                if row.get("ListenerId") != lid:
                    raise CollectionError("ClbBackendListenerMismatch")
                scopes = [(listener["id"], row)]
                for rule in array(row, "Rules"):
                    location = identity(rule.get("LocationId"), "loc-")
                    rid = listener["resource_id"] + "/" + location
                    parent = stable_id(lb["account"], lb["region"], "clb.rule", rid)
                    if parent not in graph.nodes or not any(
                        e["source"] == listener["id"]
                        and e["target"] == parent
                        and e["relationship"] == "HAS_RULE"
                        for e in graph.edges.values()
                    ):
                        raise CollectionError("UncollectedClbBackendRule")
                    scopes.append((parent, rule))
                for parent, scope in scopes:
                    for key, prepare, kind in (
                        ("Targets", backend, "clb.targetbinding"),
                        ("FunctionTargets", function, "clb.functiontarget"),
                    ):
                        for raw in array(scope, key):
                            if key == "FunctionTargets" and (
                                graph.nodes[parent]["kind"] != "clb.rule"
                                or listener["properties"].get("Protocol") not in {"HTTP", "HTTPS"}
                            ):
                                raise CollectionError("InvalidClbFunctionFrontend")
                            props = prepare(raw)
                            rid = stable_id(
                                parent,
                                props.get("InstanceId"),
                                props.get("EniId"),
                                props.get("Port"),
                                props.get("FunctionNamespace"),
                                props.get("FunctionName"),
                                props.get("FunctionQualifier"),
                            )
                            if rid in seen:
                                raise CollectionError("DuplicateClbBackend")
                            seen.add(rid)
                            prepared.append((rid, kind, parent, props))
            # Validate the full unpaginated listener response before mutation.
            for rid, kind, parent, props in prepared:
                nid = graph.add(
                    lb["account"],
                    lb["region"],
                    kind,
                    rid,
                    props.get("InstanceName")
                    or props.get("FunctionName")
                    or props.get("InstanceId"),
                    source=SOURCE,
                )
                graph.nodes[nid]["properties"].update(
                    props,
                    LoadBalancerId=lb["resource_id"],
                    ListenerId=lid,
                    reachability_verified=False,
                )
                graph.edge(parent, nid, "HAS_BACKEND", SOURCE)
                if kind == "clb.targetbinding":
                    mapping = {
                        "CVM": ("cvm.instance", "ins-"),
                        "ENI": ("vpc.networkinterface", "eni-"),
                        "NAT": ("vpc.nat", "nat-"),
                    }
                    mapped = mapping.get(props["Type"])
                    target_id = (
                        props.get("EniId") or props["InstanceId"]
                        if props["Type"] == "ENI"
                        else props["InstanceId"]
                    )
                    if mapped and target_id.startswith(mapped[1]):
                        target = graph.add(
                            lb["account"],
                            lb["region"],
                            mapped[0],
                            identity(target_id, mapped[1]),
                            status="reference",
                        )
                        graph.edge(nid, target, "FORWARDS_TO", SOURCE)
                record["count"] += 1

        runner.scope("clb", "DescribeTargets", lb["region"], operation, listener["resource_id"])


def link_functions(graph):
    functions = {}
    for node in graph.nodes.values():
        if node["kind"] == "scf.function" and node["status"] == "enriched":
            functions.setdefault(
                (
                    node["account"],
                    node["region"],
                    node["properties"].get("Namespace"),
                    node["name"],
                ),
                [],
            ).append(node)
    for node in list(graph.nodes.values()):
        if node["kind"] != "clb.functiontarget" or node["status"] != "enriched":
            continue
        p = node["properties"]
        matches = functions.get(
            (node["account"], node["region"], p.get("FunctionNamespace"), p.get("FunctionName")), ()
        )
        p["function_resolution"] = (
            "matched-collected-function"
            if len(matches) == 1
            else "ambiguous"
            if matches
            else "uncollected"
        )
        if len(matches) == 1:
            graph.edge(node["id"], matches[0]["id"], "FORWARDS_TO", "network.corroboration")
        else:
            from .network_parity import issue

            issue(graph, node, "UnresolvedClbFunctionTarget")
