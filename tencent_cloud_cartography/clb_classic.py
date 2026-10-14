"""Traditional CLB listener-wide backend configuration and reported health."""

import ipaddress
import json

from .clb import certificates, identity, listener
from .transport import CollectionError
from .vpc import fields


def collect(runner, lb):
    graph = runner.graph
    listeners = []
    targets = []

    def read(action, result, prepare, selected):
        def operation(record):
            data = runner.transport.call(
                "clb", action, lb["region"], LoadBalancerId=lb["resource_id"]
            )
            if data.get("RequestId"):
                record["request_ids"].append(data["RequestId"])
            batch = data.get(result)
            if not isinstance(batch, list):
                raise CollectionError("InvalidClassicClbResponse")
            prepared = [prepare(row) for row in batch]
            ids = [p[0] for p in prepared]
            if len(set(ids)) != len(ids):
                raise CollectionError("DuplicateClassicClbIdentity")
            selected.extend(prepared)
            record["count"] = len(prepared)

        runner.scope("clb", action, lb["region"], operation, lb["resource_id"])

    def frontend(raw):
        rid = identity(raw.get("ListenerId"), "lbl-")
        props = fields(
            raw,
            (
                "ListenerName",
                "Protocol",
                "HttpHash",
                "SSLMode",
                "CertId",
                "CertCaId",
                "HttpCheckPath",
            ),
            integers=(
                "ListenerPort",
                "InstancePort",
                "SessionExpire",
                "HealthSwitch",
                "TimeOut",
                "IntervalTime",
                "HealthNum",
                "UnhealthNum",
                "HttpCode",
                "Status",
            ),
        )
        if props.get("HttpCheckPath"):
            props["HttpCheckPath"] = props["HttpCheckPath"].split("?")[0].split("#")[0]
        return rid, props

    def backend(raw):
        rid = identity(raw.get("InstanceId"), "ins-")
        props = fields(raw, ("Type", "InstanceName"), integers=("Weight", "RunFlag"))
        ips = raw.get("PrivateIpAddresses")
        if not isinstance(ips, list):
            raise CollectionError("InvalidClassicClbBackendAddress")
        props["addresses"] = json.dumps([str(ipaddress.ip_address(ip)) for ip in ips])
        return rid, props

    read("DescribeClassicalLBListeners", "Listeners", frontend, listeners)
    read("DescribeClassicalLBTargets", "Targets", backend, targets)
    for lid, meta in listeners:
        nid = listener(
            graph,
            lb,
            dict(
                ListenerId=lid,
                ListenerName=meta.get("ListenerName"),
                Protocol=meta.get("Protocol"),
                Port=meta.get("ListenerPort"),
            ),
            "clb.DescribeClassicalLBListeners",
        )
        graph.nodes[nid]["properties"].update(meta, clb_generation="traditional")
        certificates(
            graph,
            graph.nodes[nid],
            dict(
                Certificate=dict(
                    SSLMode=meta.get("SSLMode"),
                    CertId=meta.get("CertId"),
                    CertCaId=meta.get("CertCaId"),
                )
            ),
            "clb.DescribeClassicalLBListeners",
        )
        bindings = []
        for tid, props in targets:
            bid = graph.add(
                runner.account,
                lb["region"],
                "clb.targetbinding",
                lb["resource_id"] + "/" + lid + "/" + tid,
                props.get("InstanceName"),
                source="clb.DescribeClassicalLBTargets",
            )
            graph.nodes[bid]["properties"].update(
                props,
                InstanceId=tid,
                Port=meta.get("InstancePort"),
                ListenerId=lid,
                LoadBalancerId=lb["resource_id"],
                clb_generation="traditional",
            )
            graph.edge(nid, bid, "HAS_BACKEND", "clb.DescribeClassicalLBTargets")
            if props.get("Type") == "CVM":
                target = graph.add(
                    runner.account, lb["region"], "cvm.instance", tid, status="reference"
                )
                graph.edge(bid, target, "FORWARDS_TO", "clb.DescribeClassicalLBTargets")
            bindings.append(bid)

        def health(record, lid=lid, meta=meta, bindings=bindings):
            data = runner.transport.call(
                "clb",
                "DescribeClassicalLBHealthStatus",
                lb["region"],
                LoadBalancerId=lb["resource_id"],
                ListenerId=lid,
            )
            if data.get("RequestId"):
                record["request_ids"].append(data["RequestId"])
            batch = data.get("HealthList")
            if not isinstance(batch, list):
                raise CollectionError("InvalidClassicClbHealth")
            prepared = []
            for raw in batch:
                props = fields(
                    raw, ("IP", "Protocol"), integers=("Port", "ListenerPort", "HealthStatus")
                )
                ipaddress.ip_address(props.get("IP"))
                matches = [
                    bid
                    for bid in bindings
                    if props["IP"] in json.loads(graph.nodes[bid]["properties"]["addresses"])
                    and props.get("Port") == meta.get("InstancePort")
                    and props.get("ListenerPort") == meta.get("ListenerPort")
                    and props.get("Protocol") == meta.get("Protocol")
                ]
                if len(matches) != 1:
                    raise CollectionError("UnresolvedClassicClbHealth")
                prepared.append((matches[0], props))
            if len({bid for bid, _ in prepared}) != len(prepared):
                raise CollectionError("DuplicateClassicClbHealth")
            for bid, props in prepared:
                graph.nodes[bid]["properties"].update(
                    reported_health=props["HealthStatus"], reachability_verified=False
                )
                record["count"] += 1

        runner.scope(
            "clb",
            "DescribeClassicalLBHealthStatus",
            lb["region"],
            health,
            lb["resource_id"] + "/" + lid,
        )
