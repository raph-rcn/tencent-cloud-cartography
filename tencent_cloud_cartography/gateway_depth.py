"""Gateway mappings and metadata backend resolution; no destination probes."""

import ipaddress
import json

from .model import stable_id
from .transport import CollectionError
from .vpc import fields


def mappings(graph, service, domain, raw):
    data = raw.get("Result")
    if not isinstance(data, dict) or type(data.get("IsDefaultMapping")) is not bool:
        raise CollectionError("InvalidGatewayMapping")
    rows = data.get("PathMappingSet")
    if rows is None and data["IsDefaultMapping"]:
        rows = []
    if not isinstance(rows, list):
        raise CollectionError("InvalidGatewayMapping")
    prepared = [fields(r, ("Path", "Environment")) for r in rows]
    for p in prepared:
        if (
            not p.get("Path", "").startswith("/")
            or "?" in p["Path"]
            or "#" in p["Path"]
            or any(ord(c) < 32 for c in p["Path"])
            or p.get("Environment") not in ("test", "prepub", "release")
        ):
            raise CollectionError("InvalidGatewayMapping")
    if len({p["Path"] for p in prepared}) != len(prepared):
        raise CollectionError("DuplicateGatewayMapping")
    from .gateway import environment

    for p in prepared:
        nid = graph.add(
            service["account"],
            service["region"],
            "apigateway.pathmapping",
            domain["resource_id"] + "/" + stable_id(p["Path"]),
            p["Path"],
            source="apigateway.DescribeServiceSubDomainMappings",
        )
        graph.nodes[nid]["properties"].update(p, routing_verified=False)
        graph.edge(
            domain["id"], nid, "HAS_PATH_MAPPING", "apigateway.DescribeServiceSubDomainMappings"
        )
        eid = environment(graph, service, {"EnvironmentName": p["Environment"]}, "reference")
        graph.edge(nid, eid, "MAPS_TO_ENVIRONMENT", "apigateway.DescribeServiceSubDomainMappings")
    domain["properties"].update(IsDefaultMapping=data["IsDefaultMapping"], mappings_collected=True)


def tsf(graph, integration, raw):
    p = integration["properties"]
    for key, strings, bools, nums in (
        (
            "ServiceTsfLoadBalanceConf",
            ("Method",),
            ("IsLoadBalance", "SessionStickRequired"),
            ("SessionStickTimeout",),
        ),
        (
            "ServiceTsfHealthCheckConf",
            (),
            ("IsHealthCheck",),
            ("RequestVolumeThreshold", "SleepWindowInMilliseconds", "ErrorThresholdPercentage"),
        ),
    ):
        if raw.get(key) is not None:
            p[key] = json.dumps(fields(raw[key], strings, bools, nums), sort_keys=True)
    rows = raw.get("MicroServices") or []
    if not isinstance(rows, list):
        raise CollectionError("InvalidGatewayMicroservices")
    prepared = [fields(r, ("ClusterId", "NamespaceId", "MicroServiceName")) for r in rows]
    if any(
        not all(r.get(k) for k in ("ClusterId", "NamespaceId", "MicroServiceName"))
        for r in prepared
    ):
        raise CollectionError("InvalidGatewayMicroservices")
    if len({tuple(sorted(r.items())) for r in prepared}) != len(prepared):
        raise CollectionError("DuplicateGatewayMicroservice")
    for r in prepared:
        nid = graph.add(
            integration["account"],
            integration["region"],
            "apigateway.microservice",
            stable_id(r["ClusterId"], r["NamespaceId"], r["MicroServiceName"]),
            r["MicroServiceName"],
            source="apigateway.DescribeApi",
        )
        graph.nodes[nid]["properties"].update(r, backend_resolved=False)
        graph.edge(
            integration["id"], nid, "CONFIGURED_TSF_BACKEND", "apigateway.DescribeApi.MicroServices"
        )


def http_backend(graph, integration):
    from urllib.parse import urlsplit

    p = integration["properties"]
    p["backend_resolved"] = False
    if p.get("Product") == "upstream" and p.get("UpstreamId"):
        nid = graph.add(
            integration["account"],
            integration["region"],
            "apigateway.upstream",
            p["UpstreamId"],
            source="apigateway.DescribeApi",
            status="reference",
        )
        graph.nodes[nid]["properties"].update(
            detail_collected=False, metadata_projection_supported=False
        )
        graph.edge(
            integration["id"], nid, "CONFIGURED_UPSTREAM", "apigateway.ServiceConfig.UpstreamId"
        )
        return
    kind = {"cvm": "cvm.instance", "clb": "clb.clb"}.get(p.get("Product"))
    if not kind or not p.get("UniqVpcId") or not p.get("Url"):
        return
    try:
        host = str(
            ipaddress.ip_address(
                urlsplit(p["Url"] if "://" in p["Url"] else "//" + p["Url"]).hostname
            )
        )
    except ValueError:
        return
    candidates = []
    for n in graph.nodes.values():
        if (
            n["kind"] != kind
            or n["account"] != integration["account"]
            or n["region"] != integration["region"]
            or n["status"] != "enriched"
        ):
            continue
        addresses = set()
        for value in n["properties"].get("ip_addresses", "").split(", "):
            try:
                addresses.add(str(ipaddress.ip_address(value)))
            except ValueError:
                continue
        if host not in addresses:
            continue
        vpcs = {
            graph.nodes[e["target"]]["resource_id"]
            for e in graph.edges.values()
            if e["source"] == n["id"]
            and e["relationship"] == "IN_VPC"
            and graph.nodes[e["target"]]["kind"] == "vpc.vpc"
        }
        if vpcs == {p["UniqVpcId"]}:
            candidates.append(n)
    if len(candidates) == 1:
        graph.edge(
            integration["id"],
            candidates[0]["id"],
            "CONFIGURED_HTTP_BACKEND",
            "API product/VPC/address + unique collected backend",
        )
        p["backend_resolved"] = True


def collect_upstream_bindings(runner, service):
    import re

    from .catalog import Collector
    from .transport import pages

    refs = {
        n["properties"].get("UpstreamId")
        for n in runner.graph.nodes.values()
        if n["kind"] == "apigateway.integration"
        and n["account"] == service["account"]
        and n["region"] == service["region"]
        and n["resource_id"].startswith(service["resource_id"] + "/")
    }
    for upstream in sorted(r for r in refs if r):
        action = "DescribeUpstreamBindApis"
        if any(
            r["account"] == runner.account
            and r["region"] == service["region"]
            and r["action"] == action
            and r["detail"] == upstream
            for r in runner.graph.coverage
        ):
            continue

        def operation(record, upstream=upstream):
            if not re.fullmatch(r"[A-Za-z0-9-]+", upstream):
                raise CollectionError("InvalidGatewayUpstream")
            spec = Collector(
                "apigateway",
                action,
                "Result.BindApiSet",
                "apigateway.upstreambinding",
                ("ApiId",),
                total="Result.TotalCount",
                require_total=True,
            )
            seen = set()
            for rows, request in pages(
                runner.transport, spec, service["region"], {"UpstreamId": upstream}
            ):
                if request:
                    record["request_ids"].append(request)
                prepared = [
                    fields(r, ("ServiceId", "ApiId", "ApiName", "ServiceName", "BindTime"))
                    for r in rows
                ]
                keys = [(p.get("ServiceId"), p.get("ApiId")) for p in prepared]
                if (
                    any(
                        not all(
                            isinstance(v, str) and re.fullmatch(r"[A-Za-z0-9-]+", v) for v in key
                        )
                        for key in keys
                    )
                    or len(set(keys)) != len(keys)
                    or seen.intersection(keys)
                ):
                    raise CollectionError("InvalidGatewayUpstreamBinding")
                seen.update(keys)
                uid = runner.graph.add(
                    runner.account,
                    service["region"],
                    "apigateway.upstream",
                    upstream,
                    source="apigateway." + action,
                    status="reference",
                )
                runner.graph.nodes[uid]["properties"]["bindings_collected"] = True
                for p in prepared:
                    aid = runner.graph.add(
                        runner.account,
                        service["region"],
                        "apigateway.api",
                        p["ServiceId"] + "/" + p["ApiId"],
                        p.get("ApiName"),
                        source="apigateway." + action,
                        status="reference",
                    )
                    bid = runner.graph.add(
                        runner.account,
                        service["region"],
                        "apigateway.upstreambinding",
                        upstream + "/" + p["ServiceId"] + "/" + p["ApiId"],
                        source="apigateway." + action,
                    )
                    runner.graph.nodes[bid]["properties"].update(
                        p, UpstreamId=upstream, routing_verified=False
                    )
                    runner.graph.edge(aid, bid, "HAS_UPSTREAM_BINDING", "apigateway." + action)
                    runner.graph.edge(bid, uid, "BINDS_UPSTREAM", "apigateway." + action)
                    record["count"] += 1

        runner.scope("apigateway", action, service["region"], operation, upstream)
