"""API Gateway configuration and explicit deployment/backend relationships."""

from urllib.parse import urlsplit, urlunsplit
import json

from .catalog import GATEWAY_CHILDREN
from .transport import CollectionError, pages


def identity(value):
    if not isinstance(value, str) or not value or any(ord(c) < 32 for c in value):
        raise CollectionError("InvalidGatewayIdentity")
    return value


def retain(node, raw, fields):
    for key in fields:
        if key in raw and type(raw[key]) in (str, int, bool):
            node["properties"][key] = raw[key]


def endpoint(value):
    if not isinstance(value, str) or not value:
        return ""
    p = urlsplit(value if "://" in value else "//" + value)
    if (
        p.username
        or p.password
        or not p.hostname
        or p.scheme not in ("", "http", "https", "ws", "wss")
    ):
        return ""
    return urlunsplit((p.scheme, p.netloc, p.path, "", "")).removeprefix("//")


def node(graph, service, kind, value, name=None, status="enriched"):
    value = identity(value)
    return graph.add(
        service["account"],
        service["region"],
        "apigateway." + kind,
        service["resource_id"] + "/" + value,
        name or value,
        source="apigateway configuration",
        status=status,
    )


def release(graph, service, raw, status="enriched"):
    nid = node(graph, service, "release", raw.get("VersionName"), status=status)
    retain(graph.nodes[nid], raw, ("VersionName",))
    graph.edge(service["id"], nid, "HAS_RELEASE", "apigateway release metadata")
    return nid


def environment(graph, service, raw, status="enriched"):
    nid = node(graph, service, "environment", raw.get("EnvironmentName"), status=status)
    retain(graph.nodes[nid], raw, ("EnvironmentName", "Status", "VersionName", "CreateTime"))
    if raw.get("Url"):
        graph.nodes[nid]["properties"]["Url"] = endpoint(raw["Url"])
    graph.edge(service["id"], nid, "HAS_ENVIRONMENT", "apigateway environment metadata")
    if raw.get("Status") == 1 and raw.get("VersionName"):
        rid = release(graph, service, {"VersionName": raw["VersionName"]}, "reference")
        graph.edge(nid, rid, "DEPLOYS_RELEASE", "apigateway environment Status=1")
    return nid


def domain(graph, service, raw):
    nid = node(graph, service, "domain", raw.get("DomainName"))
    retain(
        graph.nodes[nid],
        raw,
        (
            "DomainName",
            "Status",
            "CertificateId",
            "IsDefaultMapping",
            "Protocol",
            "NetType",
            "IsForcedHttps",
            "RegistrationStatus",
        ),
    )
    graph.edge(service["id"], nid, "HAS_DOMAIN", "apigateway.DescribeServiceSubDomains")
    if raw.get("CertificateId"):
        cid = graph.add(
            service["account"],
            "global",
            "ssl.certificate",
            identity(raw["CertificateId"]),
            source="apigateway.DescribeServiceSubDomains",
            status="reference",
        )
        graph.edge(nid, cid, "CONFIGURED_CERTIFICATE", "apigateway.DescribeServiceSubDomains")
    return nid


def api(graph, service, raw, detail=False):
    if raw.get("ServiceId") != service["resource_id"]:
        raise CollectionError("GatewayServiceMismatch")
    aid = identity(raw.get("ApiId"))
    nid = node(graph, service, "api", aid, raw.get("ApiName") or aid)
    retain(
        graph.nodes[nid],
        raw,
        (
            "ApiId",
            "ServiceId",
            "ApiName",
            "ApiType",
            "Protocol",
            "AuthType",
            "ApiBusinessType",
            "AuthRelationApiId",
            "CreatedTime",
            "ModifiedTime",
            "Method",
            "Path",
            "ServiceType",
            "ServiceTimeout",
            "EnableCORS",
            "ServiceScfIsIntegratedResponse",
            "ServiceScfEventIsAsyncCall",
            "IsBase64Encoded",
            "IsBase64Trigger",
        ),
    )
    props = graph.nodes[nid]["properties"]
    props.setdefault("detail_collected", False)
    graph.edge(service["id"], nid, "HAS_API", "apigateway API metadata")
    if not detail:
        return nid
    request = raw.get("RequestConfig") or {}
    for key in ("Path", "Method"):
        if isinstance(request.get(key), str):
            props[key] = request[key]
    if (
        raw.get("AuthType") == "OAUTH"
        and raw.get("ApiBusinessType") == "NORMAL"
        and raw.get("AuthRelationApiId")
    ):
        auth = node(graph, service, "api", raw["AuthRelationApiId"], status="reference")
        graph.edge(nid, auth, "CONFIGURED_AUTHORIZER", "apigateway.DescribeApi")
    environments = raw.get("Environments") or []
    if not isinstance(environments, list) or not all(isinstance(e, str) for e in environments):
        raise CollectionError("InvalidResponse")
    for name in environments:
        eid = environment(graph, service, {"EnvironmentName": name}, "reference")
        graph.edge(nid, eid, "LISTED_IN_ENVIRONMENT", "apigateway.DescribeApi.Environments")
        if graph.nodes[eid]["properties"].get("Status") == 0:
            props["deployment_state_conflict"] = True
    config = raw.get("ServiceConfig") or {}
    if not isinstance(config, dict):
        raise CollectionError("InvalidResponse")
    backend = raw.get("ServiceType")
    if not backend:
        props["detail_collected"] = True
        return nid
    roles = [("backend", "ServiceScfFunction")]
    if backend == "SCF" and str(raw.get("Protocol", "")).upper() == "WEBSOCKET":
        roles += [
            (role, "ServiceWebsocket" + role.title() + "Function")
            for role in ("register", "cleanup", "transport")
        ]
    for role, prefix in roles:
        if role != "backend" and not raw.get(prefix + "Name"):
            continue
        iid = node(
            graph,
            service,
            "integration",
            aid + "/" + role,
            (raw.get("ApiName") or aid) + " · " + role,
        )
        ip = graph.nodes[iid]["properties"]
        ip.update(ServiceType=backend, integration_role=role)
        graph.edge(nid, iid, "HAS_INTEGRATION", "apigateway.DescribeApi")
        if backend == "SCF":
            for suffix, key in [
                ("Name", "scf_name"),
                ("Namespace", "scf_namespace"),
                ("Qualifier", "scf_qualifier"),
            ]:
                if isinstance(raw.get(prefix + suffix), str):
                    ip[key] = raw[prefix + suffix]
        else:
            retain(
                graph.nodes[iid], config, ("Product", "UniqVpcId", "Path", "Method", "UpstreamId")
            )
            if config.get("Url"):
                ip["Url"] = endpoint(config["Url"])
            if isinstance(config.get("UniqVpcId"), str) and config["UniqVpcId"].startswith("vpc-"):
                vid = graph.add(
                    service["account"],
                    service["region"],
                    "vpc.vpc",
                    config["UniqVpcId"],
                    status="reference",
                )
                graph.edge(iid, vid, "BACKEND_VPC", "apigateway.DescribeApi.ServiceConfig")
            if backend == "COS":
                cos = config.get("CosConfig") or {}
                for field in ("Action", "BucketName", "Authorization", "PathMatchMode"):
                    if type(cos.get(field)) in (str, bool):
                        ip["cos_" + field] = cos[field]
    props["detail_collected"] = True
    return nid


def collect_service(runner, sid):
    graph = runner.graph
    service = graph.nodes[sid]
    region = service["region"]
    service_id = service["resource_id"]

    def detail_scope(action, params, apply, detail):
        def operation(record):
            raw = runner.transport.call("apigateway", action, region=region, **params)
            if raw.get("RequestId"):
                record["request_ids"].append(raw["RequestId"])
            apply(raw)
            record["count"] = 1

        runner.scope("apigateway", action, region, operation, detail)

    def service_detail(raw):
        if raw.get("ServiceId") != service_id:
            raise CollectionError("GatewayServiceMismatch")
        retain(
            service,
            raw,
            (
                "Protocol",
                "CreatedTime",
                "ModifiedTime",
                "InternalSubDomain",
                "OuterSubDomain",
                "InnerHttpPort",
                "InnerHttpsPort",
                "IpVersion",
                "InstanceId",
                "InstanceName",
                "DeploymentType",
                "UniqVpcId",
            ),
        )
        if raw.get("NetTypes") is not None:
            if not isinstance(raw["NetTypes"], list) or not all(
                isinstance(v, str) for v in raw["NetTypes"]
            ):
                raise CollectionError("InvalidResponse")
            service["properties"]["NetTypes"] = json.dumps(raw["NetTypes"])
        vpc = raw.get("UniqVpcId")
        if isinstance(vpc, str) and vpc.startswith("vpc-"):
            vid = graph.add(service["account"], region, "vpc.vpc", vpc, status="reference")
            graph.edge(sid, vid, "IN_VPC", "apigateway.DescribeService")

    detail_scope("DescribeService", {"ServiceId": service_id}, service_detail, service_id)
    for key, add in [
        ("release", release),
        ("environment", environment),
        ("domain", domain),
        ("api", api),
    ]:
        spec = GATEWAY_CHILDREN[key]
        collected = []

        def operation(record):
            seen = set()
            for rows, request_id in pages(
                runner.transport, spec, region, {"ServiceId": service_id}
            ):
                if request_id:
                    record["request_ids"].append(request_id)
                for row in rows:
                    rid = row.get(spec.ids[0])
                    if rid in seen:
                        raise CollectionError("DuplicateGatewayResource")
                    nid = add(graph, service, row)
                    seen.add(rid)
                    collected.append(nid)
                    record["count"] += 1

        runner.scope("apigateway", spec.action, region, operation, service_id)
        if key == "api":
            for nid in collected:
                aid = graph.nodes[nid]["properties"]["ApiId"]

                def add_detail(response, aid=aid):
                    raw = response.get("Result")
                    if not isinstance(raw, dict) or raw.get("ApiId") != aid:
                        raise CollectionError("GatewayApiMismatch")
                    api(graph, service, raw, True)

                detail_scope(
                    "DescribeApi",
                    {"ServiceId": service_id, "ApiId": aid},
                    add_detail,
                    service_id + "/" + aid,
                )


def link_backends(graph):
    for integration in list(graph.nodes.values()):
        if integration["kind"] != "apigateway.integration":
            continue
        p = integration["properties"]
        targets = []
        if p["ServiceType"] == "SCF" and p.get("scf_name") and p.get("scf_namespace"):
            targets = [
                n
                for n in graph.nodes.values()
                if n["kind"] == "scf.function"
                and n["account"] == integration["account"]
                and n["region"] == integration["region"]
                and n["name"] == p["scf_name"]
                and n["properties"].get("Namespace") == p["scf_namespace"]
            ]
            # Do not resolve a name when multiple function identities claim it.
            if len(targets) != 1:
                targets = []
            for fn in targets:
                graph.edge(
                    integration["id"],
                    fn["id"],
                    "CONFIGURED_SCF_BACKEND",
                    "API configuration + collected function identity",
                )
                qualifier = p.get("scf_qualifier")
                if qualifier:
                    kind = (
                        "scf.version"
                        if qualifier == "$LATEST" or qualifier.isdigit()
                        else "scf.alias"
                    )
                    qid = graph.add(
                        fn["account"],
                        fn["region"],
                        kind,
                        fn["resource_id"] + "/" + qualifier,
                        fn["name"] + ":" + qualifier,
                        status="reference",
                    )
                    graph.edge(
                        integration["id"], qid, "CONFIGURED_QUALIFIER", "apigateway.DescribeApi"
                    )
        elif p["ServiceType"] == "COS" and p.get("cos_BucketName"):
            targets = [
                n
                for n in graph.nodes.values()
                if n["kind"] == "cos.bucket"
                and n["account"] == integration["account"]
                and n["region"] == integration["region"]
                and n["resource_id"] == p["cos_BucketName"]
            ]
            for bucket in targets:
                graph.edge(
                    integration["id"],
                    bucket["id"],
                    "CONFIGURED_COS_BACKEND",
                    "API configuration + collected bucket identity",
                )
        if p["ServiceType"] in ("SCF", "COS"):
            p["backend_resolved"] = bool(targets)
