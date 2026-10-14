"""TKE cluster metadata, authentication, public CA details and explicit access mappings."""

import base64
import ipaddress
import json
from dataclasses import replace
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .transport import CollectionError, pages
from .vpc import fields, identity

DETAIL_ACTIONS = (
    "DescribeClusterEndpoints",
    "DescribeClusterAuthenticationOptions",
    "DescribeControlPlaneLogs",
)


def array(value):
    if not isinstance(value, list):
        raise CollectionError("InvalidTkeArray")
    return value


def cluster(raw):
    props = fields(
        raw,
        (
            "ClusterName",
            "ClusterDescription",
            "ClusterVersion",
            "ClusterOs",
            "ClusterType",
            "ClusterStatus",
            "ImageId",
            "OsCustomizeType",
            "ContainerRuntime",
            "CreatedTime",
            "ClusterLevel",
            "RuntimeVersion",
            "CdcId",
            "ClusterCategory",
        ),
        (
            "DeletionProtection",
            "EnableExternalNode",
            "AutoUpgradeClusterLevel",
            "QGPUShareEnable",
            "IsHighAvailability",
        ),
        ("ClusterNodeNum", "ClusterMaterNodeNum", "ClusterEtcdNodeNum", "ProjectId"),
    )
    rid = identity(raw.get("ClusterId"), "cls")
    props["ClusterId"] = rid
    links = []
    network = raw.get("ClusterNetworkSettings")
    if network is not None:
        net = fields(
            network,
            ("KubeProxyMode", "CiliumMode"),
            ("Ipvs", "Cni", "IsDualStack", "DataPlaneV2"),
            ("MaxNodePodNum", "MaxClusterServiceNum"),
        )
        if network.get("VpcId"):
            props["VpcId"] = identity(network["VpcId"], "vpc")
            links.append(("vpc.vpc", props["VpcId"], "IN_VPC"))
        for name in ("ClusterCIDR", "ServiceCIDR", "Ipv6ServiceCIDR"):
            if network.get(name):
                try:
                    net[name] = str(ipaddress.ip_network(network[name], strict=True))
                except (ValueError, TypeError) as exc:
                    raise CollectionError("InvalidTkeCidr") from exc
        subs = array(network.get("Subnets") or [])
        if network.get("SubnetId"):
            subs = [*subs, network["SubnetId"]]
        for sid in sorted(set(identity(value, "subnet") for value in subs)):
            links.append(("vpc.subnet", sid, "USES_SUBNET"))
        props["network_configuration"] = json.dumps(net, sort_keys=True)
    if props.get("ImageId"):
        identity(props["ImageId"], "img")
        links.append(("cvm.image", props["ImageId"], "USES_IMAGE"))
    return rid, props, links


def endpoint(value):
    if not isinstance(value, str) or not value or any(ord(c) < 32 for c in value):
        raise CollectionError("InvalidTkeEndpoint")
    parsed = urlparse(value if "://" in value else "https://" + value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise CollectionError("InvalidTkeEndpoint")
    try:
        port = parsed.port
    except ValueError as exc:
        raise CollectionError("InvalidTkeEndpoint") from exc
    host = parsed.hostname
    if ":" in host:
        host = f"[{host}]"
    return "https://" + host + (f":{port}" if port and port != 443 else "")


def ca_metadata(value):
    from cryptography.exceptions import UnsupportedAlgorithm

    if not isinstance(value, str) or not value or len(value) > 1_000_000 or "PRIVATE KEY" in value:
        raise CollectionError("InvalidClusterCa")
    try:
        raw = value.encode()
        if "BEGIN CERTIFICATE" not in value:
            raw = base64.b64decode(raw, validate=True)
        cert = (
            x509.load_pem_x509_certificate(raw)
            if b"BEGIN CERTIFICATE" in raw
            else x509.load_der_x509_certificate(raw)
        )
        public = cert.public_key()
        return dict(
            fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(),
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            not_before=cert.not_valid_before_utc.isoformat(),
            not_after=cert.not_valid_after_utc.isoformat(),
            serial_number=str(cert.serial_number),
            signature_algorithm_oid=cert.signature_algorithm_oid.dotted_string,
            public_key_type=type(public).__name__,
            public_key_bits=getattr(public, "key_size", 0),
            is_ca=cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca,
        )
    except (ValueError, TypeError, x509.ExtensionNotFound, UnsupportedAlgorithm) as exc:
        raise CollectionError("InvalidClusterCa") from exc


def collect(runner, spec, region):
    selected = []
    source = "tke.DescribeClusters"

    def operation(record):
        seen = set()
        for rows, request in pages(runner.transport, replace(spec, require_total=True), region):
            if request:
                record["request_ids"].append(request)
            prepared = [cluster(raw) for raw in rows]
            ids = [row[0] for row in prepared]
            if len(set(ids)) != len(ids) or seen.intersection(ids):
                raise CollectionError("DuplicateTkeCluster")
            seen.update(ids)
            for rid, props, links in prepared:
                nid = runner.graph.add(
                    runner.account,
                    region,
                    "tke.cluster",
                    rid,
                    props.get("ClusterName"),
                    source=source,
                )
                runner.graph.nodes[nid]["properties"].update(props)
                for kind, value, relation in links:
                    target = runner.graph.add(
                        runner.account, region, kind, value, source=source, status="reference"
                    )
                    runner.graph.edge(nid, target, relation, source)
                selected.append(nid)
                record["count"] += 1

    runner.scope("tke", spec.action, region, operation)
    for nid in selected:
        details(runner, nid)


def details(runner, nid):
    node = runner.graph.nodes[nid]
    rid = node["resource_id"]
    region = node["region"]
    for action in DETAIL_ACTIONS:

        def operation(record, action=action):
            params = dict(ClusterId=rid)
            if action == "DescribeControlPlaneLogs":
                params["ClusterType"] = "tke"
            data = runner.transport.call("tke", action, region, **params)
            if data.get("RequestId"):
                record["request_ids"].append(data["RequestId"])
            if action == "DescribeClusterEndpoints":
                props = fields(
                    data, ("ClusterDomain", "ClusterExternalDomain", "ClusterIntranetDomain")
                )
                links = []
                for name in ("ClusterExternalEndpoint", "ClusterIntranetEndpoint"):
                    if data.get(name):
                        props[name] = endpoint(data[name])
                if data.get("ClusterExternalACL") is not None:
                    try:
                        props["ClusterExternalACL"] = json.dumps(
                            [
                                str(ipaddress.ip_network(v, strict=False))
                                for v in array(data["ClusterExternalACL"])
                            ]
                        )
                    except (ValueError, TypeError) as exc:
                        raise CollectionError("InvalidTkeEndpointAcl") from exc
                for name, prefix, kind in (
                    ("SecurityGroup", "sg", "vpc.securitygroup"),
                    ("IntranetSecurityGroup", "sg", "vpc.securitygroup"),
                    ("ClusterIntranetSubnetId", "subnet", "vpc.subnet"),
                ):
                    if data.get(name):
                        props[name] = identity(data[name], prefix)
                        links.append((kind, props[name], name))
                metadata = (
                    ca_metadata(data["CertificationAuthority"])
                    if data.get("CertificationAuthority")
                    else None
                )
                node["properties"].update(props, endpoints_collected=True)
                for kind, value, relation in links:
                    target = runner.graph.add(
                        runner.account,
                        region,
                        kind,
                        value,
                        source="tke." + action,
                        status="reference",
                    )
                    runner.graph.edge(
                        nid, target, "CONFIGURED_" + relation.upper(), "tke." + action
                    )
                if metadata:
                    target = runner.graph.add(
                        runner.account,
                        region,
                        "tke.certificateauthority",
                        rid + "/" + metadata["fingerprint_sha256"],
                        metadata["subject"],
                        source="tke." + action,
                    )
                    runner.graph.nodes[target]["properties"].update(metadata)
                    runner.graph.edge(nid, target, "HAS_CERTIFICATE_AUTHORITY", "tke." + action)
            elif action == "DescribeClusterAuthenticationOptions":
                props = fields(data, ("LatestOperationState",))
                for name, strings, booleans in (
                    (
                        "ServiceAccounts",
                        ("Issuer", "JWKSURI"),
                        ("UseTKEDefault", "AutoCreateDiscoveryAnonymousAuth"),
                    ),
                    (
                        "OIDCConfig",
                        (),
                        ("AutoCreateOIDCConfig", "AutoInstallPodIdentityWebhookAddon"),
                    ),
                ):
                    if data.get(name) is not None:
                        nested = fields(data[name], strings, booleans)
                        if name == "ServiceAccounts":
                            for key in strings:
                                if nested.get(key):
                                    nested[key] = (
                                        endpoint(nested[key])
                                        if urlparse(nested[key]).path in ("", "/")
                                        else validated_auth_url(nested[key])
                                    )
                        if (
                            name == "OIDCConfig"
                            and data[name].get("AutoCreateClientId") is not None
                        ):
                            ids = array(data[name]["AutoCreateClientId"])
                            if not all(isinstance(v, str) and v for v in ids):
                                raise CollectionError("InvalidTkeAuthClientId")
                            nested["AutoCreateClientId"] = ids
                        props[name] = json.dumps(nested, sort_keys=True)
                node["properties"].update(props, authentication_collected=True)
            else:
                prepared = []
                for raw in array(data.get("Details")):
                    props = fields(
                        raw, ("Name", "LogSetId", "TopicId", "TopicRegion"), integers=("LogLevel",)
                    )
                    if not props.get("Name"):
                        raise CollectionError("InvalidTkeLogConfig")
                    prepared.append(props)
                if len({v["Name"] for v in prepared}) != len(prepared):
                    raise CollectionError("DuplicateTkeLogConfig")
                node["properties"]["control_plane_logs"] = json.dumps(prepared, sort_keys=True)
                for props in prepared:
                    if props.get("TopicId") and props.get("TopicRegion"):
                        target = runner.graph.add(
                            runner.account,
                            props["TopicRegion"],
                            "cls.topic",
                            props["TopicId"],
                            source="tke." + action,
                            status="reference",
                        )
                        runner.graph.edge(
                            nid, target, "CONFIGURED_CONTROL_PLANE_LOG_TOPIC", "tke." + action
                        )
            record["count"] = 1

        runner.scope("tke", action, region, operation, rid)

    def blocked(record):
        raise CollectionError("UnsupportedMetadataOnlyNodeDetail")

    runner.scope("tke", "DescribeClusterInstances", region, blocked, rid)


def validated_auth_url(value):
    parsed = urlparse(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or any(ord(c) < 32 for c in value)
    ):
        raise CollectionError("InvalidTkeAuthUrl")
    return value


def collect_access_mappings(runner):
    """Certificate CN mappings for collected users; not an RBAC permission verdict."""
    graph = runner.graph
    users = [
        n
        for n in graph.nodes.values()
        if n["kind"] == "cam.user"
        and n["account"] == runner.account
        and n["status"] == "enriched"
        and n["resource_id"].isdigit()
    ]
    clusters = [
        n
        for n in graph.nodes.values()
        if n["kind"] == "tke.cluster"
        and n["account"] == runner.account
        and n["status"] == "enriched"
    ]
    for node in clusters:
        for start in range(0, len(users), 50):
            selected = {n["resource_id"]: n["id"] for n in users[start : start + 50]}

            def operation(record, node=node, selected=selected):
                data = runner.transport.call(
                    "tke",
                    "DescribeClusterCommonNames",
                    node["region"],
                    ClusterId=node["resource_id"],
                    SubaccountUins=list(selected),
                )
                if data.get("RequestId"):
                    record["request_ids"].append(data["RequestId"])
                prepared = []
                for raw in array(data.get("CommonNames")):
                    props = fields(raw, ("SubaccountUin", "CN"))
                    if props.get("SubaccountUin") not in selected or not props.get("CN"):
                        raise CollectionError("InvalidTkeCommonName")
                    prepared.append(props)
                if len({p["SubaccountUin"] for p in prepared}) != len(prepared):
                    raise CollectionError("DuplicateTkeCommonName")
                for props in prepared:
                    nid = graph.add(
                        runner.account,
                        node["region"],
                        "tke.accessmapping",
                        node["resource_id"] + "/" + props["SubaccountUin"],
                        props["CN"],
                        source="tke.DescribeClusterCommonNames",
                    )
                    graph.nodes[nid]["properties"].update(
                        props,
                        effective_access_verified=False,
                        mapping_scope="queried_collected_users",
                    )
                    graph.edge(
                        node["id"], nid, "HAS_ACCESS_MAPPING", "tke.DescribeClusterCommonNames"
                    )
                    graph.edge(
                        nid,
                        selected[props["SubaccountUin"]],
                        "MAPS_PRINCIPAL",
                        "tke.DescribeClusterCommonNames",
                    )
                    record["count"] += 1

            runner.scope(
                "tke",
                "DescribeClusterCommonNames",
                node["region"],
                operation,
                node["resource_id"] + ":" + str(start),
            )
