"""Typed ES cluster network/capacity/access configuration, never query contents."""

import ipaddress
import json
from dataclasses import replace
from urllib.parse import urlsplit, urlunsplit

from .transport import CollectionError, pages
from .vpc import fields, identity


def prepare(raw, account, region):
    rid = identity(raw.get("InstanceId"), "es")
    if raw.get("Region") not in (None, "", region) or raw.get("Uin") not in (None, "", account):
        raise CollectionError("ElasticsearchScopeMismatch")
    props = fields(
        raw,
        (
            "InstanceName",
            "EsVersion",
            "Zone",
            "RenewFlag",
            "ChargeType",
            "NodeType",
            "DiskType",
            "LicenseType",
            "RealLicenseType",
            "CreateTime",
            "UpdateTime",
            "Deadline",
            "Protocol",
            "PublicAccess",
            "KibanaPublicAccess",
            "KibanaPrivateAccess",
            "EnableDestroyProtection",
            "ServerCertSource",
        ),
        (
            "AllowCosBackup",
            "EnableHotWarmMode",
            "AutoIndexEnabled",
            "EnableHybridStorage",
            "IsInRecycleBin",
            "RecycleLockEnabled",
        ),
        (
            "ChargePeriod",
            "NodeNum",
            "CpuNum",
            "MemSize",
            "DiskSize",
            "DeployMode",
            "SecurityType",
            "SceneType",
            "ReadWriteMode",
            "OpenMTLS",
        ),
    )
    for key in ("Status", "HealthStatus"):
        if raw.get(key) is not None:
            if type(raw[key]) is not int:
                raise CollectionError("InvalidElasticsearchStatus")
            props[key] = raw[key]
    props.update(
        zone=props.get("Zone", ""), engine="elasticsearch", internet_exposure_verified=False
    )
    links = []
    for field, kind, prefix, relation in (
        ("VpcUid", "vpc.vpc", "vpc", "IN_VPC"),
        ("SubnetUid", "vpc.subnet", "subnet", "IN_SUBNET"),
    ):
        if raw.get(field) not in (None, ""):
            value = identity(raw[field], prefix)
            props[field] = value
            links.append((kind, value, relation))
    groups = raw.get("SecurityGroups") or []
    if not isinstance(groups, list) or len(set(groups)) != len(groups):
        raise CollectionError("InvalidElasticsearchSecurityGroups")
    links.extend(("vpc.securitygroup", identity(g, "sg"), "USES_SECURITY_GROUP") for g in groups)
    endpoints = []
    for key in ("EsVip", "KibanaPrivateVip"):
        if raw.get(key) not in (None, ""):
            props[key] = str(ipaddress.ip_address(raw[key]))
    for key in (
        "EsPrivateUrl",
        "EsPublicUrl",
        "KibanaUrl",
        "KibanaPrivateUrl",
        "CustomKibanaPrivateUrl",
    ):
        if raw.get(key) not in (None, ""):
            if not isinstance(raw[key], str) or any(ord(c) < 32 for c in raw[key]):
                raise CollectionError("InvalidElasticsearchEndpoint")
            parsed = urlsplit(raw[key])
            if (
                parsed.scheme not in ("http", "https")
                or not parsed.hostname
                or parsed.username
                or parsed.password
            ):
                raise CollectionError("InvalidElasticsearchEndpoint")
            if parsed.port is not None and not 0 < parsed.port < 65536:
                raise CollectionError("InvalidElasticsearchEndpoint")
            endpoints.append(
                dict(field=key, url=urlunsplit(parsed._replace(query="", fragment="")))
            )
    props["configured_endpoints"] = json.dumps(endpoints, sort_keys=True)
    for key in ("PublicAccess", "KibanaPublicAccess", "KibanaPrivateAccess"):
        if props.get(key) not in (None, "", "OPEN", "CLOSE"):
            raise CollectionError("UnknownElasticsearchAccessFlag")
    for key in ("EsAcl", "EsPublicAcl"):
        if raw.get(key) is not None:
            if not isinstance(raw[key], dict):
                raise CollectionError("InvalidElasticsearchAcl")
            acl = {}
            for direction in ("WhiteIpList", "BlackIpList"):
                values = raw[key].get(direction) or []
                if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
                    raise CollectionError("InvalidElasticsearchAcl")
                acl[direction] = [
                    str(ipaddress.ip_network(v, strict=False))
                    if "/" in v
                    else str(ipaddress.ip_address(v))
                    for v in values
                ]
            props[key] = json.dumps(acl, sort_keys=True)
    configs = raw.get("NodeInfoList") or []
    if not isinstance(configs, list):
        raise CollectionError("InvalidElasticsearchNodeConfiguration")
    selected = [
        fields(
            row,
            ("Type", "NodeType", "DiskType", "KmsKeyId", "KmsKeyName"),
            integers=("NodeNum", "DiskSize", "DiskCount", "DiskEncrypt", "CpuNum", "MemSize"),
        )
        for row in configs
    ]
    props["node_configuration"] = json.dumps(selected, sort_keys=True)
    props["raw_es_kibana_config_retained"] = False
    return rid, props, links


def collect(runner, spec, region):
    def operation(record):
        seen = set()
        for batch, request in pages(runner.transport, replace(spec, require_total=True), region):
            if request:
                record["request_ids"].append(request)
            prepared = [prepare(row, runner.account, region) for row in batch]
            ids = [rid for rid, _, _ in prepared]
            if len(set(ids)) != len(ids) or seen.intersection(ids):
                raise CollectionError("DuplicateElasticsearchInstance")
            seen.update(ids)
            for rid, props, links in prepared:
                nid = runner.graph.add(
                    runner.account,
                    region,
                    "es.instance",
                    rid,
                    props.get("InstanceName"),
                    source="es.DescribeInstances",
                )
                runner.graph.nodes[nid]["properties"].update(props)
                for kind, value, relation in links:
                    target = runner.graph.add(
                        runner.account, region, kind, value, status="reference"
                    )
                    runner.graph.edge(nid, target, relation, "es.DescribeInstances")
                record["count"] += 1

    runner.scope("es", spec.action, region, operation)
