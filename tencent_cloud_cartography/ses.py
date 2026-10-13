"""SES sending-domain metadata and provider-reported DNS checks, never mail contents."""

import ipaddress
import json
import re

from .catalog import SES_ENDPOINTS
from .dns import normal_name
from .model import stable_id
from .transport import CollectionError


def domain(value, records=False):
    name = normal_name(value)
    pattern = (
        r"[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?" if records else r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
    )
    if (
        len(name) > 253
        or "." not in name
        or any(len(label) > 63 or not re.fullmatch(pattern, label) for label in name.split("."))
    ):
        raise CollectionError("InvalidSesDomain")
    return name


def properties(raw, detail=False):
    if not isinstance(raw, dict) or raw.get("IdentityType") != "DOMAIN":
        raise CollectionError("InvalidSesIdentityType")
    flag = "VerifiedForSendingStatus" if detail else "SendingEnabled"
    if type(raw.get(flag)) is not bool:
        raise CollectionError("InvalidSesVerificationStatus")
    props = {"IdentityType": "DOMAIN", flag: raw[flag]}
    if raw.get("DKIMOption") is not None:
        option = raw["DKIMOption"]
        if type(option) is not int or option not in (0, 1, 2):
            raise CollectionError("InvalidSesDkimOption")
        props.update(
            DKIMOption=option, dkim_key_bits={0: "1024", 1: "2048", 2: "1024,2048"}[option]
        )
    for field in ("CurrentReputationLevel", "DailyQuota"):
        if raw.get(field) is not None:
            if type(raw[field]) is not int or raw[field] < 0:
                raise CollectionError("InvalidSesQuota")
            props[field] = raw[field]
    if raw.get("SendIp") is not None:
        values = raw["SendIp"]
        if not isinstance(values, list):
            raise CollectionError("InvalidSesSendIp")
        try:
            if any(not isinstance(v, str) for v in values):
                raise ValueError
            props["SendIp"] = json.dumps([str(ipaddress.ip_address(v)) for v in values])
        except ValueError as exc:
            raise CollectionError("InvalidSesSendIp") from exc
    if raw.get("TagList") is not None:
        tags = raw["TagList"]
        if not isinstance(tags, list) or any(
            not isinstance(t, dict)
            or any(not isinstance(t.get(k), str) for k in ("TagKey", "TagValue"))
            for t in tags
        ):
            raise CollectionError("InvalidSesTags")
        props["tags"] = json.dumps(
            [{k: t[k] for k in ("TagKey", "TagValue")} for t in tags], sort_keys=True
        )
    return props


def prepare(raw):
    properties(raw)
    return {**raw, "IdentityName": domain(raw.get("IdentityName"))}


def configuration(graph, nid, raw, source):
    props = properties(raw)
    node = graph.nodes[nid]
    node["properties"].update(props, dns_name=node["resource_id"], delivery_verified=False)


def attributes(raw, identity):
    rows = raw.get("Attributes")
    if not isinstance(rows, list):
        raise CollectionError("InvalidSesDnsAttributes")
    result, seen = [], set()
    for row in rows:
        if not isinstance(row, dict) or row.get("Type") not in {"TXT", "CNAME", "MX", "A"}:
            raise CollectionError("InvalidSesDnsType")
        name = domain(row.get("SendDomain"), records=True)
        if name != identity and not name.endswith("." + identity):
            raise CollectionError("SesDnsDomainMismatch")
        if type(row.get("Status")) is not bool:
            raise CollectionError("InvalidSesDnsStatus")
        for field in ("ExpectedValue", "CurrentValue"):
            if not isinstance(row.get(field), str) or len(row[field]) > 32768:
                raise CollectionError("InvalidSesDnsValue")
        if not row["ExpectedValue"]:
            raise CollectionError("InvalidSesDnsValue")
        key = (name, row["Type"], row["ExpectedValue"])
        if key in seen:
            raise CollectionError("DuplicateSesDnsCheck")
        seen.add(key)
        result.append(
            dict(
                dns_name=name,
                record_type=row["Type"],
                expected_value=row["ExpectedValue"],
                current_value=row["CurrentValue"],
                provider_check_passed=row["Status"],
            )
        )
    return result


def collect_domains(runner, spec, region):
    if region not in SES_ENDPOINTS:

        def unsupported(record):
            raise CollectionError("UnsupportedSesRegion")

        runner.scope(
            "ses",
            spec.action,
            region,
            unsupported,
            "Supported regions: " + ", ".join(SES_ENDPOINTS),
        )
        return
    for nid, _ in runner.native(spec, region):
        node = runner.graph.nodes[nid]

        def detail(record, node=node):
            source = "ses.GetEmailIdentity"
            response = runner.transport.call(
                "ses", "GetEmailIdentity", region=region, EmailIdentity=node["resource_id"]
            )
            if response.get("RequestId"):
                record["request_ids"].append(response["RequestId"])
            # API does not echo the identity: scope derives from the exact request.
            if (
                response.get("IdentityName") is not None
                and domain(response["IdentityName"]) != node["resource_id"]
            ):
                raise CollectionError("SesIdentityMismatch")
            props = properties(response, detail=True)
            checks = attributes(response, node["resource_id"])
            props["verification_changed_since_list"] = (
                props["VerifiedForSendingStatus"] != node["properties"]["SendingEnabled"]
            )
            if "DKIMOption" in props and "DKIMOption" in node["properties"]:
                props["dkim_changed_since_list"] = (
                    props["DKIMOption"] != node["properties"]["DKIMOption"]
                )
                props["list_DKIMOption"] = node["properties"]["DKIMOption"]
            node["properties"].update(props, detail_collected=True, dns_check_count=len(checks))
            node["sources"] = sorted(set(node["sources"] + [source]))
            for check in checks:
                rid = (
                    node["resource_id"]
                    + "/"
                    + stable_id(check["dns_name"], check["record_type"], check["expected_value"])
                )
                cid = runner.graph.add(
                    node["account"],
                    region,
                    "ses.dnscheck",
                    rid,
                    f"{check['dns_name']} · {check['record_type']}",
                    source=source,
                )
                runner.graph.nodes[cid]["properties"].update(check, delivery_verified=False)
                runner.graph.edge(node["id"], cid, "HAS_DNS_CHECK", source)
            record["count"] = 1

        runner.scope("ses", "GetEmailIdentity", region, detail, node["resource_id"])


def link_dns_checks(graph):
    index = {}
    for node in graph.nodes.values():
        p = node["properties"]
        if (
            node["kind"] == "dnspod.record"
            and node["region"] == "global"
            and node["status"] == "enriched"
            and p.get("dns_scope") == "public"
        ):
            key = (node["account"], p.get("dns_name"), p.get("record_type"), p.get("record_value"))
            index.setdefault(key, []).append(node["id"])
    for node in graph.nodes.values():
        if node["kind"] != "ses.dnscheck":
            continue
        p = node["properties"]
        matches = index.get(
            (node["account"], p["dns_name"], p["record_type"], p["expected_value"]), []
        )
        for target in matches:
            graph.edge(
                node["id"],
                target,
                "MATCHES_EXPECTED_DNS_RECORD",
                "ses.GetEmailIdentity / dnspod.DescribeRecordList: exact name/type/value",
            )
        p["matching_dns_record_count"] = len(matches)
