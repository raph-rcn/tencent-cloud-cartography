"""CDN certificate-deployment metadata without fetching TLS private-key fields."""

import re

from .catalog import Collector
from .ses import domain
from .transport import CollectionError, pages

DEPLOYMENTS = Collector(
    "ssl",
    "DescribeHostCdnInstanceList",
    "InstanceList",
    "cdn.domain",
    ("Domain",),
    regional=False,
    require_total=True,
    page_size=200,
)
SOURCE = "ssl.DescribeHostCdnInstanceList"


def prepare(row):
    if not isinstance(row, dict) or not isinstance(row.get("Domain"), str):
        raise CollectionError("InvalidCdnDomain")
    raw = row["Domain"]
    name = "*." + domain(raw[2:]) if raw.startswith("*.") else domain(raw)
    props = {
        "Domain": name,
        "metadata_view": "certificate-deployment",
        "origin_configuration_collected": False,
    }
    for key in ("Status", "HttpsBillingSwitch"):
        value = row.get(key)
        if value is not None:
            if not isinstance(value, str) or len(value) > 128 or any(ord(c) < 32 for c in value):
                raise CollectionError("InvalidCdnMetadata")
            props[key] = value
    cert = row.get("CertId")
    if cert is not None and (
        not isinstance(cert, str) or (cert and not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", cert))
    ):
        raise CollectionError("InvalidCdnCertificateId")
    if cert:
        props["CertId"] = cert
    props["state"] = props.get("Status", "")
    return name, props


def collect_domains(runner):
    def unsupported(record):
        raise CollectionError("UnsupportedMetadataOnlyCdnListing")

    runner.scope(
        "cdn",
        "DescribeDomains",
        "global",
        unsupported,
        "Disabled: Origin.AdvanceHttps.CertInfo can contain PrivateKey. SSL deployment "
        "metadata is a limited view; origins and complete domain coverage remain unavailable.",
    )

    def operation(record):
        seen = set()
        for rows, request_id in pages(
            runner.transport, DEPLOYMENTS, "global", {"IsCache": 0, "AsyncCache": 0}
        ):
            if request_id:
                record["request_ids"].append(request_id)
            # Validate the whole page before adding nodes or edges.
            prepared = [prepare(row) for row in rows]
            names = [name for name, _ in prepared]
            if len(set(names)) != len(names) or seen.intersection(names):
                raise CollectionError("DuplicateCdnDomain")
            seen.update(names)
            for name, props in prepared:
                nid = runner.graph.add(runner.account, "global", "cdn.domain", name, source=SOURCE)
                runner.graph.nodes[nid]["properties"].update(props)
                if props.get("CertId"):
                    cid = runner.graph.add(
                        runner.account,
                        "global",
                        "ssl.certificate",
                        props["CertId"],
                        source=SOURCE,
                        status="reference",
                    )
                    runner.graph.edge(nid, cid, "USES_CERTIFICATE", SOURCE)
                record["count"] += 1

    runner.scope(
        "ssl",
        DEPLOYMENTS.action,
        "global",
        operation,
        "CDN deployment view, requested fresh/synchronous. Empty results do not prove "
        "that the account has no CDN domains. HTTPS billing is not HTTPS enablement.",
    )
