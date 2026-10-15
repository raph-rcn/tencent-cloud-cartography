"""Shared DNS visibility and configured resolver links, never live resolution."""

import json
import re
from urllib.parse import urlsplit

from .catalog import Collector
from .collect import CollectorRunner
from .dns import collect_records, normal_name, zone_configuration
from .transport import CollectionError, pages

SOURCE = "analysis.platform-dns-links"
ACTIONS = {("dnspod", "DescribeDomain")}
KINDS = {"dnspod.sharedview", "privatedns.outboundendpoint"}
SHARED = Collector(
    "dnspod",
    "DescribeDomainList",
    "DomainList",
    "dnspod.sharedview",
    ("DomainId",),
    total="DomainCountInfo.DomainTotal",
    paging="offset",
    require_total=True,
    regional=False,
)


def collect_shared(runner):
    pending = []

    def discover(record):
        seen = set()
        for rows, request_id in pages(runner.transport, SHARED, "global", {"Type": "SHARE"}):
            if request_id:
                record["request_ids"].append(request_id)
            prepared = []
            for raw in rows:
                if (
                    type(raw.get("DomainId")) is not int
                    or raw["DomainId"] <= 0
                    or raw["DomainId"] in seen
                ):
                    raise CollectionError("InvalidSharedDnsDomainIdentity")
                name = normal_name(raw.get("Punycode") or raw.get("Name"))
                seen.add(raw["DomainId"])
                prepared.append((raw, name))
            for raw, name in prepared:
                nid = runner.graph.add(
                    runner.account,
                    "global",
                    "dnspod.sharedview",
                    str(raw["DomainId"]),
                    name,
                    source="dnspod.DescribeDomainList",
                )
                runner.graph.nodes[nid]["properties"].update(
                    query_account=runner.account,
                    domain_id=raw["DomainId"],
                    dns_name=name,
                    owner_identity_verified=False,
                    ownership_scope="shared_visibility_query",
                )
                pending.append(runner.graph.nodes[nid])
                record["count"] += 1

    runner.scope("dnspod", "DescribeDomainList", "global", discover, "SHARE")
    for view in pending:

        def detail(record, view=view):
            response = runner.transport.call(
                "dnspod", "DescribeDomain", "global", DomainId=view["properties"]["domain_id"]
            )
            if response.get("RequestId"):
                record["request_ids"].append(response["RequestId"])
            raw = response.get("DomainInfo")
            if (
                not isinstance(raw, dict)
                or raw.get("DomainId") != view["properties"]["domain_id"]
                or normal_name(raw.get("Punycode") or raw.get("Domain"))
                != view["properties"]["dns_name"]
            ):
                raise CollectionError("SharedDnsDomainScopeMismatch")
            owner = raw.get("Uin")
            if (
                not isinstance(owner, str)
                or not re.fullmatch(r"[1-9][0-9]*", owner)
                or owner == runner.account
            ):
                raise CollectionError("UnresolvedSharedDnsOwner")
            nid = runner.graph.add(
                owner,
                "global",
                "dnspod.domain",
                str(raw["DomainId"]),
                view["name"],
                source="dnspod.DescribeDomain",
            )
            clean = {**raw, "Name": raw.get("Domain"), "EffectiveDNS": raw.get("DnspodNsList", [])}
            zone_configuration(runner.graph, nid, clean, "dnspod.DescribeDomain")
            runner.graph.nodes[nid]["properties"].update(
                owner_uin=owner, query_account=runner.account, observed_through_shared_access=True
            )
            view["properties"].update(
                owner_identity_verified=True, owner_uin=owner, owned_domain_node_id=nid
            )
            runner.graph.edge(view["id"], nid, "OBSERVES_SHARED_DOMAIN", "dnspod.DescribeDomain")
            record["count"] = 1
            scoped = CollectorRunner(
                runner.graph, runner.transport, owner, runner.regions, runner.progress, runner.plan
            )
            collect_records(scoped, nid, clean)

        runner.scope("dnspod", "DescribeDomain", "global", detail, view["resource_id"])


def link(graph):
    graph.edges = {i: e for i, e in graph.edges.items() if e.get("provenance") != SOURCE}
    referenced = {e[k] for e in graph.edges.values() for k in ("source", "target")}
    graph.nodes = {
        i: n
        for i, n in graph.nodes.items()
        if not (n["status"] == "reference" and n.get("sources") == [SOURCE] and i not in referenced)
    }
    nodes = list(graph.nodes.values())

    def targets(node, kind, rid, region=None):
        return [
            n
            for n in nodes
            if n["kind"] == kind
            and n["account"] == node["account"]
            and n["resource_id"] == rid
            and (region is None or n["region"] == region)
        ]

    def connect(node, kind, rid, relation, region=None):
        found = targets(node, kind, rid, region)
        if len(found) == 1:
            graph.edge(node["id"], found[0]["id"], relation, SOURCE)
        return found

    for n in nodes:
        p = n["properties"]
        if n["kind"] == "privatedns.forwardrule":
            p.update(
                resolver_precedence="not_independently_determined",
                runtime_resolution_verified=False,
            )
            if p.get("ZoneId"):
                connect(n, "privatedns.zone", p["ZoneId"], "FORWARDS_PRIVATE_ZONE", "global")
            if p.get("EndPointId"):
                # Inbound and outbound endpoint IDs are separate resource types.
                tid = graph.add(
                    n["account"],
                    "global",
                    "privatedns.outboundendpoint",
                    p["EndPointId"],
                    p.get("EndPointName"),
                    status="reference",
                    source=SOURCE,
                )
                graph.nodes[tid]["properties"].update(
                    identity_basis="forward_rule_endpoint_id", endpoint_detail_available=False
                )
                graph.edge(n["id"], tid, "USES_FORWARD_ENDPOINT", SOURCE)
            for v in json.loads(p.get("VpcSet", "[]")):
                if re.fullmatch(r"[a-z]+-[a-z0-9-]+", v.get("Region", "")) and re.fullmatch(
                    r"vpc-[a-z0-9]+", v.get("UniqVpcId", "")
                ):
                    vid = graph.add(
                        n["account"],
                        v["Region"],
                        "vpc.vpc",
                        v["UniqVpcId"],
                        status="reference",
                        source=SOURCE,
                    )
                    graph.edge(n["id"], vid, "ASSOCIATED_WITH_VPC", SOURCE)
        elif n["kind"] == "privatedns.inboundendpoint":
            found = connect(n, "vpc.vpc", p.get("UniqVpcId"), "IN_VPC")
            p["vpc_region_resolved"] = len(found) == 1
            if len(found) == 1:
                for service in json.loads(p.get("EndPointService", "[]")):
                    matches = connect(
                        n,
                        "vpc.subnet",
                        service.get("UniqSubnetId"),
                        "IN_SUBNET",
                        found[0]["region"],
                    )
                    for subnet in matches:
                        # An explicit conflicting VPC ID must never gain an edge.
                        subnet_vpcs = [
                            e["target"]
                            for e in graph.edges.values()
                            if e["source"] == subnet["id"] and e["relationship"] == "IN_VPC"
                        ]
                        if subnet_vpcs and found[0]["id"] not in subnet_vpcs:
                            graph.edges = {
                                i: e
                                for i, e in graph.edges.items()
                                if not (
                                    e["source"] == n["id"]
                                    and e["target"] == subnet["id"]
                                    and e["provenance"] == SOURCE
                                )
                            }
        elif n["kind"] == "dnspod.alias":
            p.update(
                alias_scope="provider_domain_alias_configuration", runtime_resolution_verified=False
            )
            connect(n, "dnspod.domain", p.get("parent_resource_id"), "DOMAIN_ALIAS_OF", "global")
        elif n["kind"] == "dnspod.sharegrant":
            # QCloudUIN is the recipient, never the domain owner or an auth proof.
            p.update(recipient_uin=p.get("QCloudUIN", ""), effective_access_verified=False)
    # Match CNAME/name targets only to exact, already collected endpoint hosts.
    # Private matches additionally require a common explicit VPC binding.
    associations, vpcs = {}, {}
    for e in graph.edges.values():
        if e["relationship"] == "ASSOCIATED_WITH_VPC":
            associations.setdefault(e["source"], set()).add(e["target"])
        elif e["relationship"] == "IN_VPC":
            vpcs.setdefault(e["source"], set()).add(e["target"])
    endpoints = {}
    for resource in nodes:
        p = resource["properties"]
        values = [
            p[k]
            for k in ("WanDomain", "DnsPodDomain", "PublicDomain", "InternalEndpoint")
            if isinstance(p.get(k), str) and p[k]
        ]
        for endpoint in json.loads(p.get("configured_endpoints", "[]")):
            if not isinstance(endpoint, dict):
                continue
            values += [
                endpoint[k] for k in ("Address", "address") if isinstance(endpoint.get(k), str)
            ]
            if endpoint.get("url"):
                host = urlsplit(endpoint["url"]).hostname
                if host:
                    values.append(host)
        for value in values:
            try:
                host = normal_name(value)
            except CollectionError:
                continue
            endpoints.setdefault((resource["account"], host), set()).add(resource["id"])
    for name in nodes:
        if name["kind"] not in {"dnspod.name", "privatedns.name"}:
            continue
        p = name["properties"]
        found = endpoints.get((name["account"], p.get("dns_value")), set())
        if p.get("dns_scope") != "public":
            found = {
                i for i in found if associations.get(p.get("dns_scope"), set()) & vpcs.get(i, set())
            }
        if len(found) == 1:
            graph.edge(name["id"], next(iter(found)), "MATCHES_CONFIGURED_ENDPOINT_HOST", SOURCE)
