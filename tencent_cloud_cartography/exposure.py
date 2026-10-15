"""Configured CLB exposure paths, equivalent to the source's EXPOSE graph links."""

import ipaddress

from .model import stable_id
from .network_parity import cross_applies, cross_resources, indices, legacy_cross_resources

SOURCE = "analysis.clb-exposure"


def analyze(graph):
    obsolete = {nid for nid, n in graph.nodes.items() if n["kind"] == "clb.exposurepath"}
    graph.nodes = {nid: n for nid, n in graph.nodes.items() if nid not in obsolete}
    graph.edges = {
        eid: e
        for eid, e in graph.edges.items()
        if e["source"] not in obsolete
        and e["target"] not in obsolete
        and e.get("provenance") != SOURCE
    }
    graph.coverage = [r for r in graph.coverage if r.get("action") != "AnalyzeClbExposure"]
    edges = list(graph.edges.values())
    links = indices(graph)
    cross_metadata = [
        n
        for n in graph.nodes.values()
        if n["kind"] == "clb.crosstarget" and n["status"] == "enriched"
    ]
    interface_addresses = [n for n in graph.nodes.values() if n["kind"] == "vpc.interfaceaddress"]
    outgoing, parents, vpcs = {}, {}, {}
    for edge in edges:
        outgoing.setdefault(edge["source"], []).append(edge)
        if edge["relationship"] in {"HAS_LISTENER", "HAS_RULE", "HAS_TARGET_GROUP", "HAS_BACKEND"}:
            parents.setdefault(edge["target"], set()).add(edge["source"])
        if edge["relationship"] == "IN_VPC":
            vpcs.setdefault(edge["source"], set()).add(edge["target"])

    def scope(node, lb):
        return (
            node["status"] == "enriched"
            and (node["account"], node["region"]) == (lb["account"], lb["region"])
            and len(vpcs.get(lb["id"], ())) == 1
            and vpcs.get(node["id"]) == vpcs.get(lb["id"])
            and all(
                graph.nodes[vid]["kind"] == "vpc.vpc"
                and (graph.nodes[vid]["account"], graph.nodes[vid]["region"])
                == (lb["account"], lb["region"])
                for vid in vpcs[lb["id"]]
            )
        )

    counts, unresolved = {}, set()
    for edge in edges:
        if edge["relationship"] != "FORWARDS_TO":
            continue
        frontend, backend = graph.nodes[edge["source"]], graph.nodes[edge["target"]]
        if (
            frontend["kind"]
            not in {"clb.listener", "clb.rule", "clb.targetbinding", "clb.functiontarget"}
            or frontend["status"] != "enriched"
        ):
            continue
        ancestry, pending = set(), list(parents.get(frontend["id"], ()))
        while pending:
            parent = pending.pop()
            if parent in ancestry:
                continue
            node = graph.nodes[parent]
            if (
                node["kind"]
                not in {
                    "clb.clb",
                    "clb.listener",
                    "clb.rule",
                    "clb.targetgroup",
                    "clb.targetbinding",
                    "clb.functiontarget",
                }
                or node["status"] != "enriched"
                or (node["account"], node["region"]) != (frontend["account"], frontend["region"])
            ):
                continue
            ancestry.add(parent)
            pending.extend(parents.get(parent, ()))
        for lid in ancestry:
            lb = graph.nodes[lid]
            if (
                lb["kind"] != "clb.clb"
                or lb["status"] != "enriched"
                or (frontend["account"], frontend["region"]) != (lb["account"], lb["region"])
            ):
                continue
            counts.setdefault(lid, 0)
            targets = []
            if (
                backend["kind"] == "scf.function"
                and frontend["kind"] == "clb.functiontarget"
                and backend["status"] == "enriched"
                and (backend["account"], backend["region"]) == (lb["account"], lb["region"])
                and backend["name"] == frontend["properties"].get("FunctionName")
                and backend["properties"].get("Namespace")
                == frontend["properties"].get("FunctionNamespace")
                and lb["properties"].get("Forward") != 0
            ):
                targets = [(backend, "explicit-scf-function-binding")]
            if backend["kind"] in {
                "cvm.instance",
                "vpc.networkinterface",
                "vpc.nat",
                "vpc.havip",
            } and scope(backend, lb):
                targets = [
                    (
                        backend,
                        "explicit-instance"
                        if backend["kind"] == "cvm.instance"
                        else "explicit-provider-resource",
                    )
                ]
            elif (
                backend["kind"] == "clb.target"
                and backend["status"] == "enriched"
                and (backend["account"], backend["region"]) == (lb["account"], lb["region"])
            ):
                matched = [
                    graph.nodes[e["target"]]
                    for e in outgoing.get(backend["id"], ())
                    if e["relationship"] == "MATCHES_INTERFACE_ADDRESS"
                ]
                if (
                    len(matched) == 1
                    and matched[0]["kind"] == "vpc.interfaceaddress"
                    and scope(matched[0], lb)
                ):
                    address = matched[0]
                    try:
                        reported = ipaddress.ip_address(
                            backend["properties"].get("TargetAddress") or backend["name"]
                        )
                        actual = ipaddress.ip_address(address["properties"].get("address"))
                    except (ValueError, TypeError):
                        unresolved.add(lid)
                        continue
                    if reported != actual:
                        unresolved.add(lid)
                        continue
                    reported_id = backend["properties"].get("TargetId", "")
                    if reported_id.startswith("eni-") and reported_id != address["properties"].get(
                        "NetworkInterfaceId"
                    ):
                        unresolved.add(lid)
                        continue
                    if reported_id.startswith("ins-") and not any(
                        interface["status"] == "enriched"
                        and scope(interface, lb)
                        and interface["resource_id"]
                        == address["properties"].get("NetworkInterfaceId")
                        and interface["properties"].get("Business") in (None, "", "cvm")
                        and any(
                            graph.nodes[t]["resource_id"] == reported_id
                            and scope(graph.nodes[t], lb)
                            for t in links.get((interface["id"], "ATTACHED_TO"), ())
                        )
                        for interface in graph.nodes.values()
                        if interface["kind"] == "vpc.networkinterface"
                        and address["id"] in links.get((interface["id"], "HAS_ADDRESS"), ())
                    ):
                        unresolved.add(lid)
                        continue
                    targets.append((address, "corroborated-interface-address"))
                    # Resolve through the collected ENI's unique attachment, rather
                    # than accepting a standalone instance match from another scope.
                    interfaces = [
                        graph.nodes[e["source"]]
                        for e in edges
                        if e["target"] == address["id"]
                        and e["relationship"] == "HAS_ADDRESS"
                        and graph.nodes[e["source"]]["kind"] == "vpc.networkinterface"
                    ]
                    if (
                        len(interfaces) == 1
                        and scope(interfaces[0], lb)
                        and interfaces[0]["properties"].get("Business") in (None, "", "cvm")
                        and address["properties"].get("NetworkInterfaceId")
                        == interfaces[0]["resource_id"]
                    ):
                        attached = [
                            graph.nodes[e["target"]]
                            for e in outgoing.get(interfaces[0]["id"], ())
                            if e["relationship"] == "ATTACHED_TO"
                            and graph.nodes[e["target"]]["kind"] == "cvm.instance"
                        ]
                        if len(attached) == 1 and scope(attached[0], lb):
                            targets.append((attached[0], "corroborated-interface-attachment"))
                references = [
                    graph.nodes[e["target"]]
                    for e in outgoing.get(backend["id"], ())
                    if e["relationship"] == "REFERENCES_BACKEND_RESOURCE"
                ]
                if (
                    len(references) == 1
                    and scope(references[0], lb)
                    and references[0]["kind"] in {"vpc.networkinterface", "vpc.nat", "vpc.havip"}
                    and backend["properties"].get("TargetId") == references[0]["resource_id"]
                    and (
                        references[0]["kind"] != "vpc.networkinterface"
                        or not backend["properties"].get("TargetAddress")
                        or (
                            len(matched) == 1
                            and matched[0]["id"]
                            in links.get((references[0]["id"], "HAS_ADDRESS"), ())
                        )
                    )
                ):
                    targets.append((references[0], "explicit-provider-resource"))
            # Native cross-target metadata must belong to this exact listener/LB.
            # Revalidate the remote ENI/IP/VPC identity for imported snapshots too.
            legacy = (
                legacy_cross_resources(graph, lb, backend, links)
                if backend["kind"] != "scf.function"
                else None
            )
            if legacy is not None:
                targets = [(n, "corroborated-legacy-cross-region-metadata") for n in legacy]
            cross = [
                e
                for e in cross_metadata
                if e["properties"].get("LoadBalancerId") == lb["resource_id"]
                and cross_applies(graph, e, frontend, backend, ancestry | {frontend["id"]}, links)
            ]
            if len(cross) == 1:
                resources, _ = cross_resources(graph, cross[0], interface_addresses, links)
                if legacy is not None and not (
                    {n["id"] for n in legacy} & {n["id"] for n in resources}
                ):
                    resources = []
                targets = [(n, "corroborated-cross-vpc-metadata") for n in resources]
            elif len(cross) > 1:
                targets = []
            if not targets:
                unresolved.add(lid)
                continue
            for target, resolution in targets:
                rid = stable_id(lid, frontend["id"], backend["id"], target["id"])
                nid = graph.add(
                    lb["account"],
                    lb["region"],
                    "clb.exposurepath",
                    rid,
                    f"Configured exposure: {lb['name']} → {target['name']}",
                    source=SOURCE,
                )
                graph.nodes[nid]["properties"].update(
                    LoadBalancerId=lb["resource_id"],
                    frontend_id=frontend["resource_id"],
                    backend_id=backend["resource_id"],
                    target_id=target["resource_id"],
                    target_kind=target["kind"],
                    resolution=resolution,
                    reachability_verified=False,
                    evaluation_scope="configured_clb_forwarding",
                )
                for label, source, destination in (
                    ("EXPOSE", lid, target["id"]),
                    ("HAS_EXPOSURE_PATH", lid, nid),
                    ("VIA_FRONTEND", nid, frontend["id"]),
                    ("VIA_BACKEND", nid, backend["id"]),
                    ("TARGETS_RESOURCE", nid, target["id"]),
                ):
                    graph.edge(source, destination, label, SOURCE)
                counts[lid] += 1
    for lid, count in counts.items():
        lb = graph.nodes[lid]
        graph.coverage.append(
            dict(
                account=lb["account"],
                region=lb["region"],
                service="analysis",
                action="AnalyzeClbExposure",
                detail=lb["resource_id"],
                status="error" if lid in unresolved else "complete",
                error="UnresolvedClbBackend" if lid in unresolved else "",
                count=count,
                request_ids=[],
            )
        )
