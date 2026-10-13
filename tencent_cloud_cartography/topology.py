"""Cytoscape projection; placement is based only on collected containment edges."""

from collections import Counter

from .catalog import DETAIL_KINDS
from .icons import icon_for, service_title
from .model import stable_id


def topology(snapshot, account="", region="", view="architecture", limit=2500):
    candidates = [
        n
        for n in snapshot["nodes"]
        if (not account or n["account"] == account)
        and (not region or n["region"] in {region, "global"})
        and (view == "full" or n["kind"] not in DETAIL_KINDS)
    ]
    # Keep containment targets whenever their child is selected.
    selected = {n["id"]: n for n in candidates[:limit]}
    original = {n["id"]: n for n in snapshot["nodes"]}
    containment = {}
    for edge in snapshot["edges"]:
        if edge["relationship"] in {"IN_VPC", "IN_SUBNET"}:
            containment.setdefault((edge["source"], edge["relationship"]), set()).add(
                edge["target"]
            )
    for node in list(selected.values()):
        for relation in ("IN_SUBNET", "IN_VPC"):
            for target in containment.get((node["id"], relation), set()):
                if target in original:
                    selected[target] = original[target]
    for node in list(selected.values()):
        for target in containment.get((node["id"], "IN_VPC"), set()):
            if target in original:
                selected[target] = original[target]
    elements = {}
    accounts = {a["id"]: a["display"] for a in snapshot["accounts"]}

    def container(nid, label, kind, parent=None):
        if nid not in elements:
            data = dict(id=nid, label=label, title=label, type=kind, kind="container")
            if parent:
                data["parent"] = parent
            elements[nid] = dict(data=data, classes=kind)
        return nid

    for node in selected.values():
        aid = container(
            "account-" + node["account"], accounts.get(node["account"], node["account"]), "account"
        )
        rid = container(
            "region-" + stable_id(node["account"], node["region"]), node["region"], "region", aid
        )
        parent = rid
        vpcs = containment.get((node["id"], "IN_VPC"), set()) & selected.keys()
        subnets = containment.get((node["id"], "IN_SUBNET"), set()) & selected.keys()
        if len(vpcs) == 1 and node["kind"] != "vpc.vpc":
            parent = next(iter(vpcs))
        if node["kind"] == "vpc.subnet" and node["properties"].get("zone"):
            parent = container(
                "zone-" + stable_id(parent, node["properties"]["zone"]),
                node["properties"]["zone"],
                "availabilityZone",
                parent,
            )
        elif len(subnets) == 1 and node["kind"] not in {"vpc.vpc", "vpc.subnet"}:
            parent = next(iter(subnets))
        kind = {"vpc.vpc": "vpc", "vpc.subnet": "subnet"}.get(node["kind"], "resource")
        title = service_title(node["kind"])
        data = dict(
            id=node["id"],
            label=node["name"],
            title=title,
            type=kind,
            kind="resource" if kind == "resource" else "container",
            primaryLabel=node["resource_id"],
            labels=[node["kind"], node["status"]],
            icon=icon_for(node["kind"]),
            parent=parent,
            properties={
                **node["properties"],
                "resource_id": node["resource_id"],
                "resource_type": node["kind"],
                "account": node["account"],
                "region": node["region"],
                "collection_status": node["status"],
                "sources": ", ".join(node["sources"]),
            },
        )
        elements[node["id"]] = dict(
            data=data,
            classes=kind
            + " inventory-node"
            + (" unresolved" if node["status"] != "enriched" else ""),
        )
    edges = []
    for edge in snapshot["edges"]:
        if edge["source"] not in selected or edge["target"] not in selected:
            continue
        if (
            view == "architecture"
            and elements[edge["source"]]["data"].get("parent") == edge["target"]
        ):
            continue
        edges.append(dict(data={**edge, "label": edge["relationship"].replace("_", " ").lower()}))
    return dict(
        elements=list(elements.values()) + edges,
        stats=dict(
            resources=len(selected),
            relationships=len(edges),
            services=dict(Counter(service_title(n["kind"]) for n in selected.values())),
        ),
        truncated=len(candidates) > limit,
        limit=limit,
        status=snapshot["status"],
    )
