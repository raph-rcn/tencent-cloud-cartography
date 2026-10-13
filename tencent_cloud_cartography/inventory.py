"""CloudRC identity reconciliation using documented type codes and explicit scopes."""

import json
import re

from .catalog import COLLECTORS
from .transport import CollectionError

# https://cloud.tencent.com/document/product/1791/115765
TYPE_ALIASES = {
    "cvm.volume": "cbs.disk",
    "ckafka.ckafkaid": "ckafka.instance",
    "cdb.instanceid": "cdb.instance",
}
# CloudRC labels this code as a function, whereas ListNamespaces returns namespaces.
# Without a documented ResourceId contract, neither identity is safe to infer.
AMBIGUOUS_TYPES = {"scf.namespace": "scf.inventoryresource"}
GLOBAL_KINDS = {spec.kind for spec in COLLECTORS if not spec.regional}


def type_identity(value):
    if not isinstance(value, str):
        raise CollectionError("InvalidInventoryType")
    parts = re.split(r"::|\.", value.lower())
    if parts and parts[0] == "qcs":
        parts = parts[1:]
    if len(parts) != 2 or not all(re.fullmatch(r"[a-z0-9_-]+", p) for p in parts):
        raise CollectionError("InvalidInventoryType")
    original = ".".join(parts)
    if original in AMBIGUOUS_TYPES:
        return AMBIGUOUS_TYPES[original], "ambiguous-provider-type"
    return TYPE_ALIASES.get(
        original, original
    ), "type-alias" if original in TYPE_ALIASES else "exact-type"


def identity(item, account):
    if not isinstance(item, dict):
        raise CollectionError("InvalidInventoryResource")
    owner = item.get("Uin")
    if type(owner) not in (int, str) or not re.fullmatch(r"[0-9]+", str(owner)):
        raise CollectionError("InvalidInventoryOwner")
    if str(owner) != account:
        raise CollectionError("AccountMismatch")
    kind, resolution = type_identity(item.get("ResourceType"))
    rid = item.get("ResourceId")
    if not isinstance(rid, str) or not rid or any(ord(c) < 32 for c in rid):
        raise CollectionError("InvalidInventoryResourceId")
    region = item.get("RegionCode")
    if region in (None, ""):
        region = "unknown"
    elif not isinstance(region, str) or not re.fullmatch(r"global|[a-z]+-[a-z0-9-]+", region):
        raise CollectionError("InvalidInventoryRegion")
    alias = item.get("ResourceAlias")
    if alias is not None and not isinstance(alias, str):
        raise CollectionError("InvalidInventoryName")
    return kind, rid, region, resolution


def add_resource(graph, account, item, parsed):
    kind, rid, region, resolution = parsed
    metadata = {}
    for field in ("CreateTime", "ZoneCode"):
        if item.get(field) is not None:
            if not isinstance(item[field], str):
                raise CollectionError("InvalidInventoryMetadata")
            metadata[field] = item[field]
    for field in ("PrivateIpAddress", "PublicIpAddress"):
        if item.get(field) is not None:
            if not isinstance(item[field], list) or not all(
                isinstance(v, str) for v in item[field]
            ):
                raise CollectionError("InvalidInventoryAddresses")
            metadata[field] = item[field]
    tags = item.get("Tags")
    clean_tags = None
    if tags is not None:
        if not isinstance(tags, list):
            raise CollectionError("InvalidInventoryTags")
        clean_tags = []
        for tag in tags:
            if not isinstance(tag, dict) or any(
                tag.get(k) is not None and not isinstance(tag[k], str) for k in ("Key", "Value")
            ):
                raise CollectionError("InvalidInventoryTags")
            clean_tags.append({k: tag[k] for k in ("Key", "Value") if tag.get(k) is not None})
    nid = graph.add(
        account,
        region,
        kind,
        rid,
        item.get("ResourceAlias"),
        metadata,
        "cloudrc.SearchResources",
        "inventory-only",
    )
    node = graph.nodes[nid]
    node["sources"] = sorted(set(node["sources"] + ["cloudrc.SearchResources"]))
    props = node["properties"]
    props.update(
        inventory_resource_type=item["ResourceType"],
        inventory_resource_id=rid,
        inventory_type_resolution=resolution,
        inventory_region_code=item.get("RegionCode") or "",
        inventory_region_resolution="missing" if region == "unknown" else "explicit",
    )
    if item.get("ResourceAlias") is not None:
        props["inventory_name"] = item["ResourceAlias"]
    for field in ("PayMode", "ExpireTime"):
        if isinstance(item.get(field), str):
            props["inventory_" + field] = item[field]
    if clean_tags is not None:
        props["inventory_tags"] = json.dumps(clean_tags, sort_keys=True)
    return nid


def reconcile_global_inventory(graph):
    """Resolve a missing region only after the global native API proves the identity."""
    from .model import stable_id

    index = {}
    for node in graph.nodes.values():
        if node["status"] == "enriched" and node["region"] == "global":
            key = (node["account"], node["kind"], node["resource_id"])
            index.setdefault(key, []).append(node)
    replacements = {}
    for old in list(graph.nodes.values()):
        if (
            old["status"] != "inventory-only"
            or old["region"] != "unknown"
            or old["kind"] not in GLOBAL_KINDS
            or "cloudrc.SearchResources" not in old["sources"]
        ):
            continue
        matches = index.get((old["account"], old["kind"], old["resource_id"]), [])
        if len(matches) != 1:
            continue
        new = matches[0]
        for key, value in old["properties"].items():
            new["properties"].setdefault(key, value)
        new["properties"]["inventory_region_resolution"] = "native-global"
        new["sources"] = sorted(set(new["sources"] + old["sources"]))
        replacements[old["id"]] = new["id"]
        del graph.nodes[old["id"]]
    for eid, edge in list(graph.edges.items()):
        if edge["source"] in replacements or edge["target"] in replacements:
            del graph.edges[eid]
            source = replacements.get(edge["source"], edge["source"])
            target = replacements.get(edge["target"], edge["target"])
            prior = graph.edges.get(stable_id(source, target, edge["relationship"]), {})
            provenance = "; ".join(
                sorted({p for p in (edge.get("provenance", ""), prior.get("provenance", "")) if p})
            )
            graph.edge(source, target, edge["relationship"], provenance)
