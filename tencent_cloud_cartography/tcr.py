"""TCR Enterprise registry configuration and image metadata; no image pulls."""

import re

from .catalog import TCR_CHILDREN
from .transport import CollectionError, pages


def component(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9]+(?:[._-]+[a-z0-9]+)*", value):
        raise CollectionError("InvalidTcrName")
    return value


def retain(node, raw, fields):
    for field in fields:
        if field in raw and isinstance(raw[field], (str, bool, int)):
            node["properties"][field] = raw[field]


def child(graph, registry, kind, rid, name, raw, fields, source, status="enriched"):
    nid = graph.add(
        registry["account"], registry["region"], kind, rid, name, source=source, status=status
    )
    retain(graph.nodes[nid], raw, fields)
    graph.nodes[nid]["properties"]["RegistryId"] = registry["resource_id"]
    return nid


def namespace(graph, registry, raw, source, status="enriched"):
    name = component(raw.get("Name"))
    nid = child(
        graph,
        registry,
        "tcr.namespace",
        f"{registry['resource_id']}/{name}",
        name,
        raw,
        ("NamespaceId", "Public", "CreationTime", "AutoScan", "PreventVUL", "Severity"),
        source,
        status,
    )
    graph.edge(registry["id"], nid, "HAS_NAMESPACE", source)
    return nid


def repository(graph, registry, raw, source):
    ns = component(raw.get("Namespace"))
    full = raw.get("Name")
    # DescribeRepositories returns namespace/repository, while DescribeImages
    # requires the repository component without the namespace prefix.
    if not isinstance(full, str) or not full.startswith(ns + "/"):
        raise CollectionError("TcrNamespaceMismatch")
    repo = "/".join(component(part) for part in full[len(ns) + 1 :].split("/"))
    nid = child(
        graph,
        registry,
        "tcr.repository",
        f"{registry['resource_id']}/{full}",
        full,
        raw,
        ("Public", "CreationTime", "UpdateTime", "BriefDescription"),
        source,
    )
    graph.nodes[nid]["properties"].update(Namespace=ns, RepositoryName=repo)
    nsid = namespace(graph, registry, {"Name": ns}, source, "reference")
    graph.edge(nsid, nid, "HAS_REPOSITORY", source)
    graph.edge(registry["id"], nid, "HAS_REPOSITORY", source)
    return nid


def image(graph, registry, repo, raw, source):
    digest = raw.get("Digest")
    # OCI/Docker content digest, kept whole. Never identify images by a mutable tag.
    if not isinstance(digest, str) or not re.fullmatch(
        r"[a-z0-9]+(?:[+._-][a-z0-9]+)*:[A-Za-z0-9=_-]+", digest
    ):
        raise CollectionError("InvalidImageDigest")
    algorithm, value = digest.split(":", 1)
    if algorithm in {"sha256", "sha512"} and not re.fullmatch(
        r"[a-f0-9]{" + str(64 if algorithm == "sha256" else 128) + r"}", value
    ):
        raise CollectionError("InvalidImageDigest")
    tag = raw.get("ImageVersion")
    if (
        tag is not None
        and tag != ""
        and (
            not isinstance(tag, str) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", tag)
        )
    ):
        raise CollectionError("InvalidImageTag")
    # Reference and content nodes are separate: many tags may point at one digest.
    refid = f"{repo['resource_id']}:{tag}" if tag else f"{repo['resource_id']}@{digest}"
    iid = graph.add(
        registry["account"],
        registry["region"],
        "tcr.image",
        digest,
        f"{algorithm}:{value[:12]}…",
        source=source,
    )
    retain(graph.nodes[iid], raw, ("Digest", "Size", "Kind"))
    rid = child(
        graph,
        registry,
        "tcr.imagereference",
        refid,
        f"{repo['name']}:{tag}" if tag else f"{repo['name']}@{digest}",
        raw,
        ("Digest", "ImageVersion", "Size", "Kind", "UpdateTime"),
        source,
    )
    graph.edge(repo["id"], rid, "HAS_IMAGE", source)
    graph.edge(rid, iid, "REFERS_TO_IMAGE", source)
    return rid


def collect_registry(runner, registry_id, raw):
    graph, registry = runner.graph, runner.graph.nodes[registry_id]
    retain(
        registry,
        raw,
        (
            "RegistryType",
            "PublicDomain",
            "InternalEndpoint",
            "EnableAnonymous",
            "CreatedAt",
            "DeletionProtection",
            "EnableCosMAZ",
            "EnableCosVersioning",
        ),
    )
    base = {"RegistryId": registry["resource_id"]}

    def collect_rows(kind, params, add, detail):
        spec, collected = TCR_CHILDREN[kind], []
        source = f"tcr.{spec.action}"

        def operation(record):
            seen = set()
            for rows, request_id in pages(runner.transport, spec, registry["region"], params):
                if request_id:
                    record["request_ids"].append(request_id)
                for row in rows:
                    identity = (
                        (row.get("ImageVersion") or row.get("Digest"))
                        if kind == "image"
                        else row.get("Name")
                    )
                    if identity in seen:
                        raise CollectionError("DuplicateTcrResource")
                    nid = add(row, source)
                    seen.add(identity)
                    collected.append(nid)
                    record["count"] += 1

        runner.scope("tcr", spec.action, registry["region"], operation, detail)
        return collected

    # All avoids the ambiguous namespace page-offset wording. Count reconciliation
    # fails explicitly if the server returns only a subset despite this flag.
    collect_rows(
        "namespace",
        {**base, "All": True},
        lambda row, src: namespace(graph, registry, row, src),
        registry["resource_id"],
    )
    # Repositories are independent of namespace-list permission.
    repos = collect_rows(
        "repository",
        base,
        lambda row, src: repository(graph, registry, row, src),
        registry["resource_id"],
    )
    for nid in repos:
        repo = graph.nodes[nid]
        params = {
            **base,
            "NamespaceName": repo["properties"]["Namespace"],
            "RepositoryName": repo["properties"]["RepositoryName"],
        }
        collect_rows(
            "image",
            params,
            lambda row, src: image(graph, registry, repo, row, src),
            repo["resource_id"],
        )
