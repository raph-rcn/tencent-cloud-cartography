"""AWS ECR provenance helpers.

The upstream project used this module for cross-provider supply-chain matching.
This fork keeps only the small, provider-neutral parsing helpers required by the
AWS ECR image-layer collector.
"""

from __future__ import annotations

import re
from typing import Any


def normalize_vcs_url(url: str) -> str:
    """Normalize a provenance VCS URL to HTTPS without a ``.git`` suffix."""
    normalized = url.strip()
    ssh_match = re.match(r"git@([^:]+):(.+)", normalized)
    if ssh_match:
        host, path = ssh_match.groups()
        normalized = f"https://{host}/{path}"
    if normalized.endswith(".git"):
        normalized = normalized[:-4]
    return normalized


def get_slsa_dependency_list(predicate: dict[str, Any]) -> list[dict[str, Any]]:
    """Return dependencies from either the SLSA v0.2 or v1 predicate shape."""
    materials = predicate.get("materials", [])
    if materials:
        return materials
    build_definition = predicate.get("buildDefinition", {})
    return build_definition.get("resolvedDependencies", [])


def extract_container_parent_image(predicate: dict[str, Any]) -> dict[str, str]:
    """Extract the first non-Dockerfile OCI parent image from SLSA provenance."""
    for dependency in get_slsa_dependency_list(predicate):
        if not isinstance(dependency, dict):
            continue
        uri = str(dependency.get("uri", ""))
        uri_lower = uri.lower()
        if (
            not uri_lower.startswith(("pkg:docker/", "pkg:oci/", "oci://"))
            or "dockerfile" in uri_lower
        ):
            continue
        digest = dependency.get("digest", {})
        if not isinstance(digest, dict) or not digest.get("sha256"):
            continue
        return {
            "parent_image_uri": uri,
            "parent_image_digest": f"sha256:{digest['sha256']}",
        }
    return {}


def extract_image_source_provenance(predicate: dict[str, Any]) -> dict[str, str]:
    """Extract source URI, revision, and source file from SLSA provenance."""
    result: dict[str, str] = {}
    metadata = predicate.get("metadata", {})
    vcs = metadata.get("https://mobyproject.org/buildkit@v1#metadata", {}).get(
        "vcs",
        {},
    )
    if not vcs:
        vcs = (
            predicate.get("runDetails", {})
            .get("metadata", {})
            .get("buildkit_metadata", {})
            .get("vcs", {})
        )

    build_definition = predicate.get("buildDefinition", {})
    external_parameters = build_definition.get("externalParameters", {})
    dependencies = get_slsa_dependency_list(predicate)

    source_uri = vcs.get("source") or external_parameters.get("source")
    if source_uri:
        result["source_uri"] = normalize_vcs_url(str(source_uri))

    revision = vcs.get("revision")
    if not revision:
        for dependency in dependencies:
            digest = dependency.get("digest", {}) if isinstance(dependency, dict) else {}
            if isinstance(digest, dict) and digest.get("gitCommit"):
                revision = digest["gitCommit"]
                break
    if revision:
        result["source_revision"] = str(revision)

    entry_point = (
        predicate.get("invocation", {}).get("configSource", {}).get("entryPoint")
        or external_parameters.get("entryPoint")
        or external_parameters.get("configSource", {}).get("path")
        or "Dockerfile"
    )
    if "source_uri" in result:
        dockerfile_directory = (
            str(vcs.get("localdir:dockerfile") or "").removeprefix("./").rstrip("/")
        )
        result["source_file"] = (
            f"{dockerfile_directory}/{entry_point}"
            if dockerfile_directory
            else str(entry_point)
        )
    return result


def extract_workflow_path_from_ref(workflow_ref: str | None) -> str | None:
    """Extract ``path`` from an ``owner/repo/path@revision`` workflow ref."""
    if not workflow_ref:
        return None
    parts = workflow_ref.split("@", 1)[0].split("/", 2)
    return parts[2] if len(parts) == 3 else None
