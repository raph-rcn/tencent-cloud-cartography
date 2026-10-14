"""Atomic private snapshots and an optional isolated Neo4j mirror."""

import json
import os
import tempfile
from pathlib import Path


def save(snapshot, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix=".snapshot-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(snapshot, stream, ensure_ascii=False, indent=2, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def validate(data):
    """Validate graph structure before publication, independently of either backend."""
    try:
        if data.get("schema_version") != 1 or not all(
            isinstance(data.get(k), list) for k in ("nodes", "edges", "accounts", "coverage")
        ):
            raise ValueError("Unsupported snapshot schema")
        if (
            data.get("mode") not in {"live", "demo", "setup"}
            or data.get("status") not in {"complete", "partial"}
            or not isinstance(data.get("created_at"), str)
        ):
            raise ValueError("Invalid snapshot metadata")
        ids = [n["id"] for n in data["nodes"]]
        if data["mode"] == "setup" and any(data[k] for k in ("nodes", "edges", "accounts")):
            raise ValueError("Setup state must not contain inventory")
        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate resource IDs")
        id_set = set(ids)
        for node in data["nodes"]:
            if (
                not all(
                    isinstance(node[k], str) and node[k]
                    for k in ("id", "account", "region", "kind", "resource_id", "name", "status")
                )
                or not isinstance(node["properties"], dict)
                or not isinstance(node["sources"], list)
            ):
                raise ValueError("Invalid resource schema")
        edge_ids = set()
        for edge in data["edges"]:
            if edge["source"] not in id_set or edge["target"] not in id_set:
                raise ValueError("Invalid graph endpoints")
            if edge["id"] in edge_ids or not all(
                isinstance(edge[k], str) for k in ("id", "relationship", "provenance")
            ):
                raise ValueError("Invalid relationship schema")
            edge_ids.add(edge["id"])
        account_ids = [a["id"] for a in data["accounts"]]
        if len(account_ids) != len(set(account_ids)) or not all(
            isinstance(a.get("display"), str) for a in data["accounts"]
        ):
            raise ValueError("Invalid accounts")
        if not isinstance(data.get("unresolved"), int):
            raise ValueError("Invalid coverage metadata")
        json.dumps(data, allow_nan=False)
        return data
    except (KeyError, TypeError, AttributeError) as exc:
        raise ValueError("Invalid snapshot structure") from exc


def load(path):
    # Read once: an atomic writer may replace the pathname while we are reading.
    with Path(path).open("rb") as stream:
        raw = stream.read(100_000_001)
    if len(raw) > 100_000_000:
        raise ValueError("Snapshot exceeds 100 MB")
    return validate(json.loads(raw))


def mirror(snapshot, uri, user=None, password=None, database=None):
    from .neo4j import mirror as publish

    return publish(snapshot, uri, user, password, database)
