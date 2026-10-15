"""Offline, operator-declared STS restrictions. Never acquire a token or assume a role."""

import json
import re
from pathlib import Path

from .authorization import evaluate
from .cam import _unique_object, parse_document
from .model import stable_id
from .transport import CollectionError

SOURCE = "operator.declared-session-policy"


def load(path):
    raw = Path(path).read_bytes()
    if len(raw) > 262144:
        raise ValueError("Session policy manifest exceeds 256 KiB")
    return validate(json.loads(raw, object_pairs_hook=_unique_object))


def validate(rows):
    if not isinstance(rows, list) or len(rows) > 100:
        raise ValueError("Provide at most 100 exact principal session policy declarations")
    selected, seen = [], set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"account", "kind", "principal_id", "policy"}:
            raise ValueError("Invalid session policy declaration")
        if (
            not isinstance(row["account"], str)
            or not re.fullmatch(r"[1-9][0-9]*", row["account"])
            or not isinstance(row["kind"], str)
            or row["kind"] not in {"cam.user", "cam.role"}
            or not isinstance(row["principal_id"], str)
            or not re.fullmatch(r"[1-9][0-9]*", row["principal_id"])
        ):
            raise ValueError("Invalid session policy principal")
        key = row["account"], row["kind"], row["principal_id"]
        if key in seen:
            raise ValueError(
                "Duplicate session policy principal; combine restrictions into one document"
            )
        seen.add(key)
        document = parse_document(json.dumps(row["policy"]))
        if any("principal" in r for r in document["statement"]):
            raise ValueError("Session policies cannot grant a different principal")
        selected.append({**row, "policy": document})
    return selected


def apply(graph, rows):
    selected = validate(rows)
    index = {
        (n["account"], n["kind"], n["resource_id"]): n
        for n in graph.nodes.values()
        if n["region"] == "global" and n["status"] == "enriched"
    }
    if any((r["account"], r["kind"], r["principal_id"]) not in index for r in selected):
        raise ValueError("Session declaration must name a collected principal in this snapshot")
    stale = {
        i
        for i, n in graph.nodes.items()
        if n["kind"] in {"cam.sessionpolicy", "cam.sessionpolicystatement"}
    }
    graph.nodes = {i: n for i, n in graph.nodes.items() if i not in stale}
    graph.edges = {
        i: e
        for i, e in graph.edges.items()
        if e["source"] not in stale and e["target"] not in stale
    }
    for row in selected:
        principal = index[row["account"], row["kind"], row["principal_id"]]
        nid = graph.add(
            row["account"],
            "global",
            "cam.sessionpolicy",
            stable_id(principal["id"], "session"),
            "Declared STS session restriction",
            source=SOURCE,
        )
        graph.nodes[nid]["properties"].update(
            policy_document=json.dumps(row["policy"], sort_keys=True),
            source_scope="operator_declared_hypothetical_session",
            live_session_verified=False,
        )
        graph.edge(principal["id"], nid, "HAS_DECLARED_SESSION_POLICY", SOURCE)
        for i, statement in enumerate(row["policy"]["statement"]):
            sid = graph.add(
                row["account"],
                "global",
                "cam.sessionpolicystatement",
                stable_id(nid, str(i)),
                source=SOURCE,
            )
            graph.nodes[sid]["properties"]["statement"] = json.dumps(statement, sort_keys=True)
            graph.edge(nid, sid, "HAS_SESSION_STATEMENT", SOURCE)


def gate(graph, principal, outgoing, action, scope, context, target):
    policies = [
        graph.nodes[e["target"]]
        for e in outgoing.get(principal["id"], ())
        if e["relationship"] == "HAS_DECLARED_SESSION_POLICY"
    ]
    if not policies:
        return None
    if len(policies) != 1:
        raise CollectionError("AmbiguousSessionPolicy")
    policy = policies[0]
    if (
        policy["kind"] != "cam.sessionpolicy"
        or policy["account"] != principal["account"]
        or policy["region"] != "global"
    ):
        raise CollectionError("InvalidSessionPolicyScope")
    document = parse_document(policy["properties"].get("policy_document"))
    if any("principal" in r for r in document["statement"]):
        raise CollectionError("InvalidSessionPolicyScope")
    statements = [
        (
            stable_id(
                principal["account"],
                "global",
                "cam.sessionpolicystatement",
                stable_id(policy["id"], str(i)),
            ),
            row,
        )
        for i, row in enumerate(document["statement"])
    ]
    return evaluate(
        statements,
        action,
        scope,
        context,
        all(sid in graph.nodes for sid, _ in statements),
        principal["account"],
        target,
    )
