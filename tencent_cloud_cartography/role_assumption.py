"""Configured named-CAM role assumption and paths; never call STS AssumeRole."""

import json
from collections import deque

from .authorization import (
    DEFAULT_ANALYSIS_LIMIT,
    Gate,
    analysis_limit,
    attach_evidence,
    boundary_gate,
    combine,
    context_values,
    evaluate,
    identity_statements,
    index,
    limit_record,
    principal_match,
    replace_generated,
)
from .cam import parse_document
from .model import stable_id
from .permissions import identities
from .transport import CollectionError

SOURCE = "analysis.role-assumption"


def trust_statements(graph, role, caller, outgoing):
    complete = any(
        r.get("service") == "cam"
        and r.get("action") == "GetRole"
        and r.get("account") == role["account"]
        and r.get("detail") == role["resource_id"]
        and r.get("status") in {"complete", "empty"}
        for r in graph.coverage
    )
    rows = []
    try:
        doc = parse_document(role["properties"].get("trust_document"), trust=True)
        for i, row in enumerate(doc["statement"]):
            sid = stable_id(role["account"], "global", "cam.truststatement", f"{role['id']}/{i}")
            if sid not in graph.nodes:
                complete = False
                continue
            selected = dict(row)
            selected["_principal_match"] = principal_match(
                selected.pop("principal"), caller, graph, outgoing, trust=True
            )
            rows.append((sid, selected))
    except CollectionError:
        complete = False
    return rows, complete


def analyze(graph, context=None, max_decisions=DEFAULT_ANALYSIS_LIMIT):
    context = context_values(context)
    max_decisions = analysis_limit(max_decisions)
    generated = 0
    replace_generated(
        graph,
        {"cam.assumptiondecision", "cam.authorizationpath"},
        {"AnalyzeRoleAssumption", "AnalyzeAuthorizationPaths"},
    )
    outgoing = index(graph)
    callers = [
        n
        for n in graph.nodes.values()
        if n["kind"] in {"cam.user", "cam.role"} and n["status"] == "enriched"
    ]
    roles = [n for n in callers if n["kind"] == "cam.role"]
    for caller in callers:
        identity_rows, identity_complete = identity_statements(graph, caller, outgoing)
        count, unknown = 0, False
        for role in roles:
            if generated >= max_decisions:
                limit_record(graph, "AnalyzeRoleAssumption", generated, max_decisions)
                paths(graph, context, max_decisions)
                return
            canonical = identities(role)
            trust_rows, trust_complete = trust_statements(graph, role, caller, outgoing)
            attrs = dict(context)
            # Provider-documented request identity, derived from collected owner
            # and UIN/RoleId. Operator context cannot overwrite this field.
            attrs["qcs:assume_principal_arn"] = (
                f"qcs::cam::uin/{caller['account']}:{'uin' if caller['kind'] == 'cam.user' else 'role'}/{caller['resource_id']}"
            )
            identity = evaluate(
                identity_rows,
                "sts:AssumeRole",
                canonical,
                attrs,
                identity_complete,
                caller["account"],
                role,
            )
            trust = evaluate(
                trust_rows,
                "sts:AssumeRole",
                canonical,
                attrs,
                trust_complete,
                role["account"],
                role,
            )
            boundary = boundary_gate(
                graph, caller, outgoing, "sts:AssumeRole", canonical, attrs, role
            )
            if not canonical:
                identity, trust, boundary = [
                    Gate(complete=False, reasons=["unresolved_role_resource_identity"])
                    for _ in range(3)
                ]
            result, reason = combine([identity, trust, boundary], intersection=True)
            unknown |= result == "unknown"
            nid = graph.add(
                role["account"],
                "global",
                "cam.assumptiondecision",
                stable_id(caller["id"], role["id"]),
                f"Assume {role['name']}: {result}",
                source=SOURCE,
            )
            graph.nodes[nid]["properties"].update(
                action="sts:AssumeRole",
                decision=result,
                decision_reason=reason,
                caller_account=caller["account"],
                caller_id=caller["resource_id"],
                role_id=role["resource_id"],
                cross_account=caller["account"] != role["account"],
                resource_scope=json.dumps(canonical),
                evaluation_scope="collected_named_cam_identity_boundary_and_role_trust",
                trust_evaluated=trust.complete,
                boundary_evaluated=boundary.complete,
                session_constraints="unknown",
                effective_access_decision="unknown",
                effective_assumption_verified=False,
                resulting_session_policy="unknown",
                resulting_role_boundary_requires_separate_resource_analysis=True,
                evaluated_context=json.dumps(attrs, sort_keys=True),
                unresolved_reasons=json.dumps(
                    sorted({r for g in (identity, trust, boundary) for r in g.reasons})
                ),
                authorization_evidence=attach_evidence(
                    graph, nid, [identity, trust, boundary], SOURCE
                ),
            )
            graph.edge(caller["id"], nid, "HAS_ASSUMPTION_ANALYSIS", SOURCE)
            graph.edge(nid, role["id"], "TARGETS_ROLE", SOURCE)
            count += 1
            generated += 1
        if count:
            graph.coverage.append(
                dict(
                    account=caller["account"],
                    region="global",
                    service="analysis",
                    action="AnalyzeRoleAssumption",
                    detail=caller["id"],
                    status="error" if unknown else "complete",
                    error="UnresolvedRoleAssumptionEvidence" if unknown else "",
                    count=count,
                    request_ids=[],
                )
            )
    paths(graph, context, max_decisions)


def paths(graph, context=None, max_decisions=DEFAULT_ANALYSIS_LIMIT):
    """One shortest witness per endpoint/decision class; cycles cannot loop forever."""
    replace_generated(graph, {"cam.authorizationpath"}, {"AnalyzeAuthorizationPaths"})
    out = index(graph)
    assumptions = {}
    permissions = {}
    states = {}
    generated = 0
    for caller in list(graph.nodes.values()):
        if caller["kind"] not in {"cam.user", "cam.role"}:
            continue
        for edge in out.get(caller["id"], ()):
            decision = graph.nodes[edge["target"]]
            if decision["properties"].get("decision") == "denied":
                continue
            if (
                edge["relationship"] == "HAS_ASSUMPTION_ANALYSIS"
                and decision["kind"] == "cam.assumptiondecision"
            ):
                targets = [
                    e["target"]
                    for e in out.get(decision["id"], ())
                    if e["relationship"] == "TARGETS_ROLE"
                ]
                if len(targets) == 1:
                    assumptions.setdefault(caller["id"], []).append((targets[0], decision))
            elif (
                edge["relationship"] == "HAS_COS_AUTHORIZATION_ANALYSIS"
                and decision["kind"] == "cos.authorizationdecision"
            ):
                permissions.setdefault(caller["id"], []).append(decision)
                states[decision["id"]] = decision["properties"]["decision"]
            elif (
                edge["relationship"] == "HAS_PERMISSION_ANALYSIS"
                and decision["kind"] == "cam.permissiondecision"
            ):
                targets = [
                    graph.nodes[e["target"]]
                    for e in out.get(decision["id"], ())
                    if e["relationship"] == "TARGETS_RESOURCE"
                ]
                if len(targets) != 1 or targets[0]["kind"] == "cos.bucket":
                    continue  # A legacy COS identity match cannot bypass the joined COS result.
                props = decision["properties"]
                scope = props.get("resource_scope")
                if not isinstance(scope, str):
                    continue
                scope = json.loads(scope) if scope.startswith("[") else scope
                rows, complete = identity_statements(graph, caller, out)
                identity = evaluate(
                    rows, props["action"], scope, context, complete, caller["account"], targets[0]
                )
                boundary = boundary_gate(
                    graph, caller, out, props["action"], scope, context, targets[0]
                )
                state, _ = combine([identity, boundary], intersection=True)
                if state != "denied":
                    permissions.setdefault(caller["id"], []).append(decision)
                    states[decision["id"]] = state
    rank = {"allowed": 0, "conditional": 1, "unknown": 2}
    for start in sorted(
        n["id"]
        for n in graph.nodes.values()
        if n["kind"] in {"cam.user", "cam.role"} and n["status"] == "enriched"
    ):
        queue = deque([(start, "allowed", [])])
        visited, emitted, count = {(start, "allowed")}, set(), 0
        while queue:
            current, state, witness = queue.popleft()
            if witness:
                for permission in permissions.get(current, ()):
                    if generated >= max_decisions:
                        limit_record(graph, "AnalyzeAuthorizationPaths", generated, max_decisions)
                        return
                    result = max((state, states[permission["id"]]), key=rank.__getitem__)
                    key = (permission["id"], result)
                    if key in emitted:
                        continue
                    emitted.add(key)
                    refs = [*witness, permission["id"]]
                    nid = graph.add(
                        graph.nodes[start]["account"],
                        permission["region"],
                        "cam.authorizationpath",
                        stable_id(start, permission["id"], result),
                        "Role permission path: " + result,
                        source=SOURCE,
                    )
                    graph.nodes[nid]["properties"].update(
                        decision=result,
                        evaluation_scope="configured_role_chain_to_cos_permission"
                        if permission["kind"] == "cos.authorizationdecision"
                        else "configured_role_chain_to_identity_boundary_permission",
                        action=permission["properties"]["action"],
                        resource_scope=permission["properties"]["resource_scope"],
                        assumption_hops=len(witness),
                        witness_decision_ids=json.dumps(refs),
                        path_selection="shortest_witness_per_endpoint_and_decision_class",
                        all_alternative_paths_enumerated=False,
                        joint_conditions_satisfiability="not_verified",
                        service_launch_or_privileged_operation_invoked=False,
                        session_constraints="unknown",
                        effective_access_decision="unknown",
                        effective_access_verified=False,
                    )
                    graph.edge(start, nid, "HAS_CONFIGURED_AUTHORIZATION_PATH", SOURCE)
                    for ref in refs:
                        graph.edge(nid, ref, "SUPPORTED_BY_DECISION", SOURCE)
                    for e in out.get(permission["id"], ()):
                        if e["relationship"] == "TARGETS_RESOURCE":
                            graph.edge(nid, e["target"], "TARGETS_RESOURCE", SOURCE)
                    count += 1
                    generated += 1
            for target, decision in sorted(assumptions.get(current, ()), key=lambda v: v[1]["id"]):
                result = max((state, decision["properties"]["decision"]), key=rank.__getitem__)
                if (target, result) not in visited:
                    visited.add((target, result))
                    queue.append((target, result, [*witness, decision["id"]]))
        if count:
            graph.coverage.append(
                dict(
                    account=graph.nodes[start]["account"],
                    region="global",
                    service="analysis",
                    action="AnalyzeAuthorizationPaths",
                    detail=start,
                    status="complete",
                    count=count,
                    request_ids=[],
                    all_alternative_paths_enumerated=False,
                )
            )
