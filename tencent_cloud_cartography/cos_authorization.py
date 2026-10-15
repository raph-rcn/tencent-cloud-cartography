"""Named signed-principal COS policy/ACL decisions, separate from unsigned access."""

import json

from .authorization import (
    ANONYMOUS,
    DEFAULT_ANALYSIS_LIMIT,
    analysis_limit,
    attach_evidence,
    boundary_gate,
    combine,
    context_values,
    evaluate,
    identity_statements,
    index,
    limit_record,
    normalize_resource,
    principal_match,
    replace_generated,
)
from .cam import parse_document
from .cos import ALL_USERS
from .model import stable_id
from .permissions import action_matches, identities
from .public_access import ACL_ACTIONS, ACTIONS
from .public_access import statements as anonymous_statements
from .transport import CollectionError

SOURCE = "analysis.cos-named-authorization"
OBJECT_ACTIONS = {
    "cos:GetObject",
    "cos:PutObject",
    "cos:DeleteObject",
    "cos:GetObjectACL",
    "cos:PutObjectACL",
}


def bucket_statements(graph, bucket, principal, outgoing, anonymous=False):
    if anonymous:
        return anonymous_statements(graph, bucket, outgoing)
    rows, complete = [], bucket["properties"].get("policy_collected") is True
    raw = bucket["properties"].get("policy_document")
    if raw:
        try:
            doc = parse_document(raw, cos=True)
            for i, row in enumerate(doc["statement"]):
                sid = stable_id(
                    bucket["account"], "global", "cam.policystatement", f"{bucket['id']}/{i}"
                )
                if sid not in graph.nodes or "principal" not in row:
                    complete = False
                    continue
                selected = dict(row)
                selector = selected["principal"]
                account_expressions = {
                    f"qcs::cam::uin/{principal['account']}:root",
                    f"qcs::cam::uin/{principal['account']}:uin/{principal['account']}",
                }
                # An account grant delegates through the parent account. It is
                # not a direct grant to every named user in that namespace.
                delegated = isinstance(selector, dict) and bool(
                    set(selector.get("qcs", [])) & account_expressions
                )
                direct = dict(selector) if isinstance(selector, dict) else selector
                if delegated:
                    direct["qcs"] = [
                        expr for expr in selector.get("qcs", []) if expr not in account_expressions
                    ]
                selected["_account_delegation"] = (
                    delegated and principal_match(direct, principal, graph, outgoing) is not True
                )
                selected["_principal_match"] = principal_match(
                    selected.pop("principal"), principal, graph, outgoing
                )
                if selected["_principal_match"] is False:
                    continue
                rows.append((sid, selected))
        except CollectionError:
            complete = False
    elif bucket["properties"].get("policy_absent") is not True:
        complete = False
    complete &= bucket["properties"].get("acl_collected") is True
    canonical = identities(bucket)
    if not canonical:
        return rows, False
    for edge in outgoing.get(bucket["id"], ()):
        if edge["relationship"] != "HAS_ACL_GRANT":
            continue
        grant = graph.nodes[edge["target"]]
        props = grant["properties"]
        if grant["kind"] != "cos.aclgrant" or (grant["account"], grant["region"]) != (
            bucket["account"],
            bucket["region"],
        ):
            complete = False
            continue
        if props.get("URI") == ALL_USERS or props.get("ID") in ANONYMOUS:
            continue  # Unsigned route is evaluated separately.
        if props.get("ID"):
            match = principal_match({"qcs": [props["ID"]]}, principal, graph, outgoing)
        else:
            match = None
        if match is False:
            continue
        actions = ACL_ACTIONS.get(props.get("permission"))
        if actions is None:
            complete = False
            continue
        for action in actions | (
            {"cos:GetObject"} if props.get("permission") in {"READ", "FULL_CONTROL"} else set()
        ):
            row = dict(
                effect="allow",
                action=[action],
                resource=[canonical[0] if action in OBJECT_ACTIONS else canonical[0][:-1]],
                _principal_match=match,
            )
            if action in OBJECT_ACTIONS:
                row["condition"] = {"object_acl_inherits_bucket": True}
            rows.append((grant["id"], row))
    return rows, complete


def selections(bucket, rows, action, objects=None):
    canonical = identities(bucket)
    if not canonical:
        return []
    if action not in OBJECT_ACTIONS:
        # Both forms appear in provider bucket-operation examples. Treat these as
        # aliases of one bucket operation, not as an object read scope.
        return [[canonical[0][:-1], canonical[0]]]
    choices = (
        set(objects or {}) if action in {"cos:GetObjectACL", "cos:PutObjectACL"} else {canonical[0]}
    )
    if action == "cos:GetObject":
        choices.update(objects or {})
    prefix = canonical[0][:-1]
    for _, row in rows:
        if row["effect"] != "allow":
            continue
        try:
            if not any(action_matches(expr, action) for expr in row["action"]):
                continue
            for expr in row["resource"]:
                normalized = normalize_resource(
                    expr, row.get("_scope_owner", bucket["account"]), bucket
                )
                if normalized.startswith(prefix) and len(normalized) > len(prefix):
                    choices.add(normalized)
        except CollectionError:
            continue
    return sorted(choices)


def owner_conflict(bucket):
    raw = bucket["properties"].get("acl_owner_id", "")
    if raw.startswith("qcs::cam::uin/"):
        return raw != f"qcs::cam::uin/{bucket['account']}:uin/{bucket['account']}"
    return False  # AppId/opaque owner metadata is never converted to a UIN.


def analyze(graph, context=None, max_decisions=DEFAULT_ANALYSIS_LIMIT):
    context = context_values(context)
    max_decisions = analysis_limit(max_decisions)
    generated = 0
    replace_generated(graph, {"cos.authorizationdecision"}, {"AnalyzeCosNamedAuthorization"})
    outgoing = index(graph)
    unsigned = {}
    for node in graph.nodes.values():
        if node["kind"] == "cos.publicaccessdecision":
            props = node["properties"]
            unsigned.setdefault(
                (node["account"], node["region"], props.get("action"), props.get("resource_scope")),
                [],
            ).append(node["id"])
    principals = [
        n
        for n in graph.nodes.values()
        if n["kind"] in {"cam.user", "cam.role"} and n["status"] == "enriched"
    ]
    buckets = [
        n for n in graph.nodes.values() if n["kind"] == "cos.bucket" and n["status"] == "enriched"
    ]
    from .cos_object_acls import current_objects, scoped_rows

    for principal in principals:
        identity_rows, identity_complete = identity_statements(graph, principal, outgoing)
        for bucket in buckets:
            resource_rows, resource_complete = bucket_statements(graph, bucket, principal, outgoing)
            anonymous_rows, anonymous_complete = bucket_statements(
                graph, bucket, principal, outgoing, True
            )
            objects = current_objects(graph, bucket) if identities(bucket) else {}
            count, unresolved = 0, False
            actions = dict(ACTIONS)
            if objects:
                actions.update(
                    {"cos:GetObjectACL": "READ_OBJECT_ACL", "cos:PutObjectACL": "WRITE_OBJECT_ACL"}
                )
            for action, capability in actions.items():
                for scope in selections(
                    bucket,
                    [
                        *(
                            (sid, {**row, "_scope_owner": principal["account"]})
                            for sid, row in identity_rows
                        ),
                        *resource_rows,
                        *anonymous_rows,
                    ],
                    action,
                    objects,
                ):
                    obj = (
                        objects.get(scope)
                        if isinstance(scope, str)
                        and action in {"cos:GetObject", "cos:GetObjectACL", "cos:PutObjectACL"}
                        else None
                    )
                    scoped_resource_rows, scoped_anonymous_rows = resource_rows, anonymous_rows
                    scoped_resource_complete, scoped_anonymous_complete = (
                        resource_complete,
                        anonymous_complete,
                    )
                    acl_complete = False
                    if obj:
                        scoped_resource_rows, acl_complete = scoped_rows(
                            graph, bucket, obj, principal, outgoing, resource_rows
                        )
                        scoped_anonymous_rows, anonymous_acl_complete = scoped_rows(
                            graph, bucket, obj, principal, outgoing, anonymous_rows, True
                        )
                        policy_complete = bucket["properties"].get(
                            "policy_collected"
                        ) is True and bool(
                            bucket["properties"].get("policy_document")
                            or bucket["properties"].get("policy_absent")
                        )
                        scoped_resource_complete = policy_complete and acl_complete
                        scoped_anonymous_complete = policy_complete and anonymous_acl_complete
                    if generated >= max_decisions:
                        limit_record(
                            graph, "AnalyzeCosNamedAuthorization", generated, max_decisions
                        )
                        return
                    identity = evaluate(
                        identity_rows,
                        action,
                        scope,
                        context,
                        identity_complete,
                        principal["account"],
                        bucket,
                    )
                    resource = evaluate(
                        [
                            row
                            for row in scoped_resource_rows
                            if principal["account"] != bucket["account"]
                            or not row[1].get("_account_delegation")
                            or row[1]["effect"] == "deny"
                        ],
                        action,
                        scope,
                        context,
                        scoped_resource_complete,
                        bucket["account"],
                        bucket,
                    )
                    boundary = boundary_gate(
                        graph, principal, outgoing, action, scope, context, bucket
                    )
                    if (
                        action in OBJECT_ACTIONS
                        and not acl_complete
                        and resource.allow is False
                        and resource.deny is not True
                    ):
                        resource.grants_complete = False
                        resource.reasons.append("object_acl_grants_not_collected")
                    public = evaluate(
                        scoped_anonymous_rows,
                        action,
                        scope,
                        context,
                        scoped_anonymous_complete,
                        bucket["account"],
                        bucket,
                    )
                    cross = principal["account"] != bucket["account"]
                    gates = [identity, resource, boundary]
                    reasons = []
                    base, reason = combine([identity, resource], intersection=cross)
                    # Identity policy grants are constrained by the boundary.
                    # A resource-only grant's interaction with an implicit boundary
                    # deny has no verified Tencent contract; do not import AWS rules.
                    if boundary.deny is True:
                        result, reason = "denied", "explicit_boundary_deny"
                    elif base == "denied":
                        result = base
                    elif not boundary.complete:
                        result, reason = (
                            "unknown",
                            "permission_boundary_presence_or_document_unknown",
                        )
                    elif boundary.decision == "denied":
                        if not cross and resource.allow is not False:
                            result, reason = (
                                "unknown",
                                "resource_grant_boundary_interaction_unverified",
                            )
                        else:
                            result, reason = "denied", "permission_boundary_has_no_allow"
                    else:
                        result = (
                            base
                            if base == "unknown"
                            else (
                                "conditional"
                                if base == "conditional" or boundary.decision == "conditional"
                                else base
                            )
                        )
                    from .session_policy import gate as session_gate

                    session = session_gate(
                        graph, principal, outgoing, action, scope, context, bucket
                    )
                    if session is not None:
                        gates.append(session)
                        if session.deny is True:
                            result, reason = "denied", "explicit_declared_session_deny"
                        elif result != "denied":
                            if session.decision == "denied":
                                result, reason = "denied", "declared_session_has_no_allow"
                            elif session.decision == "unknown":
                                result, reason = (
                                    "unknown",
                                    "declared_session_constraints_unresolved",
                                )
                            elif session.decision == "conditional" and result == "allowed":
                                result, reason = "conditional", "declared_session_conditions"
                    if (
                        action in OBJECT_ACTIONS
                        and not acl_complete
                        and result == "denied"
                        and reason == "no_collected_grant"
                    ):
                        result, reason = "unknown", "object_acl_grants_not_collected"
                    if (
                        public.decision == "denied"
                        and public.deny is not True
                        and action in OBJECT_ACTIONS
                        and not acl_complete
                    ):
                        public.grants_complete = False
                        public.reasons.append("object_acl_grants_not_collected")
                    if owner_conflict(bucket) and reason not in {
                        "explicit_deny",
                        "explicit_boundary_deny",
                    }:
                        result, reason = "unknown", "bucket_owner_metadata_conflict"
                    for gate in gates:
                        reasons.extend(gate.reasons)
                    reasons.append(reason)
                    unresolved |= result == "unknown"
                    nid = graph.add(
                        bucket["account"],
                        bucket["region"],
                        "cos.authorizationdecision",
                        stable_id(
                            principal["id"], bucket["id"], action, json.dumps(scope, sort_keys=True)
                        ),
                        f"Signed {capability}: {result}",
                        source=SOURCE,
                    )
                    props = graph.nodes[nid]["properties"]
                    props.update(
                        action=action,
                        capability=capability,
                        decision=result,
                        decision_reason=reason,
                        resource_scope=json.dumps(scope) if isinstance(scope, list) else scope,
                        principal_account=principal["account"],
                        principal_id=principal["resource_id"],
                        target_account=bucket["account"],
                        cross_account=cross,
                        evaluation_scope="collected_configuration_for_signed_principal",
                        cross_account_gate="identity_and_resource"
                        if cross
                        else "identity_or_resource",
                        anonymous_route_decision=public.decision,
                        session_constraints="operator_declared_policy_evaluated"
                        if session is not None
                        else "unknown",
                        live_session_verified=False,
                        effective_access_decision="unknown",
                        effective_access_verified=False,
                        data_access_verified=False,
                        object_acls_collected=obj is not None,
                        selected_acl_inheritance_complete=acl_complete,
                        boundary_evaluated=boundary.complete,
                        identity_collection_complete=identity.complete,
                        resource_collection_complete=resource.complete,
                        evaluated_context=json.dumps(context, sort_keys=True),
                        context_source="operator_declared" if context else "unspecified",
                        unresolved_reasons=json.dumps(sorted(set(reasons))),
                        authorization_evidence=attach_evidence(
                            graph, nid, [*gates, public], SOURCE
                        ),
                    )
                    graph.edge(principal["id"], nid, "HAS_COS_AUTHORIZATION_ANALYSIS", SOURCE)
                    graph.edge(nid, bucket["id"], "TARGETS_RESOURCE", SOURCE)
                    if obj:
                        graph.edge(nid, obj["id"], "USES_SELECTED_OBJECT_ACL", SOURCE)
                    # Reuse existing anonymous configuration nodes only when the
                    # exact action AND scope agree; never attach a broader prefix.
                    for selected_scope in scope if isinstance(scope, list) else [scope]:
                        for alt in unsigned.get(
                            (bucket["account"], bucket["region"], action, selected_scope), ()
                        ):
                            graph.edge(nid, alt, "ALTERNATIVE_UNSIGNED_ANALYSIS", SOURCE)
                    count += 1
                    generated += 1
            graph.coverage.append(
                dict(
                    account=principal["account"],
                    region=bucket["region"],
                    service="analysis",
                    action="AnalyzeCosNamedAuthorization",
                    detail=json.dumps(
                        dict(principal=principal["id"], bucket=bucket["id"]), sort_keys=True
                    ),
                    status="error" if unresolved or not count else "complete",
                    error="UnresolvedCosAuthorizationEvidence" if unresolved or not count else "",
                    count=count,
                    request_ids=[],
                )
            )
