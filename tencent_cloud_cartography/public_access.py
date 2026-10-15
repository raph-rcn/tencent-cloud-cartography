"""Anonymous COS access from collected bucket policies and ACL configuration."""

import json

from .cam import parse_document
from .cos import ALL_USERS
from .model import stable_id
from .permissions import evaluate, identities, scopes
from .transport import CollectionError

SOURCE = "analysis.cos-anonymous-access"
ACTIONS = {
    "cos:GetObject": "READ_OBJECT",
    "cos:PutObject": "WRITE_OBJECT",
    "cos:DeleteObject": "DELETE_OBJECT",
    "cos:GetBucket": "LIST_BUCKET",
    "cos:GetBucketACL": "READ_BUCKET_ACL",
    "cos:PutBucketACL": "WRITE_BUCKET_ACL",
}
ACL_ACTIONS = {
    "READ": {"cos:GetBucket"},
    "WRITE": {"cos:PutObject", "cos:DeleteObject"},
    "READ_ACP": {"cos:GetBucketACL"},
    "WRITE_ACP": {"cos:PutBucketACL"},
}
ACL_ACTIONS["FULL_CONTROL"] = set().union(*ACL_ACTIONS.values())


def anonymous(principal):
    if principal == "*":
        return True
    if not isinstance(principal, dict):
        return None
    qcs = principal.get("qcs", [])
    if any(
        value in {"*", "qcs::cam::anyone:anyone", "qcs::cam::anonymous:anonymous"} for value in qcs
    ):
        return True
    if any(value.startswith("qcs::cam::uin/") for value in qcs) or set(principal) <= {
        "qcs",
        "service",
        "federated",
    }:
        # An authenticated account/service is not the anonymous requester.
        if not any("*" in value for value in qcs):
            return False
    return None


def statements(graph, bucket, outgoing):
    result, complete = [], bool(bucket["properties"].get("policy_collected"))
    document = bucket["properties"].get("policy_document")
    if document:
        try:
            parsed = parse_document(document, cos=True)
            for index, row in enumerate(parsed["statement"]):
                applicable = anonymous(row.get("principal"))
                if applicable is False:
                    continue
                sid = stable_id(
                    bucket["account"], "global", "cam.policystatement", f"{bucket['id']}/{index}"
                )
                if sid not in graph.nodes:
                    complete = False
                    continue
                selected = dict(row)
                if applicable is True:
                    selected.pop("principal", None)
                result.append((sid, selected))
        except CollectionError:
            complete = False
    elif not bucket["properties"].get("policy_absent"):
        complete = False
    acl_complete = bucket["properties"].get("acl_collected") is True
    resource = identities(bucket)
    if not resource:
        return result, False
    object_scope, bucket_scope = resource[0], resource[0][:-1]
    for edge in outgoing.get(bucket["id"], []):
        if edge["relationship"] != "HAS_ACL_GRANT":
            continue
        grant = graph.nodes[edge["target"]]
        props = grant["properties"]
        if grant["kind"] != "cos.aclgrant" or (grant["account"], grant["region"]) != (
            bucket["account"],
            bucket["region"],
        ):
            acl_complete = False
            continue
        if props.get("URI") != ALL_USERS and props.get("ID") != "qcs::cam::anyone:anyone":
            continue
        actions = ACL_ACTIONS.get(props.get("permission"))
        if actions is None:
            acl_complete = False
            continue
        for action in actions:
            result.append(
                (
                    grant["id"],
                    dict(
                        effect="allow",
                        action=[action],
                        resource=[
                            object_scope
                            if action in {"cos:PutObject", "cos:DeleteObject"}
                            else bucket_scope
                        ],
                    ),
                )
            )
        if props.get("permission") in {"READ", "FULL_CONTROL"}:
            result.append(
                (
                    grant["id"],
                    dict(
                        effect="allow",
                        action=["cos:GetObject"],
                        resource=[object_scope],
                        condition={"object_acl_inherits_bucket": True},
                    ),
                )
            )
    return result, complete and acl_complete


def analyze(graph, max_decisions=25000, context=None):
    from .authorization import context_values

    context = context_values(context)
    obsolete = {nid for nid, n in graph.nodes.items() if n["kind"] == "cos.publicaccessdecision"}
    graph.nodes = {nid: n for nid, n in graph.nodes.items() if nid not in obsolete}
    graph.edges = {
        eid: e
        for eid, e in graph.edges.items()
        if e["source"] not in obsolete and e["target"] not in obsolete
    }
    graph.coverage = [r for r in graph.coverage if r.get("action") != "AnalyzeCosAnonymousAccess"]
    outgoing = {}
    for edge in graph.edges.values():
        outgoing.setdefault(edge["source"], []).append(edge)
    for bucket in list(graph.nodes.values()):
        if bucket["kind"] != "cos.bucket" or bucket["status"] != "enriched":
            continue
        selected, complete = statements(graph, bucket, outgoing)
        canonical = identities(bucket)
        if not canonical:
            complete = False
        count, incomplete = 0, not complete
        for action, capability in ACTIONS.items():
            choices = (
                scopes(bucket, selected, action)
                if action in {"cos:GetObject", "cos:PutObject", "cos:DeleteObject"}
                else [canonical[0][:-1]]
                if canonical
                else []
            )
            for scope in choices:
                decision, evidence = evaluate(selected, action, scope, complete, context)
                decision = decision.replace(
                    "collected_identity_policies", "collected_bucket_configuration"
                )
                incomplete |= decision == "incomplete"
                rid = stable_id(bucket["id"], action, scope)
                nid = graph.add(
                    bucket["account"],
                    bucket["region"],
                    "cos.publicaccessdecision",
                    rid,
                    f"Anonymous {capability}: {decision}",
                    source=SOURCE,
                )
                graph.nodes[nid]["properties"].update(
                    action=action,
                    capability=capability,
                    resource_scope=scope,
                    decision=decision,
                    requester="anonymous",
                    evaluation_scope="collected_bucket_policy_and_acl",
                    effective_access_verified=False,
                    object_acl_overrides_evaluated=False,
                    evaluated_context=json.dumps(context, sort_keys=True),
                    conditions=json.dumps([e[2] for e in evidence if e[2]], sort_keys=True),
                    configuration_complete=complete,
                )
                graph.edge(bucket["id"], nid, "HAS_PUBLIC_ACCESS_ANALYSIS", SOURCE)
                for sid, *_ in evidence:
                    graph.edge(nid, sid, "BASED_ON_CONFIGURATION", SOURCE)
                count += 1
        graph.coverage.append(
            dict(
                account=bucket["account"],
                region=bucket["region"],
                service="analysis",
                action="AnalyzeCosAnonymousAccess",
                detail=bucket["resource_id"],
                status="error" if incomplete else "complete",
                error="IncompleteCosAccessConfiguration" if incomplete else "",
                count=count,
                request_ids=[],
            )
        )

    from .cos_account import analyze as summarize_accounts
    from .cos_object_acls import analyze as analyze_object_acls

    analyze_object_acls(graph, context=context, max_decisions=max_decisions)
    summarize_accounts(graph)
