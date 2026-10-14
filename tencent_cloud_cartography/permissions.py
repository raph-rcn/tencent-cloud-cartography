"""Conservative analysis of collected identity policies and selected QCS resources."""

import json
import re

from .cam import parse_document
from .model import stable_id
from .transport import CollectionError

SOURCE = "analysis.identity-policies"
RULES = {
    "cos.bucket": (("cos:GetObject", "READ"), ("cos:PutObject", "WRITE")),
    "ssm.secret": (("ssm:GetSecretValue", "GET_SECRET"),),
    "cam.role": (("cam:PassRole", "PASS_ROLE"),),
}


def pattern(value):
    # Tencent documents * matching; other expressions are not guessed.
    if not isinstance(value, str) or not value or "?" in value or "${" in value:
        raise CollectionError("UnsupportedPermissionExpression")
    return re.compile("^" + re.escape(value).replace(r"\*", ".*") + "$")


def action_matches(expression, action):
    expression = expression.removeprefix("name/")
    if expression != "*" and not re.fullmatch(r"[a-z0-9*]+:[A-Za-z0-9*]+", expression):
        raise CollectionError("UnsupportedPermissionAction")
    regex = pattern(expression)
    if regex.fullmatch(action):
        return True
    if re.fullmatch(regex.pattern, action, re.IGNORECASE):
        raise CollectionError("UnverifiedActionCase")
    return False


def matches_scope(expression, scope):
    """True: entire scope covered; None: possible subset overlap; False: disjoint."""
    regex = pattern(expression)
    if expression != "*":
        parts = expression.split(":", 5)
        if len(parts) != 6 or parts[0] != "qcs" or parts[1]:
            raise CollectionError("UnsupportedPermissionResource")
    if "*" not in scope:
        return bool(regex.fullmatch(scope))
    if expression == "*" or expression == scope:
        return True
    # Only prove wildcard-language inclusion for a single trailing wildcard.
    if expression.count("*") == 1 and expression.endswith("*"):
        prefix = expression[:-1]
        fixed = scope.split("*", 1)[0]
        if fixed.startswith(prefix):
            return True
        if not prefix.startswith(fixed):
            return False
        return None
    fixed = scope.split("*", 1)[0]
    other = expression.split("*", 1)[0]
    if not (fixed.startswith(other) or other.startswith(fixed)):
        return False
    return None


def evaluate(statements, action, scope, complete=True):
    evidence = []
    allows, denies, uncertain_allow, uncertain_deny = False, False, False, False
    unsupported = False
    for sid, statement in statements:
        try:
            if not any(action_matches(expr, action) for expr in statement["action"]):
                continue
            matches = [
                matches_scope(expr, value)
                for expr in statement["resource"]
                for value in (scope if isinstance(scope, list) else [scope])
            ]
            if all(value is False for value in matches):
                continue
            matched = True if True in matches else None
            condition = statement.get("condition")
            if condition or "principal" in statement:
                matched = None
            evidence.append((sid, statement["effect"], condition or {}, matched))
            if statement["effect"] == "deny":
                denies |= matched is True
                uncertain_deny |= matched is None
            else:
                allows |= matched is True
                uncertain_allow |= matched is None
        except CollectionError:
            unsupported = True
    if denies:
        decision = "explicit_deny"
    elif not complete or unsupported:
        decision = "incomplete"
    elif uncertain_deny and (allows or uncertain_allow):
        decision = "conditional"
    elif allows:
        decision = "allow_from_collected_identity_policies"
    elif uncertain_allow:
        decision = "conditional"
    else:
        decision = "implicit_deny_from_collected_identity_policies"
    return decision, evidence


def identities(node):
    """Never turn an AppId into a UIN, or infer a secret's creator."""
    owner, region, rid, props = (
        node["account"],
        node["region"],
        node["resource_id"],
        node["properties"],
    )
    if node["kind"] == "cos.bucket":
        match = re.fullmatch(r"[a-z0-9][a-z0-9-]*-([1-9][0-9]*)", rid)
        if match and region != "global":
            return [f"qcs::cos:{region}:uid/{match[1]}:{rid}/*"]
    elif node["kind"] == "ssm.secret":
        creator = props.get("CreateUinString") or props.get("CreateUin")
        if (
            creator
            and re.fullmatch(r"[1-9][0-9]*", str(creator))
            and not any(c in rid for c in "*?${}")
        ):
            return [f"qcs::ssm:{region}:uin/{owner}:secret/creatorUin/{creator}/{rid}"]
    elif node["kind"] == "cam.role":
        arn = props.get("RoleArn")
        name = props.get("RoleName")
        result = []
        prefix = f"qcs::cam::uin/{owner}:"
        permitted = {prefix + f"role/{rid}", prefix + f"role/tencentcloudServiceRole/{rid}"}
        if isinstance(name, str) and name and not any(c in name for c in "/*?:$"):
            result.append(prefix + f"roleName/{name}")
            permitted.update(
                {prefix + f"roleName/{name}", prefix + f"role/tencentcloudServiceRoleName/{name}"}
            )
        if arn in permitted:
            result.append(arn)
        return sorted(set(result))
    return []


def scopes(target, statements, action):
    candidates = identities(target)
    if target["kind"] == "cam.role":
        return [candidates] if candidates else []
    if target["kind"] != "cos.bucket" or not candidates:
        return candidates
    prefix = candidates[0][:-1]
    selected = set()
    for _, statement in statements:
        if statement["effect"] != "allow":
            continue
        try:
            if not any(action_matches(expr, action) for expr in statement["action"]):
                continue
            for expression in statement["resource"]:
                pattern(expression)
                if expression.startswith(prefix):
                    selected.add(expression)
                elif matches_scope(expression, candidates[0]) is True:
                    selected.add(candidates[0])
        except CollectionError:
            continue
    # A bucket represents an object namespace, not a retrieved object. Keep each
    # granted object expression intact instead of claiming access to every object.
    return sorted(selected) or candidates


def policy_statements(graph, principal, outgoing):
    subjects = [principal["id"]]
    if principal["kind"] == "cam.user":
        subjects.extend(
            e["target"]
            for e in outgoing.get(principal["id"], [])
            if e["relationship"] == "MEMBER_OF"
            and graph.nodes[e["target"]]["kind"] == "cam.group"
            and graph.nodes[e["target"]]["account"] == principal["account"]
        )
    policies = {
        e["target"]
        for subject in subjects
        for e in outgoing.get(subject, [])
        if e["relationship"] == "HAS_POLICY"
    }
    selected, complete = [], True
    for pid in sorted(policies):
        node = graph.nodes[pid]
        if node["kind"] != "cam.policy" or node["account"] != principal["account"]:
            complete = False
            continue
        try:
            doc = parse_document(node["properties"].get("policy_document"))
        except CollectionError:
            complete = False
            continue
        for i, statement in enumerate(doc["statement"]):
            sid = stable_id(principal["account"], "global", "cam.policystatement", f"{pid}/{i}")
            if sid not in graph.nodes:
                complete = False
                continue
            selected.append((sid, statement))
    return selected, complete


def inventory_complete(graph, principal, records):
    def found(action, value=None, field=None):
        for record in records:
            if record.get("action") != action or record.get("status") not in {"complete", "empty"}:
                continue
            if value is None:
                return True
            if field is None and record.get("detail") == str(value):
                return True
            try:
                args = json.loads(record.get("detail", ""))
                if isinstance(args, dict) and str(args.get(field)) == str(value):
                    return True
            except (ValueError, TypeError):
                pass
        return False

    if not all(found(action) for action in ("ListUsers", "ListGroups", "DescribeRoleList")):
        return False
    action, field = (
        ("ListAttachedUserPolicies", "TargetUin")
        if principal["kind"] == "cam.user"
        else ("ListAttachedRolePolicies", "RoleId")
    )
    if not found(action, principal["resource_id"], field):
        return False
    if principal["kind"] == "cam.user":
        for node in graph.nodes.values():
            if node["kind"] == "cam.group" and node["account"] == principal["account"]:
                if (
                    node["status"] != "enriched"
                    or not found("GetGroup", node["resource_id"])
                    or not found("ListAttachedGroupPolicies", node["resource_id"], "TargetGroupId")
                ):
                    return False
    return True


def analyze(graph):
    # Re-running analysis replaces only its own generated nodes/edges/coverage.
    obsolete = {nid for nid, n in graph.nodes.items() if n["kind"] == "cam.permissiondecision"}
    graph.nodes = {nid: n for nid, n in graph.nodes.items() if nid not in obsolete}
    graph.edges = {
        eid: e
        for eid, e in graph.edges.items()
        if e["source"] not in obsolete and e["target"] not in obsolete
    }
    graph.coverage = [r for r in graph.coverage if r.get("action") != "AnalyzeIdentityPolicies"]
    outgoing = {}
    for edge in graph.edges.values():
        outgoing.setdefault(edge["source"], []).append(edge)
    principals = [
        n
        for n in graph.nodes.values()
        if n["kind"] in {"cam.user", "cam.role"} and n["status"] == "enriched"
    ]
    targets = [n for n in graph.nodes.values() if n["kind"] in RULES and n["status"] == "enriched"]
    for principal in principals:
        statements, complete = policy_statements(graph, principal, outgoing)
        records = [
            r
            for r in graph.coverage
            if r.get("account") == principal["account"] and r.get("service") == "cam"
        ]
        # No CAM collection evidence, denied lists, missing membership/details or
        # uncollected attached policies may hide an explicit deny.
        complete &= bool(records) and all(r.get("status") in {"complete", "empty"} for r in records)
        complete &= inventory_complete(graph, principal, records)
        missing_identity = False
        unsupported_analysis = False
        count = 0
        for target in targets:
            if target["account"] != principal["account"]:
                continue
            for action, capability in RULES[target["kind"]]:
                try:
                    selections = scopes(target, statements, action)
                except CollectionError:
                    selections = []
                if not selections:
                    missing_identity = True
                    continue
                for scope in selections:
                    decision, evidence = evaluate(statements, action, scope, complete)
                    unsupported_analysis |= decision == "incomplete"
                    rid = stable_id(principal["id"], target["id"], action, scope)
                    nid = graph.add(
                        principal["account"],
                        target["region"],
                        "cam.permissiondecision",
                        rid,
                        f"{capability}: {decision}",
                        source=SOURCE,
                    )
                    graph.nodes[nid]["properties"].update(
                        action=action,
                        capability=capability,
                        resource_scope=json.dumps(scope) if isinstance(scope, list) else scope,
                        decision=decision,
                        evaluation_scope="collected_identity_policies",
                        effective_access_verified=False,
                        policy_collection_complete=complete,
                        conditions=json.dumps(
                            [row[2] for row in evidence if row[2]], sort_keys=True
                        ),
                        matching_statements=json.dumps([row[0] for row in evidence]),
                    )
                    graph.edge(principal["id"], nid, "HAS_PERMISSION_ANALYSIS", SOURCE)
                    graph.edge(nid, target["id"], "TARGETS_RESOURCE", SOURCE)
                    for sid, *_ in evidence:
                        graph.edge(nid, sid, "BASED_ON_STATEMENT", SOURCE)
                    count += 1
        if count or missing_identity:
            analysis_complete = complete and not missing_identity and not unsupported_analysis
            graph.coverage.append(
                dict(
                    account=principal["account"],
                    region="global",
                    service="analysis",
                    action="AnalyzeIdentityPolicies",
                    detail=principal["resource_id"],
                    status="complete" if analysis_complete else "error",
                    error="" if analysis_complete else "IncompletePermissionAnalysis",
                    count=count,
                    request_ids=[],
                )
            )


def analyze_snapshot(snapshot):
    """Run offline; preserve original account/mode/time and validate endpoints."""
    from copy import deepcopy

    from .model import Graph
    from .storage import validate

    data = deepcopy(validate(snapshot))
    graph = Graph()
    graph.mode, graph.created_at = data["mode"], data["created_at"]
    graph.accounts = {row["id"]: row for row in data["accounts"]}
    graph.nodes = {row["id"]: row for row in data["nodes"]}
    graph.edges = {row["id"]: row for row in data["edges"]}
    graph.coverage = data["coverage"]
    from .exposure import analyze as analyze_exposure

    analyze_exposure(graph)
    analyze(graph)
    return validate({**data, **graph.snapshot()})
