"""CAM configuration graph. Statements describe policy, never effective access."""

import json
import re

from .model import stable_id
from .transport import CollectionError


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _strings(value):
    values = [value] if isinstance(value, str) else value
    if (
        not isinstance(values, list)
        or not values
        or not all(isinstance(v, str) and v for v in values)
    ):
        raise CollectionError("InvalidPolicyDocument")
    return values


def parse_document(raw, trust=False):
    """Validate the entire document before adding any statements to the graph."""
    if not isinstance(raw, str) or len(raw.encode()) > 1_000_000:
        raise CollectionError("InvalidPolicyDocument")
    try:
        document = json.loads(raw, object_pairs_hook=_unique_object)
        json.dumps(document, allow_nan=False)
    except (ValueError, TypeError, RecursionError) as exc:
        raise CollectionError("InvalidPolicyDocument") from exc
    if not isinstance(document, dict) or document.get("version") != "2.0":
        raise CollectionError("UnsupportedPolicySyntax")
    if set(document) - {"version", "statement", "principal"}:
        raise CollectionError("UnsupportedPolicySyntax")
    statements = document.get("statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements:
        raise CollectionError("InvalidPolicyDocument")
    normalized = []
    for statement in statements:
        if not isinstance(statement, dict):
            raise CollectionError("InvalidPolicyDocument")
        if set(statement) - {"effect", "action", "resource", "condition", "principal", "sid"}:
            raise CollectionError("UnsupportedPolicySyntax")
        if statement.get("effect") not in {"allow", "deny"}:
            raise CollectionError("InvalidPolicyDocument")
        item = {**statement, "action": _strings(statement.get("action"))}
        if "resource" in statement:
            item["resource"] = _strings(statement["resource"])
        elif not trust:
            raise CollectionError("InvalidPolicyDocument")
        if "condition" in statement and not isinstance(statement["condition"], dict):
            raise CollectionError("InvalidPolicyDocument")
        principal = statement.get("principal", document.get("principal"))
        if principal is not None:
            if principal == "*":
                item["principal"] = "*"
            elif isinstance(principal, dict) and principal:
                item["principal"] = {k: _strings(v) for k, v in principal.items()}
            else:
                raise CollectionError("InvalidPolicyDocument")
        elif trust:
            raise CollectionError("InvalidPolicyDocument")
        normalized.append(item)
    return {"version": "2.0", "statement": normalized}


def _principal(graph, owner, principal_type, expression, source):
    # Resolve only exact numeric CAM identities with an explicit owner UIN.
    # uid/AppId, wildcards, service names and federation identifiers stay expressions.
    match = re.fullmatch(r"qcs::cam::uin/(\d+):(uin|groupid|roleid)/(\d+)", expression)
    if principal_type == "qcs" and match:
        account, category, rid = match.groups()
        kind = {"uin": "cam.user", "groupid": "cam.group", "roleid": "cam.role"}[category]
        if category == "uin" and account == rid:
            kind = "cam.rootprincipal"
        return graph.add(account, "global", kind, rid, source=source, status="reference")
    nid = graph.add(
        owner,
        "global",
        "cam.principal",
        stable_id(principal_type, expression),
        expression,
        source=source,
    )
    graph.nodes[nid]["properties"].update(principal_type=principal_type, expression=expression)
    return nid


def add_document(graph, parent, document, source, trust=False):
    owner = graph.nodes[parent]["account"]
    graph.nodes[parent]["properties"]["trust_document" if trust else "policy_document"] = (
        json.dumps(document, ensure_ascii=False, sort_keys=True)
    )
    for index, statement in enumerate(document["statement"]):
        nid = graph.add(
            owner,
            "global",
            "cam.truststatement" if trust else "cam.policystatement",
            f"{parent}/{index}",
            f"{'Trust' if trust else 'Policy'} {index + 1}: {statement['effect']}",
            source=source,
        )
        props = graph.nodes[nid]["properties"]
        props.update(statement_index=index, effect=statement["effect"], access_evaluated=False)
        for key in ("action", "resource", "principal", "condition", "sid"):
            if key in statement:
                props[key] = json.dumps(statement[key], ensure_ascii=False, sort_keys=True)
        graph.edge(parent, nid, "HAS_TRUST_STATEMENT" if trust else "HAS_STATEMENT", source)
        principal = statement.get("principal", {})
        entries = {"wildcard": ["*"]} if principal == "*" else principal
        for category, expressions in entries.items():
            for expression in expressions:
                pid = _principal(graph, owner, category, expression, source)
                # Includes deny statements and conditions: deliberately not CAN_ASSUME.
                graph.edge(nid, pid, "NAMES_PRINCIPAL", source)


def _request(runner, record, action, **params):
    response = runner.transport.call("cam", action, **params)
    if response.get("RequestId"):
        record["request_ids"].append(response["RequestId"])
    return response


def collect_details(runner):
    graph, owner = runner.graph, runner.account
    # Freeze input sets before trust principals create external references. Never
    # follow a referenced foreign account with the collecting account's credentials.
    candidates = [
        node.copy()
        for node in graph.nodes.values()
        if node["account"] == owner and node["region"] == "global" and node["status"] == "enriched"
    ]
    for node in candidates:
        nid, rid, kind = node["id"], node["resource_id"], node["kind"]
        if kind == "cam.group":

            def group_operation(record, nid=nid, rid=rid):
                response = _request(runner, record, "GetGroup", GroupId=int(rid))
                if str(response.get("GroupId")) != rid:
                    raise CollectionError("IdentityMismatch")
                members = response.get("UserInfo")
                if not isinstance(members, list) or response.get("GroupNum") != len(members):
                    raise CollectionError("CountMismatch")
                uins = [str(member.get("Uin", "")) for member in members]
                if len(set(uins)) != len(uins) or not all(u.isdigit() and int(u) > 0 for u in uins):
                    raise CollectionError("InvalidGroupMembers")
                for member, uin in zip(members, uins, strict=True):
                    uid = graph.add(
                        owner, "global", "cam.user", uin, member.get("Name"), source="cam.GetGroup"
                    )
                    graph.edge(uid, nid, "MEMBER_OF", "cam.GetGroup")
                record["count"] = len(members)

            runner.scope("cam", "GetGroup", "global", group_operation, rid)
        elif kind in {"cam.policy", "cam.role"}:
            trust = kind == "cam.role"
            action = "GetRole" if trust else "GetPolicy"

            def document_operation(record, nid=nid, rid=rid, trust=trust, action=action, kind=kind):
                params = {"RoleId": rid} if trust else {"PolicyId": int(rid)}
                response = _request(runner, record, action, **params)
                detail = response.get("RoleInfo") if trust else response
                if not isinstance(detail, dict):
                    raise CollectionError("InvalidResponse")
                if trust and str(detail.get("RoleId")) != rid:
                    raise CollectionError("IdentityMismatch")
                document = parse_document(detail.get("PolicyDocument"), trust)
                source = f"cam.{action}"
                graph.add(
                    owner,
                    "global",
                    kind,
                    rid,
                    detail.get("RoleName" if trust else "PolicyName"),
                    detail,
                    source,
                )
                add_document(graph, nid, document, source, trust)
                record["count"] = 1

            runner.scope("cam", action, "global", document_operation, rid)
