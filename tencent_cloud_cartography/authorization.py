"""Conservative metadata authorization primitives with three-valued matches."""

import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from .cam import _unique_object
from .model import stable_id
from .permissions import (
    action_matches,
    boundary_statements,
    inventory_complete,
    matches_scope,
    policy_statements,
)
from .transport import CollectionError

ANONYMOUS = {"*", "qcs::cam::anyone:anyone", "qcs::cam::anonymous:anonymous"}
CONTEXT_KEYS = {
    "qcs:ip",
    "qcs:current_time",
    "cos:prefix",
    "cos:versionid",
    "cos:x-cos-storage-class",
    "cos:x-cos-acl",
    "cos:secure-transport",
}
STRING_KEYS = CONTEXT_KEYS - {"qcs:ip", "qcs:current_time", "cos:secure-transport"}
POLICY_ACTIONS = {
    "ListUsers",
    "ListGroups",
    "DescribeRoleList",
    "ListAttachedUserPolicies",
    "ListAttachedGroupPolicies",
    "ListAttachedRolePolicies",
    "GetGroup",
    "GetPolicy",
    "ListPolicies",
}
DEFAULT_ANALYSIS_LIMIT = 25_000


def analysis_limit(value):
    if type(value) is not int or not 1 <= value <= 1_000_000:
        raise ValueError("Analysis limit must be between 1 and 1000000 decisions per phase")
    return value


def limit_record(graph, action, count, limit):
    graph.coverage.append(
        dict(
            account="all",
            region="all",
            service="analysis",
            action=action,
            detail="Generated decision budget reached",
            status="error",
            error="AuthorizationDecisionLimitExceeded",
            count=count,
            limit=limit,
            request_ids=[],
        )
    )


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("Invalid UTC time")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None or result.utcoffset() != timedelta(0):
        raise ValueError("UTC time required")
    return result


def context_values(context=None):
    """Only nonsecret, explicitly declared request attributes are accepted."""
    if context is None:
        return {}
    if not isinstance(context, dict) or set(context) - CONTEXT_KEYS:
        raise ValueError("Unsupported authorization context key")
    for key, value in context.items():
        if key == "cos:secure-transport":
            if type(value) is not bool:
                raise ValueError("Transport context must be boolean")
        elif not isinstance(value, str) or len(value) > 4096 or any(ord(c) < 32 for c in value):
            raise ValueError("Invalid authorization context value")
        elif key == "qcs:ip":
            if "%" in value or "/" in value:
                raise ValueError("Context IP must be a single address")
            try:
                ipaddress.ip_address(value)
            except ValueError:
                raise ValueError("Invalid authorization IP context") from None
        elif key == "qcs:current_time":
            try:
                timestamp(value)
            except ValueError:
                raise ValueError("Invalid authorization UTC time context") from None
    return dict(context)


def load_context(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(16_385)
    if len(raw) > 16_384:
        raise ValueError("Authorization context too large")
    return context_values(json.loads(raw, object_pairs_hook=_unique_object))


def conjunction(values):
    return False if False in values else None if None in values else True


def disjunction(values):
    return True if True in values else None if None in values else False


def conditions(condition, context):
    """Unknown/missing attributes stay conditional; they are never read from env."""
    if not condition:
        return True, []
    results, reasons = [], []
    for operator, clauses in condition.items():
        if not isinstance(clauses, dict) or not clauses:
            results.append(None)
            reasons.append("unsupported_condition_structure")
            continue
        for key, expected in clauses.items():
            values = expected if isinstance(expected, list) else [expected]
            if not values:
                results.append(None)
                reasons.append("empty_condition_values")
                continue
            if key not in context:
                results.append(None)
                reasons.append("missing_or_unsupported_condition:" + key)
                continue
            try:
                actual = context[key]
                negative = operator in {
                    "ip_not_equal",
                    "string_not_equal",
                    "string_not_equal_ignore_case",
                    "date_not_equal",
                }
                if key == "qcs:ip" and operator in {"ip_equal", "ip_not_equal"}:
                    if not all(isinstance(v, str) and "%" not in v for v in values):
                        raise ValueError("Invalid IP condition")
                    networks = [ipaddress.ip_network(v, strict=False) for v in values]
                    matched = any(ipaddress.ip_address(actual) in net for net in networks)
                elif key == "qcs:current_time" and operator in {
                    "date_equal",
                    "date_not_equal",
                    "date_less_than",
                    "date_less_than_equal",
                    "date_greater_than",
                    "date_greater_than_equal",
                }:
                    now = timestamp(actual)
                    dates = [timestamp(v) for v in values]
                    comparison = {
                        "date_equal": lambda a, b: a == b,
                        "date_not_equal": lambda a, b: a == b,
                        "date_less_than": lambda a, b: a < b,
                        "date_less_than_equal": lambda a, b: a <= b,
                        "date_greater_than": lambda a, b: a > b,
                        "date_greater_than_equal": lambda a, b: a >= b,
                    }[operator]
                    matched = any(comparison(now, value) for value in dates)
                elif key in STRING_KEYS | {"qcs:assume_principal_arn"} and operator in {
                    "string_equal",
                    "string_not_equal",
                    "string_equal_ignore_case",
                    "string_not_equal_ignore_case",
                }:
                    if not isinstance(actual, str) or not all(isinstance(v, str) for v in values):
                        raise ValueError("Invalid string condition")
                    if operator.endswith("ignore_case"):
                        matched = actual.casefold() in [v.casefold() for v in values]
                    else:
                        matched = actual in values
                elif key == "cos:secure-transport" and operator == "bool_equal":
                    if not all(type(v) is bool or v in ("true", "false") for v in values):
                        raise ValueError("Invalid boolean condition")
                    matched = actual in [v if type(v) is bool else v == "true" for v in values]
                else:
                    raise ValueError("Unsupported condition operator/key")
                results.append(not matched if negative else matched)
            except (ValueError, TypeError):
                results.append(None)
                reasons.append("unsupported_or_invalid_condition:" + key + ":" + operator)
    return conjunction(results), sorted(set(reasons))


def index(graph):
    outgoing = {}
    for edge in graph.edges.values():
        outgoing.setdefault(edge["source"], []).append(edge)
    return outgoing


def principal_match(selector, principal, graph, outgoing, trust=False):
    if selector == "*":
        return None if trust else False
    if not isinstance(selector, dict):
        return None
    results = []
    for category, expressions in selector.items():
        if category in {"service", "federated"}:
            results.append(False)  # Named CAM identities are not service/IdP identities.
            continue
        if category != "qcs":
            results.append(None)
            continue
        for expression in expressions:
            if expression in ANONYMOUS:
                results.append(None if trust else False)
                continue
            match = re.fullmatch(
                r"qcs::cam::uin/([1-9][0-9]*):(root|(?:uin|groupid|roleid|role)/[1-9][0-9]*)",
                expression,
            )
            if not match:
                results.append(None)
                continue
            owner, identity = match.groups()
            if owner != principal["account"]:
                results.append(False)
                continue
            if identity == "root" or identity == "uin/" + owner:
                results.append(True)  # Account delegation is gated separately.
            elif identity.startswith("uin/"):
                results.append(
                    principal["kind"] == "cam.user" and identity[4:] == principal["resource_id"]
                )
            elif identity.startswith(("role/", "roleid/")):
                results.append(
                    principal["kind"] == "cam.role"
                    and identity.split("/")[1] == principal["resource_id"]
                )
            elif principal["kind"] != "cam.user":
                results.append(False)
            else:
                group = stable_id(owner, "global", "cam.group", identity.split("/")[1])
                linked = any(
                    e["relationship"] == "MEMBER_OF" and e["target"] == group
                    for e in outgoing.get(principal["id"], ())
                )
                valid = (
                    group in graph.nodes
                    and graph.nodes[group]["status"] == "enriched"
                    and any(
                        r.get("account") == owner
                        and r.get("action") == "GetGroup"
                        and r.get("detail") == identity.split("/")[1]
                        and r.get("status") in {"complete", "empty"}
                        for r in graph.coverage
                        if r.get("service") == "cam"
                    )
                )
                results.append(linked if valid else None)
    return disjunction(results)


@dataclass
class Gate:
    allow: bool | None = False
    deny: bool | None = False
    complete: bool = True
    grants_complete: bool = True
    evidence: list = field(default_factory=list)
    reasons: list = field(default_factory=list)

    @property
    def decision(self):
        if self.deny is True:
            return "denied"
        if not self.complete:
            return "unknown"
        if self.allow is False and self.grants_complete:
            return "denied"
        if self.allow is False and not self.grants_complete:
            return "unknown"
        if self.deny is None or self.allow is None:
            return "conditional"
        if not self.grants_complete and self.allow is not True:
            return "unknown"
        return "allowed" if self.allow else "denied"


def normalize_resource(value, owner, target):
    if value == "*":
        return value
    parts = value.split(":", 5)
    if len(parts) != 6 or parts[0] != "qcs" or parts[1]:
        raise CollectionError("UnsupportedPermissionResource")
    from .monitor import REGIONS

    parts[3] = REGIONS.get(parts[3], parts[3])
    if parts[2] == "cos" and parts[5].startswith("prefix/"):
        raise CollectionError("UnsupportedLegacyCosResourceNamespace")
    if parts[2] == "cos" and parts[4] == "uin/" + target["account"]:
        suffix = re.search(r"-([1-9][0-9]*)$", target["resource_id"])
        if not suffix:
            raise CollectionError("UnresolvedCosIdentity")
        # This association comes from the collected bucket owner and name. The
        # numeric UIN is never used as the AppId or compared to it.
        parts[4] = "uid/" + suffix[1]
    if parts[4] in {"", "uin/", "uid/"}:
        if parts[2] == "cos":
            if owner != target["account"]:
                raise CollectionError("UnresolvedImplicitCosOwner")
            suffix = re.search(r"-([1-9][0-9]*)$", target["resource_id"])
            if not suffix:
                raise CollectionError("UnresolvedCosIdentity")
            parts[4] = "uid/" + suffix[1]
        else:
            parts[4] = "uin/" + owner
    return ":".join(parts)


def evaluate(statements, action, scopes, context=None, complete=True, owner=None, target=None):
    gate, allows, denies = Gate(complete=complete), [], []
    if not complete:
        gate.reasons.append("incomplete_policy_evidence")
    scopes = scopes if isinstance(scopes, list) else [scopes]
    for sid, row in statements:
        try:
            matched_action = disjunction([action_matches(expr, action) for expr in row["action"]])
            if not matched_action:
                continue
            matches = [
                matches_scope(normalize_resource(expr, owner, target) if target else expr, scope)
                for expr in row.get("resource", ["*"])
                for scope in scopes
            ]
            match = disjunction(matches)
            if match is False:
                continue
            condition, reasons = conditions(row.get("condition", {}), context or {})
            if "_principal_match" in row and row["_principal_match"] is None:
                gate.complete = False
                reasons.append("unresolved_principal_selector")
            match = conjunction(
                [
                    match,
                    condition,
                    row.get("_principal_match", True),
                    None if "principal" in row else True,
                ]
            )
            if match is False:
                continue
            gate.reasons.extend(reasons)
            (denies if row["effect"] == "deny" else allows).append(match)
            gate.evidence.append(
                dict(
                    statement_id=sid,
                    effect=row["effect"],
                    matched=match,
                    condition=row.get("condition", {}),
                )
            )
        except (CollectionError, TypeError, KeyError):
            gate.complete = False
            gate.reasons.append("unsupported_policy_expression")
            gate.evidence.append(
                dict(statement_id=sid, effect=row.get("effect", "unknown"), matched=None)
            )
    gate.allow, gate.deny = disjunction(allows), disjunction(denies)
    gate.reasons = sorted(set(gate.reasons))
    return gate


def identity_statements(graph, principal, outgoing):
    rows, complete = policy_statements(graph, principal, outgoing)
    records = [
        r
        for r in graph.coverage
        if r.get("account") == principal["account"]
        and r.get("service") == "cam"
        and r.get("action") in POLICY_ACTIONS
    ]
    complete &= bool(records) and all(r.get("status") in {"complete", "empty"} for r in records)
    complete &= inventory_complete(graph, principal, records)
    return rows, complete


def boundary_gate(graph, principal, outgoing, action, scope, context, target):
    rows, present, complete = boundary_statements(graph, principal, outgoing)
    if not present:
        return Gate(complete=False, reasons=["permission_boundary_presence_unknown"])
    return evaluate(rows, action, scope, context, complete, principal["account"], target)


def combine(gates, intersection=False):
    if any(g.deny is True for g in gates):
        return "denied", "explicit_deny"
    if intersection and any(g.decision == "denied" for g in gates):
        return "denied", "required_gate_has_no_allow"
    if any(not g.complete for g in gates) or (
        intersection and any(g.decision == "unknown" for g in gates)
    ):
        return "unknown", "incomplete_evidence"
    if not intersection and all(g.decision == "denied" for g in gates):
        return "denied", "no_collected_grant"
    if any(g.deny is None for g in gates):
        return "conditional", "possible_deny"
    states = [g.decision for g in gates]
    if intersection:
        return (
            ("allowed", "all_required_gates_allow")
            if all(s == "allowed" for s in states)
            else ("conditional", "conditional_required_gate")
        )
    if "allowed" in states:
        return "allowed", "configuration_grant"
    if "conditional" not in states and "unknown" in states:
        return "unknown", "uncollected_additional_grants"
    return (
        ("conditional", "conditional_grant")
        if "conditional" in states
        else ("denied", "no_collected_grant")
    )


def replace_generated(graph, kinds, actions):
    old = {nid for nid, n in graph.nodes.items() if n["kind"] in kinds}
    graph.nodes = {nid: n for nid, n in graph.nodes.items() if nid not in old}
    graph.edges = {
        eid: e
        for eid, e in graph.edges.items()
        if e["source"] not in old and e["target"] not in old
    }
    graph.coverage = [r for r in graph.coverage if r.get("action") not in actions]


def attach_evidence(graph, nid, gates, source):
    selected = {item["statement_id"] for gate in gates for item in gate.evidence}
    for sid in sorted(selected):
        if sid in graph.nodes:
            graph.edge(nid, sid, "BASED_ON_AUTHORIZATION_EVIDENCE", source)
    return json.dumps(
        [
            dict(
                gate=i,
                decision=g.decision,
                complete=g.complete,
                grants_complete=g.grants_complete,
                reasons=sorted(set(g.reasons)),
                evidence=g.evidence,
            )
            for i, g in enumerate(gates)
        ],
        sort_keys=True,
    )
