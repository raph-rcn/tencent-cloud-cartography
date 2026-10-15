"""Kubernetes RBAC policy metadata, with no workload objects or token material."""

import json
import re

from .collect import CollectorRunner
from .model import stable_id
from .transport import CollectionError

PREFIX = "/apis/rbac.authorization.k8s.io/v1/"
RESOURCES = {
    "roles": "Role",
    "clusterroles": "ClusterRole",
    "rolebindings": "RoleBinding",
    "clusterrolebindings": "ClusterRoleBinding",
}
KINDS = {
    "tke.role",
    "tke.clusterrole",
    "tke.rolebinding",
    "tke.clusterrolebinding",
    "tke.rbacrule",
    "tke.rbacsubject",
    "tke.rbacgrant",
}
SOURCE = "kubernetes.rbac-policy-metadata"
LINK = "analysis.kubernetes-rbac"


def text(value, empty=False):
    if (
        not isinstance(value, str)
        or (not value and not empty)
        or len(value.encode()) > 4096
        or any(ord(c) < 32 for c in value)
    ):
        raise CollectionError("InvalidKubernetesRbacText")
    return value


def strings(value, empty=False):
    if not isinstance(value, list) or (not value and not empty):
        raise CollectionError("InvalidKubernetesRbacArray")
    selected = [text(v, empty=True) for v in value]
    if len(set(selected)) != len(selected):
        raise CollectionError("DuplicateKubernetesRbacValue")
    return selected


def resource_name(value):
    text(value)
    if value in {".", ".."} or any(c in value for c in "/%"):
        raise CollectionError("InvalidKubernetesRbacName")
    return value


def namespace_name(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", value
    ):
        raise CollectionError("InvalidKubernetesRbacNamespace")
    return value


def rule(raw, namespaced):
    if not isinstance(raw, dict) or set(raw) - {
        "verbs",
        "apiGroups",
        "resources",
        "resourceNames",
        "nonResourceURLs",
    }:
        raise CollectionError("UnsupportedKubernetesRbacRule")
    result = {"verbs": strings(raw.get("verbs"))}
    if raw.get("nonResourceURLs"):
        if namespaced or raw.get("resources") or raw.get("apiGroups") or raw.get("resourceNames"):
            raise CollectionError("InvalidKubernetesNonResourceRule")
        result["nonResourceURLs"] = strings(raw["nonResourceURLs"])
        if any(
            v != "*"
            and (not v.startswith("/") or ("*" in v and (not v.endswith("*") or v.count("*") != 1)))
            for v in result["nonResourceURLs"]
        ):
            raise CollectionError("InvalidKubernetesNonResourceUrl")
    else:
        result["apiGroups"] = strings(raw.get("apiGroups", [""]))
        result["resources"] = strings(raw.get("resources"))
        if raw.get("resourceNames"):
            result["resourceNames"] = strings(raw["resourceNames"])
    return result


def selectors(raw):
    if (
        not isinstance(raw, dict)
        or set(raw) != {"clusterRoleSelectors"}
        or not isinstance(raw["clusterRoleSelectors"], list)
    ):
        raise CollectionError("InvalidKubernetesAggregationRule")
    selected = []
    for selector in raw["clusterRoleSelectors"]:
        if not isinstance(selector, dict) or set(selector) - {"matchLabels", "matchExpressions"}:
            raise CollectionError("InvalidKubernetesAggregationRule")
        labels = selector.get("matchLabels", {})
        if not isinstance(labels, dict):
            raise CollectionError("InvalidKubernetesLabelSelector")
        p = {
            "matchLabels": {text(k): text(v, True) for k, v in labels.items()},
            "matchExpressions": [],
        }
        expressions = selector.get("matchExpressions", [])
        if not isinstance(expressions, list):
            raise CollectionError("InvalidKubernetesLabelSelector")
        for expr in expressions:
            if not isinstance(expr, dict) or set(expr) - {"key", "operator", "values"}:
                raise CollectionError("InvalidKubernetesLabelSelector")
            op = expr.get("operator")
            if op not in {"In", "NotIn", "Exists", "DoesNotExist"}:
                raise CollectionError("InvalidKubernetesLabelSelector")
            values = strings(expr.get("values", []), empty=op in {"Exists", "DoesNotExist"})
            if op in {"Exists", "DoesNotExist"} and values:
                raise CollectionError("InvalidKubernetesLabelSelector")
            p["matchExpressions"].append(
                dict(key=text(expr.get("key")), operator=op, values=values)
            )
        selected.append(p)
    return selected


def prepare(raw, kind):
    if (
        not isinstance(raw, dict)
        or raw.get("apiVersion") != "rbac.authorization.k8s.io/v1"
        or raw.get("kind") != kind
    ):
        raise CollectionError("InvalidKubernetesRbacObject")
    meta = raw.get("metadata")
    if not isinstance(meta, dict):
        raise CollectionError("InvalidKubernetesRbacMetadata")
    name = resource_name(meta.get("name"))
    uid = text(meta.get("uid"))
    namespaced = kind in {"Role", "RoleBinding"}
    namespace = namespace_name(meta.get("namespace")) if namespaced else ""
    if not namespaced and meta.get("namespace"):
        raise CollectionError("KubernetesRbacNamespaceMismatch")
    p = dict(
        name=name,
        uid=uid,
        namespace=namespace,
        authorization_scope="configured_rbac_only",
        effective_access_verified=False,
    )
    if kind.endswith("Binding"):
        ref = raw.get("roleRef")
        if (
            not isinstance(ref, dict)
            or ref.get("apiGroup") != "rbac.authorization.k8s.io"
            or ref.get("kind") not in {"Role", "ClusterRole"}
            or (not namespaced and ref["kind"] != "ClusterRole")
        ):
            raise CollectionError("InvalidKubernetesRoleRef")
        p["roleRef"] = dict(kind=ref["kind"], name=resource_name(ref.get("name")))
        subjects = raw.get("subjects", [])
        if not isinstance(subjects, list):
            raise CollectionError("InvalidKubernetesSubjects")
        selected = []
        for subject in subjects:
            if not isinstance(subject, dict) or subject.get("kind") not in {
                "User",
                "Group",
                "ServiceAccount",
            }:
                raise CollectionError("InvalidKubernetesSubject")
            category = subject["kind"]
            if category == "ServiceAccount":
                if subject.get("apiGroup") not in (None, ""):
                    raise CollectionError("InvalidKubernetesSubjectGroup")
                sn = namespace_name(subject.get("namespace") or namespace)
                user = resource_name(subject.get("name"))
                if len(user) > 253 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", user):
                    raise CollectionError("InvalidKubernetesServiceAccountName")
            else:
                if subject.get("apiGroup") != "rbac.authorization.k8s.io" or subject.get(
                    "namespace"
                ):
                    raise CollectionError("InvalidKubernetesSubjectGroup")
                sn, user = "", text(subject.get("name"))
            selected.append(dict(kind=category, namespace=sn, name=user))
        if len({json.dumps(s, sort_keys=True) for s in selected}) != len(selected):
            raise CollectionError("DuplicateKubernetesSubject")
        p["subjects"] = selected
    else:
        rules = raw.get("rules", [])
        if rules is None:
            rules = []
        if not isinstance(rules, list):
            raise CollectionError("InvalidKubernetesRbacRules")
        p["rules"] = [rule(v, namespaced) for v in rules]
        labels = meta.get("labels", {})
        if not isinstance(labels, dict):
            raise CollectionError("InvalidKubernetesLabels")
        p["labels"] = {text(k): text(v, True) for k, v in labels.items()}
        if raw.get("aggregationRule") is not None:
            if namespaced:
                raise CollectionError("InvalidKubernetesAggregationRule")
            p["aggregation_selectors"] = selectors(raw["aggregationRule"])
    return p


def collect(graph, cluster, transport):
    runner = CollectorRunner(graph, None, cluster["account"], [cluster["region"]], lambda _: None)
    for resource, kind in RESOURCES.items():

        def operation(record, resource=resource, kind=kind):
            cursor, version, cursors, seen = "", None, set(), set()
            for _ in range(10000):
                data = transport.rbac(PREFIX + resource, cursor)
                if (
                    not isinstance(data, dict)
                    or data.get("kind") != kind + "List"
                    or data.get("apiVersion") != "rbac.authorization.k8s.io/v1"
                    or not isinstance(data.get("items"), list)
                    or not isinstance(data.get("metadata"), dict)
                ):
                    raise CollectionError("InvalidKubernetesRbacList")
                meta = data["metadata"]
                rv, next_cursor = (
                    text(meta.get("resourceVersion")),
                    text(meta.get("continue", ""), True),
                )
                if version is not None and rv != version:
                    raise CollectionError("KubernetesRbacInventoryChanged")
                version = rv
                prepared = [prepare(row, kind) for row in data["items"]]
                keys = [(p["namespace"], p["name"]) for p in prepared]
                if len(set(keys)) != len(keys) or seen.intersection(keys):
                    raise CollectionError("DuplicateKubernetesRbacObject")
                if next_cursor and (next_cursor == cursor or next_cursor in cursors):
                    raise CollectionError("KubernetesRbacPaginationStalled")
                seen.update(keys)
                for p in prepared:
                    rid = (
                        cluster["resource_id"]
                        + "/"
                        + (p["namespace"] + "/" if p["namespace"] else "")
                        + p["name"]
                    )
                    nid = graph.add(
                        cluster["account"],
                        cluster["region"],
                        "tke." + kind.lower(),
                        rid,
                        p["name"],
                        source=SOURCE,
                    )
                    graph.nodes[nid]["properties"].update(
                        {
                            k: json.dumps(v, sort_keys=True) if isinstance(v, (list, dict)) else v
                            for k, v in p.items()
                        },
                        cluster_id=cluster["resource_id"],
                    )
                    graph.edge(cluster["id"], nid, "HAS_RBAC_CONFIGURATION", SOURCE)
                    record["count"] += 1
                if not next_cursor:
                    return
                cursors.add(next_cursor)
                cursor = next_cursor
            raise CollectionError("KubernetesRbacPageLimit")

        runner.scope(
            "kubernetes",
            "ListRbacMetadata",
            cluster["region"],
            operation,
            cluster["resource_id"] + "/" + resource,
        )
    link(graph)


def scoped_identity(node):
    p = node["properties"]
    cluster = resource_name(p.get("cluster_id"))
    namespace = (
        namespace_name(p.get("namespace"))
        if node["kind"] in {"tke.role", "tke.rolebinding"}
        else ""
    )
    if not namespace and p.get("namespace"):
        raise CollectionError("KubernetesRbacNamespaceMismatch")
    expected = cluster + "/" + (namespace + "/" if namespace else "") + resource_name(node["name"])
    if node["resource_id"] != expected:
        raise CollectionError("KubernetesRbacIdentityMismatch")


def selector_matches(selector, labels):
    if any(labels.get(k) != v for k, v in selector.get("matchLabels", {}).items()):
        return False
    for expr in selector.get("matchExpressions", []):
        key, op, values = expr["key"], expr["operator"], expr["values"]
        if op == "In" and (key not in labels or labels[key] not in values):
            return False
        if op == "NotIn" and key in labels and labels[key] in values:
            return False
        if op == "Exists" and key not in labels:
            return False
        if op == "DoesNotExist" and key in labels:
            return False
    return True


def link(graph, max_decisions=25000):
    from .authorization import limit_record, replace_generated

    replace_generated(
        graph, {"tke.rbacrule", "tke.rbacsubject", "tke.rbacgrant"}, {"AnalyzeKubernetesRbac"}
    )
    graph.edges = {i: e for i, e in graph.edges.items() if e.get("provenance") != LINK}
    referenced = {e[k] for e in graph.edges.values() for k in ("source", "target")}
    graph.nodes = {
        i: n
        for i, n in graph.nodes.items()
        if not (n["status"] == "reference" and LINK in n.get("sources", []) and i not in referenced)
    }
    roles = [
        n
        for n in graph.nodes.values()
        if n["kind"] in {"tke.role", "tke.clusterrole"} and n["status"] == "enriched"
    ]
    for role in roles:
        scoped_identity(role)
    by_role = {
        (
            n["account"],
            n["region"],
            n["properties"].get("cluster_id"),
            n["kind"],
            n["properties"].get("namespace", ""),
            n["name"],
        ): n
        for n in roles
    }
    rules = {}
    for role in roles:
        p = role["properties"]
        rules[role["id"]] = []
        for i, raw in enumerate(json.loads(p.get("rules", "[]"))):
            selected = rule(raw, role["kind"] == "tke.role")
            rid = graph.add(
                role["account"],
                role["region"],
                "tke.rbacrule",
                stable_id(role["id"], str(i)),
                source=LINK,
            )
            graph.nodes[rid]["properties"].update(
                {k: json.dumps(v, sort_keys=True) for k, v in selected.items()}
            )
            graph.edge(role["id"], rid, "HAS_RBAC_RULE", LINK)
            rules[role["id"]].append(rid)
        for selector in json.loads(p.get("aggregation_selectors", "[]")):
            for other in roles:
                if (
                    other["id"] != role["id"]
                    and other["kind"] == "tke.clusterrole"
                    and (other["account"], other["region"], other["properties"].get("cluster_id"))
                    == (role["account"], role["region"], p.get("cluster_id"))
                    and selector_matches(
                        selector, json.loads(other["properties"].get("labels", "{}"))
                    )
                ):
                    graph.edge(role["id"], other["id"], "SELECTS_AGGREGATED_ROLE", LINK)
    generated, limited = 0, False
    for binding in list(graph.nodes.values()):
        if (
            binding["kind"] not in {"tke.rolebinding", "tke.clusterrolebinding"}
            or binding["status"] != "enriched"
        ):
            continue
        scoped_identity(binding)
        p = binding["properties"]
        ref = json.loads(p.get("roleRef", "{}"))
        validated = prepare(
            dict(
                apiVersion="rbac.authorization.k8s.io/v1",
                kind="RoleBinding"
                if binding["kind"] == "tke.rolebinding"
                else "ClusterRoleBinding",
                metadata=dict(
                    name=binding["name"], uid=p.get("uid"), namespace=p.get("namespace", "")
                ),
                roleRef={**ref, "apiGroup": "rbac.authorization.k8s.io"},
                subjects=[
                    {
                        **s,
                        "apiGroup": ""
                        if s.get("kind") == "ServiceAccount"
                        else "rbac.authorization.k8s.io",
                    }
                    for s in json.loads(p.get("subjects", "[]"))
                ],
            ),
            "RoleBinding" if binding["kind"] == "tke.rolebinding" else "ClusterRoleBinding",
        )
        if not isinstance(p.get("cluster_id"), str) or not p["cluster_id"]:
            raise CollectionError("InvalidKubernetesClusterScope")
        namespace = p.get("namespace", "") if ref["kind"] == "Role" else ""
        target = by_role.get(
            (
                binding["account"],
                binding["region"],
                p.get("cluster_id"),
                "tke." + ref["kind"].lower(),
                namespace,
                ref.get("name"),
            )
        )
        p["role_reference_resolved"] = target is not None
        if not target:
            rid = (
                p["cluster_id"]
                + "/"
                + (namespace + "/" if namespace else "")
                + resource_name(ref["name"])
            )
            tid = graph.add(
                binding["account"],
                binding["region"],
                "tke." + ref["kind"].lower(),
                rid,
                ref["name"],
                status="reference",
                source=LINK,
            )
            graph.nodes[tid]["properties"].update(cluster_id=p["cluster_id"], namespace=namespace)
            graph.coverage.append(
                dict(
                    account=binding["account"],
                    region=binding["region"],
                    service="analysis",
                    action="AnalyzeKubernetesRbac",
                    detail=binding["id"],
                    status="error",
                    error="UnresolvedKubernetesRoleReference",
                    count=0,
                    request_ids=[],
                )
            )
        else:
            tid = target["id"]
        graph.edge(binding["id"], tid, "BINDS_ROLE", LINK)
        for s in validated["subjects"]:
            sid = graph.add(
                binding["account"],
                binding["region"],
                "tke.rbacsubject",
                stable_id(p["cluster_id"], s),
                s["name"],
                source=LINK,
            )
            graph.nodes[sid]["properties"].update(
                s, cluster_id=p["cluster_id"], cam_principal_resolved=False
            )
            graph.edge(binding["id"], sid, "BINDS_SUBJECT", LINK)
            if not target:
                continue
            for rid in rules[target["id"]]:
                if generated >= max_decisions:
                    if not limited:
                        limit_record(graph, "AnalyzeKubernetesRbac", generated, max_decisions)
                        limited = True
                    continue
                raw = graph.nodes[rid]["properties"]
                # Namespaced bindings cannot grant cluster-scoped nonresource URLs.
                if p.get("namespace") and raw.get("nonResourceURLs"):
                    continue
                gid = graph.add(
                    binding["account"],
                    binding["region"],
                    "tke.rbacgrant",
                    stable_id(binding["id"], sid, rid),
                    "Configured RBAC grant",
                    source=LINK,
                )
                graph.nodes[gid]["properties"].update(
                    raw,
                    namespace_scope=p.get("namespace") or "*",
                    effective_access_verified=False,
                    authorization_scope="configured_rbac_only",
                )
                graph.edge(sid, gid, "HAS_CONFIGURED_RBAC_GRANT", LINK)
                graph.edge(gid, rid, "BASED_ON_RBAC_RULE", LINK)
                graph.edge(gid, binding["id"], "BASED_ON_RBAC_BINDING", LINK)
                generated += 1
    principals = [
        n
        for n in graph.nodes.values()
        if n["kind"] == "tke.kubernetesprincipal" and n["status"] == "enriched"
    ]
    for subject in list(graph.nodes.values()):
        if subject["kind"] != "tke.rbacsubject":
            continue
        p = subject["properties"]
        for actor in principals:
            ap = actor["properties"]
            if (actor["account"], actor["region"], ap.get("cluster_id")) != (
                subject["account"],
                subject["region"],
                p.get("cluster_id"),
            ):
                continue
            groups = json.loads(ap.get("groups", "[]"))
            matched = (
                p["name"] == ap.get("username")
                if p["kind"] == "User"
                else p["name"] in groups
                if p["kind"] == "Group"
                else ap.get("username")
                == "system:serviceaccount:" + p["namespace"] + ":" + p["name"]
            )
            if matched:
                graph.edge(actor["id"], subject["id"], "MATCHES_RBAC_SUBJECT", LINK)
