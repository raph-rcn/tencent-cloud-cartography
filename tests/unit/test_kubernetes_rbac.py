import copy
import json

import pytest
from test_kubernetes_authorization import transport

from tencent_cloud_cartography.kubernetes_rbac import PREFIX, RESOURCES, collect, link, prepare
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.transport import CollectionError


def obj(kind, name, namespace=None, **fields):
    return dict(
        apiVersion="rbac.authorization.k8s.io/v1",
        kind=kind,
        metadata=dict(
            name=name, uid="uid-" + name, **({"namespace": namespace} if namespace else {})
        ),
        **fields,
    )


def setup(missing=False):
    g = Graph()
    cluster = g.nodes[g.add("100", "eu-frankfurt", "tke.cluster", "cls-one")]
    data = {r: [] for r in RESOURCES}
    data["clusterroles"] = [
        obj(
            "ClusterRole",
            "reader",
            rules=[
                dict(
                    verbs=["get", "list"], apiGroups=[""], resources=["pods"], resourceNames=["app"]
                ),
                dict(verbs=["get"], nonResourceURLs=["*"]),
            ],
        )
    ]
    data["rolebindings"] = [
        obj(
            "RoleBinding",
            "read",
            "team",
            roleRef=dict(
                apiGroup="rbac.authorization.k8s.io",
                kind="ClusterRole",
                name="missing" if missing else "reader",
            ),
            subjects=[
                dict(kind="User", apiGroup="rbac.authorization.k8s.io", name="alice"),
                dict(kind="ServiceAccount", name="builder", namespace="other"),
            ],
        )
    ]
    return g, cluster, data


class T:
    def __init__(self, data):
        self.data = data
        self.calls = []

    def rbac(self, path, cursor):
        self.calls.append((path, cursor))
        r = path.removeprefix(PREFIX)
        return dict(
            apiVersion="rbac.authorization.k8s.io/v1",
            kind=RESOURCES[r] + "List",
            metadata=dict(resourceVersion="10"),
            items=copy.deepcopy(self.data[r]),
        )


def test_configured_namespaced_grants_and_identity_matching_without_cam_guess():
    g, c, data = setup()
    actor = g.nodes[g.add("100", c["region"], "tke.kubernetesprincipal", "ctx")]
    actor["properties"].update(cluster_id="cls-one", username="alice", groups='["team"]')
    foreign = g.nodes[g.add("200", c["region"], "tke.kubernetesprincipal", "ctx")]
    foreign["properties"].update(actor["properties"])
    t = T(data)
    collect(g, c, t)
    assert {p for p, _ in t.calls} == {PREFIX + r for r in RESOURCES}
    grants = [n for n in g.nodes.values() if n["kind"] == "tke.rbacgrant"]
    assert len(grants) == 2
    assert all(
        n["properties"]["namespace_scope"] == "team"
        and not n["properties"]["effective_access_verified"]
        for n in grants
    )
    matches = [e for e in g.edges.values() if e["relationship"] == "MATCHES_RBAC_SUBJECT"]
    assert len(matches) == 1 and matches[0]["source"] == actor["id"]
    assert all(
        not n["properties"].get("cam_principal_resolved")
        for n in g.nodes.values()
        if n["kind"] == "tke.rbacsubject"
    )
    before = g.dump()
    link(g)
    assert g.dump() == before


def test_missing_roles_remain_references_with_partial_coverage_and_no_grants():
    g, c, data = setup(missing=True)
    collect(g, c, T(data))
    assert any(
        n["kind"] == "tke.clusterrole" and n["status"] == "reference" for n in g.nodes.values()
    )
    assert any(e["relationship"] == "BINDS_ROLE" for e in g.edges.values())
    assert any(r.get("error") == "UnresolvedKubernetesRoleReference" for r in g.coverage)
    assert not any(n["kind"] == "tke.rbacgrant" for n in g.nodes.values())
    before = g.dump()
    link(g)
    assert g.dump() == before


def test_aggregation_selects_metadata_without_synthesizing_permissions():
    g, c, data = setup()
    data["clusterroles"][0]["metadata"]["labels"] = {"aggregate-to-view": "true"}
    data["clusterroles"].append(
        obj(
            "ClusterRole",
            "aggregate",
            rules=[],
            aggregationRule=dict(
                clusterRoleSelectors=[dict(matchLabels={"aggregate-to-view": "true"})]
            ),
        )
    )
    data["rolebindings"][0]["roleRef"]["name"] = "aggregate"
    collect(g, c, T(data))
    assert any(e["relationship"] == "SELECTS_AGGREGATED_ROLE" for e in g.edges.values())
    assert not any(n["kind"] == "tke.rbacgrant" for n in g.nodes.values())


@pytest.mark.parametrize(
    "change",
    [
        "foreign-kind",
        "foreign-api",
        "missing-namespace",
        "foreign-role-group",
        "unknown-subject",
        "duplicate-subject",
        "unexpected-rule",
        "invalid-url",
    ],
)
def test_invalid_rbac_objects_cannot_become_grants(change):
    g, c, data = setup()
    raw = data["rolebindings"][0]
    if change == "foreign-kind":
        raw["kind"] = "ClusterRoleBinding"
    elif change == "foreign-api":
        raw["apiVersion"] = "v1"
    elif change == "missing-namespace":
        raw["metadata"].pop("namespace")
    elif change == "foreign-role-group":
        raw["roleRef"]["apiGroup"] = "other"
    elif change == "unknown-subject":
        raw["subjects"][0]["kind"] = "CAMUser"
    elif change == "duplicate-subject":
        raw["subjects"] *= 2
    elif change == "unexpected-rule":
        raw = data["clusterroles"][0]
        raw["rules"][0]["Unknown"] = True
    else:
        raw = data["clusterroles"][0]
        raw["rules"][1]["nonResourceURLs"] = ["/a*b"]
    with pytest.raises(CollectionError):
        prepare(
            raw, "ClusterRole" if change in {"unexpected-rule", "invalid-url"} else "RoleBinding"
        )


def test_annotations_not_saved_and_known_sa_namespace_default():
    raw = obj(
        "RoleBinding",
        "rb",
        "team",
        roleRef=dict(apiGroup="rbac.authorization.k8s.io", kind="Role", name="reader"),
        subjects=[dict(kind="ServiceAccount", name="build.bot")],
    )
    raw["metadata"]["annotations"] = {"last-applied": "OMIT"}
    p = prepare(raw, "RoleBinding")
    assert p["subjects"] == [dict(kind="ServiceAccount", namespace="team", name="build.bot")]
    assert "OMIT" not in json.dumps(p)


def test_rbac_transport_exact_get_allowlist_and_no_workload_fallback():
    t, calls = transport(dict(items=[]), status=200)
    t.rbac(PREFIX + "roles", "opaque")
    method, url, kw = calls[0]
    assert method == "GET" and "continue=opaque" in url and "limit=200" in url
    assert (
        kw["redirect"] is False
        and kw["retries"] is False
        and kw["headers"]["Accept"] == "application/json"
    )
    for path in ["/api/v1/secrets", PREFIX + "roles/name", PREFIX + "roles?limit=2"]:
        with pytest.raises(CollectionError):
            t.rbac(path)
    assert sum(c[0] == "GET" for c in calls) == 1


def test_rbac_decision_limit_is_visible_and_source_metadata_is_preserved():
    g, c, data = setup()
    collect(g, c, T(data))
    link(g, max_decisions=1)
    assert len([n for n in g.nodes.values() if n["kind"] == "tke.rbacgrant"]) == 1
    assert any(r.get("error") == "AuthorizationDecisionLimitExceeded" for r in g.coverage)
    assert any(n["kind"] == "tke.rolebinding" for n in g.nodes.values())


def test_paginated_rbac_identity_stability_and_duplicate_controls():
    for failure in ("version", "duplicate", "cursor"):
        g, c, data = setup()

        class P(T):
            def rbac(self, path, cursor):
                value = super().rbac(path, cursor)
                if path.endswith("roles") and not path.endswith("clusterroles"):
                    value["items"] = [obj("Role", "reader", "team", rules=[])]
                    value["metadata"]["continue"] = "next"
                    if cursor:
                        if failure == "version":
                            value["metadata"]["resourceVersion"] = "11"
                        elif failure == "cursor":
                            value["items"] = [obj("Role", "other", "team", rules=[])]
                return value

        collect(g, c, P(data))
        assert any(r["status"] == "error" and r["detail"].endswith("/roles") for r in g.coverage)


def test_grant_budget_preserves_all_collected_binding_role_subject_relationships():
    g, c, data = setup()
    other = copy.deepcopy(data["rolebindings"][0])
    other["metadata"].update(name="second", uid="uid-second")
    data["rolebindings"].append(other)
    collect(g, c, T(data))
    link(g, max_decisions=1)
    assert len([n for n in g.nodes.values() if n["kind"] == "tke.rbacgrant"]) == 1
    bindings = [n for n in g.nodes.values() if n["kind"] == "tke.rolebinding"]
    for b in bindings:
        assert any(
            e["source"] == b["id"] and e["relationship"] == "BINDS_ROLE" for e in g.edges.values()
        )
        assert (
            len(
                [
                    e
                    for e in g.edges.values()
                    if e["source"] == b["id"] and e["relationship"] == "BINDS_SUBJECT"
                ]
            )
            == 2
        )
    assert (
        len([r for r in g.coverage if r.get("error") == "AuthorizationDecisionLimitExceeded"]) == 1
    )
