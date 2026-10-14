import json
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest

from tencent_cloud_cartography.kubernetes_metadata import TableTransport
from tencent_cloud_cartography.kubernetes_permissions import collect
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.transport import CollectionError


def setup():
    g = Graph()
    cid = g.add("100", "eu-frankfurt", "tke.cluster", "cls-one")
    pid = g.add("100", "eu-frankfurt", "tke.pod", "cls-one/ns/app", "app")
    g.nodes[pid]["properties"].update(cluster_id="cls-one", namespace="ns", uid_available=False)
    return g, g.nodes[cid], pid


@pytest.mark.parametrize("allowed", [False, True])
def test_authorization_metadata_has_exact_pod_scope_and_no_execution(allowed):
    g, cluster, pid = setup()
    calls = []

    class T:
        def review(self, kind, namespace=None, pod=None):
            calls.append((kind, namespace, pod))
            if kind == "SelfSubjectReview":
                return dict(
                    status=dict(
                        userInfo=dict(
                            username="operator",
                            uid="uid-one",
                            groups=["group"],
                            extra={"omit": "SECRET"},
                        )
                    )
                )
            assert (namespace, pod) == ("ns", "app")
            return dict(status=dict(allowed=allowed, denied=not allowed, reason="SECRET"))

    collect(g, cluster, "explicit-context", T())
    assert calls == [
        ("SelfSubjectReview", None, None),
        ("SelfSubjectAccessReview", "ns", "app"),
        ("SelfSubjectReview", None, None),
    ]
    assert "SECRET" not in g.dump()
    decision = next(n for n in g.nodes.values() if n["kind"] == "tke.authorizationdecision")
    assert decision["properties"]["allowed"] is allowed
    assert decision["properties"]["authorization_review_verified"]
    assert not decision["properties"]["effective_execution_verified"]
    assert any(e["source"] == decision["id"] and e["target"] == pid for e in g.edges.values())


@pytest.mark.parametrize("failure", ["identity", "evaluation", "contradiction", "denied"])
def test_failed_controls_do_not_create_permission_decisions(failure):
    g, cluster, _ = setup()
    identities = 0

    class T:
        def review(self, kind, *args):
            nonlocal identities
            if failure == "denied":
                raise CollectionError("UnauthorizedOperation")
            if kind == "SelfSubjectReview":
                identities += 1
                return dict(
                    status=dict(
                        userInfo=dict(
                            username="other"
                            if failure == "identity" and identities == 2
                            else "operator"
                        )
                    )
                )
            return dict(
                status=dict(
                    allowed=True,
                    denied=failure == "contradiction",
                    evaluationError="failed" if failure == "evaluation" else "",
                )
            )

    collect(g, cluster, "ctx", T())
    assert g.coverage[-1]["status"] in ("denied", "error")
    assert not any(n["kind"] == "tke.authorizationdecision" for n in g.nodes.values())


def transport(response, status=201):
    calls = []

    class Response:
        def __init__(self):
            self.status = status

        def read(self, size):
            calls.append(("read", size))
            return json.dumps(response).encode()

        def close(self):
            pass

        def release_conn(self):
            pass

    def request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return Response()

    t = TableTransport.__new__(TableTransport)
    t.host = "https://10.0.0.1"

    def auth(headers, *args):
        headers["Authorization"] = "Bearer fake-token"

    t.client = SimpleNamespace(
        update_params_for_auth=auth,
        rest_client=SimpleNamespace(pool_manager=SimpleNamespace(request=request)),
    )
    return t, calls


def test_review_transport_fixed_virtual_endpoint_and_exact_body():
    spec = dict(
        resourceAttributes=dict(
            group="", resource="pods", subresource="exec", verb="create", namespace="ns", name="app"
        )
    )
    t, calls = transport(
        dict(
            kind="SelfSubjectAccessReview",
            apiVersion="authorization.k8s.io/v1",
            spec=spec,
            status=dict(allowed=True),
        )
    )
    t.review("SelfSubjectAccessReview", "ns", "app")
    method, url, kw = calls[0]
    assert method == "POST" and url.endswith(
        "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
    )
    assert json.loads(kw["body"])["spec"] == spec
    assert kw["redirect"] is False and kw["retries"] is False
    assert kw["headers"]["Authorization"] == "Bearer fake-token"
    with pytest.raises(CollectionError):
        t.review("ExecPod", "ns", "app")
    assert len([c for c in calls if c[0] == "POST"]) == 1


def test_review_scope_echo_mismatch_rejected():
    t, _ = transport(
        dict(
            kind="SelfSubjectAccessReview",
            apiVersion="authorization.k8s.io/v1",
            spec={},
            status=dict(allowed=True),
        )
    )
    with pytest.raises(CollectionError, match="Collection failed") as error:
        t.review("SelfSubjectAccessReview", "ns", "app")
    assert error.value.code == "KubernetesReviewScopeMismatch"


def test_table_transport_no_full_object_fallback_or_error_body_read():
    t, calls = transport({}, status=406)
    with pytest.raises(CollectionError) as error:
        t.table("/api/v1/nodes")
    assert error.value.code == "UnsupportedKubernetesTable"
    assert len(calls) == 1
    method, url, kw = calls[0]
    assert (
        method == "GET"
        and kw["headers"]["Accept"] == "application/json;as=Table;g=meta.k8s.io;v=v1"
    )
    assert parse_qs(urlparse(url).query)["includeObject"] == ["None"]
    with pytest.raises(CollectionError):
        t.table("/api/v1/secrets")
    assert len(calls) == 1


def test_credential_hook_output_suppressed_and_logging_restored(capsys):
    import logging

    from tencent_cloud_cartography.kubernetes_metadata import quiet_credentials

    previous = logging.root.manager.disable
    with quiet_credentials():
        print("FAKE_CREDENTIAL")
        logging.error("FAKE_CREDENTIAL")
    assert capsys.readouterr().out == "" and capsys.readouterr().err == ""
    assert logging.root.manager.disable == previous
