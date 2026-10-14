import json
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tencent_cloud_cartography.catalog import ALLOWED_ACTIONS, COLLECTORS
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.kubernetes_metadata import collect as tables
from tencent_cloud_cartography.kubernetes_metadata import (
    collect_contexts,
    link,
    parse_contexts,
    rows,
)
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.tke import ca_metadata, collect, collect_access_mappings, endpoint
from tencent_cloud_cartography.transport import CollectionError


def setup():
    g = Graph()
    nid = g.add("100", "eu-frankfurt", "tke.cluster", "cls-one")
    g.nodes[nid]["properties"].update(
        ClusterIntranetEndpoint="https://10.0.0.1", endpoints_collected=True
    )
    return g, g.nodes[nid]


def table(names, cells, cursor="", version="1"):
    return dict(
        kind="Table",
        apiVersion="meta.k8s.io/v1",
        columnDefinitions=[dict(name=n) for n in names],
        rows=[dict(cells=c) for c in cells],
        metadata=dict(continue_=cursor, resourceVersion=version),
    )


def fixture(names, cells, cursor="", version="1"):
    d = table(names, cells, cursor, version)
    d["metadata"]["continue"] = d["metadata"].pop("continue_")
    return d


def test_cluster_metadata_independent_details_no_scripts_action():
    calls = []

    class Transport:
        def call(self, service, action, region=None, **params):
            calls.append(action)
            if action == "DescribeClusters":
                return dict(
                    TotalCount=1,
                    Clusters=[
                        dict(
                            ClusterId="cls-one",
                            ClusterName="one",
                            Property="DO_NOT_PERSIST",
                            ClusterNetworkSettings=dict(
                                VpcId="vpc-one", Subnets=["subnet-one"], ClusterCIDR="10.0.0.0/16"
                            ),
                        )
                    ],
                )
            if action == "DescribeClusterEndpoints":
                return dict(
                    ClusterIntranetEndpoint="10.0.0.1:443", ClusterExternalACL=["0.0.0.0/0"]
                )
            if action == "DescribeClusterAuthenticationOptions":
                raise CollectionError("UnauthorizedOperation")
            if action == "DescribeControlPlaneLogs":
                return dict(
                    Details=[
                        dict(
                            Name="kube-apiserver",
                            TopicId="topic-one",
                            TopicRegion="ap-guangzhou",
                            LogLevel=2,
                        )
                    ]
                )
            raise AssertionError(action)

    g = Graph()
    spec = next(s for s in COLLECTORS if s.kind == "tke.cluster")
    collect(
        CollectorRunner(g, Transport(), "100", ["eu-frankfurt"], lambda _: None),
        spec,
        "eu-frankfurt",
    )
    n = next(n for n in g.nodes.values() if n["kind"] == "tke.cluster")
    assert n["properties"]["ClusterIntranetEndpoint"] == "https://10.0.0.1"
    assert "DO_NOT_PERSIST" not in g.dump()
    assert "DescribeClusterInstances" not in calls
    assert ("tke", "DescribeClusterInstances") not in ALLOWED_ACTIONS
    assert [r["status"] for r in g.coverage] == [
        "complete",
        "complete",
        "denied",
        "complete",
        "unsupported",
    ]
    assert any(n["kind"] == "cls.topic" and n["region"] == "ap-guangzhou" for n in g.nodes.values())


def test_public_ca_metadata_contains_no_pem():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cluster")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    props = ca_metadata(cert.public_bytes(serialization.Encoding.PEM).decode())
    assert props["is_ca"] and props["public_key_bits"] == 2048
    assert "BEGIN" not in json.dumps(props)
    with pytest.raises(CollectionError):
        ca_metadata(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode()
        )


@pytest.mark.parametrize(
    "value",
    [
        "http://10.0.0.1",
        "https://x/?key=a",
        "https://u:p@x",
        "https://x:wrong",
        "https://x/path",
        "https://x/#token",
    ],
)
def test_endpoint_rejects_credentials_non_tls_paths(value):
    with pytest.raises(CollectionError):
        endpoint(value)


def test_table_scoped_names_pod_node_link_and_partial_service():
    g, cluster = setup()
    calls = []

    class Transport:
        def table(self, path, cursor=""):
            calls.append(path)
            if path.endswith("/namespaces"):
                return fixture(["Name"], [["one"], ["two"]])
            if path.endswith("/nodes"):
                return fixture(["Name", "Internal-IP"], [["worker", "10.0.0.2"]])
            if path.endswith("/pods"):
                return fixture(["Name", "Node", "Unknown"], [["app", "worker", "DO_NOT_PERSIST"]])
            if path.endswith("/services"):
                raise CollectionError("UnauthorizedOperation")
            return fixture(["Name"], [])

    tables(g, cluster, Transport())
    link(g)
    pods = [n for n in g.nodes.values() if n["kind"] == "tke.pod"]
    assert len(pods) == 2 and len({n["resource_id"] for n in pods}) == 2
    assert all(n["properties"]["uid_available"] is False for n in pods)
    assert sum(e["relationship"] == "SCHEDULED_ON" for e in g.edges.values()) == 2
    assert "DO_NOT_PERSIST" not in g.dump()
    assert all(icon_for(n["kind"]) != "unmapped.svg" for n in g.nodes.values())
    assert len([r for r in g.coverage if r["status"] == "denied"]) == 2
    assert all("/namespaces/" in p for p in calls[2:])


@pytest.mark.parametrize(
    "change", ["object", "annotation", "duplicate", "badversion", "badname", "badcolumns"]
)
def test_table_projection_fails_closed(change):
    data = fixture(["Name"], [["app"]])
    if change in ("object", "annotation"):
        data["rows"][0]["object"] = {"metadata": {"annotations": {"last-applied": "ENV_SECRET"}}}
    elif change == "duplicate":
        data["columnDefinitions"].append(dict(name="Name"))
    elif change == "badversion":
        data["apiVersion"] = "v1"
    elif change == "badname":
        data["rows"][0]["cells"] = ["../../secrets"]
    else:
        data["rows"][0]["cells"] = []
    with pytest.raises(CollectionError):
        rows(data)


@pytest.mark.parametrize("failure", ["stalled", "changed", "duplicate"])
def test_table_pagination_preserves_previous_page_and_reports_failure(failure):
    g, cluster = setup()

    class Transport:
        def table(self, path, cursor=""):
            if path != "/api/v1/nodes":
                return fixture(["Name"], [])
            if not cursor:
                return fixture(["Name"], [["a"]], "next")
            return fixture(
                ["Name"],
                [["a" if failure == "duplicate" else "b"]],
                "next" if failure == "stalled" else "",
                "2" if failure == "changed" else "1",
            )

    tables(g, cluster, Transport())
    assert sum(n["kind"] == "tke.node" for n in g.nodes.values()) == 1
    assert next(r for r in g.coverage if r["detail"].endswith("/nodes"))["status"] == "error"


def test_explicit_context_requires_collected_cluster_endpoint_before_loading_credentials():
    g, node = setup()
    called = []

    def factory(*args):
        called.append(args)
        raise AssertionError()

    collect_contexts(g, {"200/eu-frankfurt/cls-other": "ctx"}, factory)
    assert not called
    assert g.coverage[-1]["error"] == "KubernetesClusterNotCollected"
    node["properties"].pop("endpoints_collected")
    collect_contexts(g, {"100/eu-frankfurt/cls-one": "ctx"}, factory)
    assert not called and g.coverage[-1]["error"] == "KubernetesEndpointNotCollected"


@pytest.mark.parametrize(
    "values",
    [
        ["ctx"],
        ["100/eu-frankfurt/cls-one="],
        ["x/eu-frankfurt/cls-one=ctx"],
        ["100/eu-frankfurt/cls-one=ctx"] * 2,
    ],
)
def test_bad_context_mapping(values):
    with pytest.raises(ValueError):
        parse_contexts(values)


def test_access_mapping_exact_user_identity_no_rbac_claim():
    g, _ = setup()
    uid = g.add("100", "global", "cam.user", "123")

    class Transport:
        def call(self, service, action, region=None, **params):
            assert params == dict(ClusterId="cls-one", SubaccountUins=["123"])
            return dict(CommonNames=[dict(SubaccountUin="123", CN="user-cn")])

    collect_access_mappings(
        CollectorRunner(g, Transport(), "100", ["eu-frankfurt"], lambda _: None)
    )
    node = next(n for n in g.nodes.values() if n["kind"] == "tke.accessmapping")
    assert node["properties"]["effective_access_verified"] is False
    assert any(
        e["target"] == uid and e["relationship"] == "MAPS_PRINCIPAL" for e in g.edges.values()
    )
