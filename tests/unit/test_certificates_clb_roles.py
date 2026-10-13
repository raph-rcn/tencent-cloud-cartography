import json
from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.cam import link_compute_roles
from tencent_cloud_cartography.catalog import COLLECTORS
from tencent_cloud_cartography.clb import collect_listeners
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.topology import topology
from tencent_cloud_cartography.transport import CollectionError

REGION = "eu-frankfurt"
SSL = next(s for s in COLLECTORS if s.service == "ssl")
CVM = next(s for s in COLLECTORS if s.kind == "cvm.instance")
ROLE = next(s for s in COLLECTORS if s.kind == "cam.role")
CLB = next(s for s in COLLECTORS if s.action == "DescribeLoadBalancersDetail")


def cert(cid="cert-server", owner="100"):
    return dict(
        CertificateId=cid,
        OwnerUin=owner,
        Domain="example.com",
        CertificateType="SVR",
        CertBeginTime="2026-01-01 08:00:00",
        CertEndTime="2027-01-01 08:00:00",
        SubjectAltName=["example.com", "*.example.com"],
        EncryptAlgorithm="RSA",
        Status=1,
        IsWildcard=True,
        CertificatePrivateKey="exclude-private-key",
        PreAuditInfo={"Email": "exclude-contact"},
        BoundResource=["do-not-infer-consumer"],
    )


def test_certificate_pagination_metadata_and_reference_reconciliation():
    graph = Graph()
    ref = graph.add("100", "global", "ssl.certificate", "cert-server", status="reference")
    calls = []

    def call(service, action, region, **params):
        calls.append((service, action, region, params))
        items = [cert("cert-" + str(i)) for i in range(100)] if params["Offset"] == 0 else [cert()]
        return dict(Certificates=items, TotalCount=101, RequestId=str(params["Offset"]))

    runner = CollectorRunner(graph, SimpleNamespace(call=call), "100", [REGION], lambda _: None)
    runner.native(SSL, "global")
    assert len(graph.nodes) == 101 and graph.nodes[ref]["status"] == "enriched"
    assert [c[3] for c in calls] == [dict(Offset=0, Limit=100), dict(Offset=100, Limit=100)]
    assert all(c[:3] == ("ssl", "DescribeCertificates", "global") for c in calls)
    assert graph.coverage[0]["request_ids"] == ["0", "100"]
    props = graph.nodes[ref]["properties"]
    assert json.loads(props["SubjectAltName"]) == ["example.com", "*.example.com"]
    assert props["certificate_time_zone"] == "Asia/Shanghai"
    assert "exclude-" not in graph.dump() and "do-not-infer-consumer" not in graph.dump()


@pytest.mark.parametrize(
    "raw,total,error",
    [
        (cert(owner="999"), 1, "AccountMismatch"),
        ({**cert(), "SubjectAltName": "example.com"}, 1, "InvalidCertificateMetadata"),
        (cert(), None, "InvalidTotal"),
    ],
)
def test_certificate_invalid_or_foreign_metadata_is_partial(raw, total, error):
    graph = Graph()
    runner = CollectorRunner(
        graph,
        SimpleNamespace(call=lambda *a, **kw: dict(Certificates=[raw], TotalCount=total)),
        "100",
        [REGION],
        lambda _: None,
    )
    runner.native(SSL, "global")
    assert graph.coverage[0]["error"] == error
    if error == "AccountMismatch":
        assert not graph.nodes


def listener_data():
    return dict(
        Listeners=[
            dict(
                ListenerId="lbl-one",
                Protocol="HTTPS",
                Port=443,
                SniSwitch=1,
                Certificate=dict(
                    CertId="cert-server",
                    CertCaId="cert-ca",
                    ExtCertIds=["cert-extra"],
                    SSLMode="MUTUAL",
                    SSLVerifyClient="OFF",
                    CertKey="exclude-private-key",
                ),
                Rules=[
                    dict(
                        ListenerId="lbl-one",
                        LocationId="loc-one",
                        Domain="example.com",
                        Url="/api?secret=exclude-query",
                        Certificate=dict(CertId="cert-rule"),
                        OAuth={"OAuthEnable": True},
                    )
                ],
            )
        ],
        TotalCount=1,
        RequestId="listeners",
    )


def clb_fixture(response=None):
    graph = Graph()
    # Flat inventory and structured listener metadata must converge on the same IDs.
    graph.native(
        "100",
        REGION,
        CLB,
        dict(
            LoadBalancerId="lb-one",
            ListenerId="lbl-one",
            Protocol="HTTPS",
            Port=443,
            LocationId="loc-one",
            Domain="example.com",
            TargetId="ins-one",
        ),
        "clb.DescribeLoadBalancersDetail",
    )
    calls = []

    def call(service, action, region, **params):
        calls.append((service, action, region, params))
        if isinstance(response, Exception):
            raise response
        return response if response is not None else listener_data()

    collect_listeners(
        CollectorRunner(graph, SimpleNamespace(call=call), "100", [REGION], lambda _: None)
    )
    return graph, calls


def test_clb_rule_listener_certificate_and_target_identity():
    graph, calls = clb_fixture()
    assert calls == [("clb", "DescribeListeners", REGION, {"LoadBalancerId": "lb-one"})]
    listeners = [n for n in graph.nodes.values() if n["kind"] == "clb.listener"]
    rules = [n for n in graph.nodes.values() if n["kind"] == "clb.rule"]
    assert len(listeners) == len(rules) == 1
    assert rules[0]["properties"]["Url"] == "/api"
    assert listeners[0]["properties"]["SSLVerifyClient"] == "OFF"
    edges = list(graph.edges.values())
    assert any(e["source"] == rules[0]["id"] and e["relationship"] == "FORWARDS_TO" for e in edges)
    assert (
        sum(
            e["source"] == listeners[0]["id"]
            and e["relationship"] == "CONFIGURED_SERVER_CERTIFICATE"
            for e in edges
        )
        == 2
    )
    assert sum(e["relationship"] == "CONFIGURED_CLIENT_CA_CERTIFICATE" for e in edges) == 1
    assert "exclude-" not in graph.dump()
    certificates = [n for n in graph.nodes.values() if n["kind"] == "ssl.certificate"]
    assert len(certificates) == 4 and all(
        n["region"] == "global" and n["account"] == "100" for n in certificates
    )
    runner = CollectorRunner(
        graph,
        SimpleNamespace(call=lambda *a, **kw: dict(Certificates=[cert()], TotalCount=1)),
        "100",
        [REGION],
        lambda _: None,
    )
    runner.native(SSL, "global")
    assert len([n for n in graph.nodes.values() if n["kind"] == "ssl.certificate"]) == 4
    assert all(icon_for(n["kind"]) != "unmapped.svg" for n in graph.nodes.values())
    assert topology(graph.snapshot(), view="full")["stats"]["relationships"] == len(graph.edges)
    assert (
        topology(graph.snapshot())["stats"]["relationships"] == 3
    )  # LB -> listener -> rule -> target


@pytest.mark.parametrize(
    "response,error",
    [
        (dict(Listeners=[], TotalCount=1), "CountMismatch"),
        (dict(Listeners=[dict(ListenerId="lbl-one")] * 2, TotalCount=2), "DuplicateListener"),
        (
            dict(
                Listeners=[
                    dict(
                        ListenerId="lbl-one",
                        Rules=[dict(LocationId="loc-one", ListenerId="lbl-other")],
                    )
                ],
                TotalCount=1,
            ),
            "ListenerMismatch",
        ),
        (CollectionError("UnauthorizedOperation"), "UnauthorizedOperation"),
    ],
)
def test_clb_invalid_and_denied_details_retain_flat_inventory(response, error):
    graph, _ = clb_fixture(response)
    assert graph.coverage[-1]["error"] == error
    assert any(n["kind"] == "clb.rule" for n in graph.nodes.values())
    assert any(e["relationship"] == "FORWARDS_TO" for e in graph.edges.values())


def test_roles_same_account_exact_name_and_unresolved_references():
    graph = Graph()
    vm = graph.native(
        "100",
        REGION,
        CVM,
        dict(InstanceId="ins-one", CamRoleName="worker"),
        "cvm.DescribeInstances",
    )
    graph.native("999", "global", ROLE, dict(RoleId="2", RoleName="worker"), "cam.DescribeRoleList")
    local = graph.native(
        "100", "global", ROLE, dict(RoleId="1", RoleName="worker"), "cam.DescribeRoleList"
    )
    unknown = graph.native(
        "100",
        REGION,
        CVM,
        dict(InstanceId="ins-two", CamRoleName="Worker"),
        "cvm.DescribeInstances",
    )
    graph.native(
        "100", REGION, CVM, dict(InstanceId="ins-three", CamRoleName=""), "cvm.DescribeInstances"
    )
    link_compute_roles(graph)
    edges = [e for e in graph.edges.values() if e["relationship"] == "CONFIGURED_CAM_ROLE"]
    assert len(edges) == 2
    assert any(e["source"] == vm and e["target"] == local for e in edges)
    ref = next(graph.nodes[e["target"]] for e in edges if e["source"] == unknown)
    assert ref["kind"] == "cam.rolereference" and ref["properties"]["resolution"] == "unresolved"
    assert icon_for(ref["kind"]) != "unmapped.svg"


def test_ambiguous_role_names_never_choose_arbitrary_role():
    graph = Graph()
    graph.native(
        "100",
        REGION,
        CVM,
        dict(InstanceId="ins-one", CamRoleName="worker"),
        "cvm.DescribeInstances",
    )
    for rid in ("1", "2"):
        graph.native(
            "100", "global", ROLE, dict(RoleId=rid, RoleName="worker"), "cam.DescribeRoleList"
        )
    link_compute_roles(graph)
    target = graph.nodes[next(iter(graph.edges.values()))["target"]]
    assert (
        target["kind"] == "cam.rolereference" and target["properties"]["resolution"] == "ambiguous"
    )
