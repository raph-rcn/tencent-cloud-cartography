import json

import pytest

from tencent_cloud_cartography.catalog import COLLECTORS, SCF_FUNCTIONS
from tencent_cloud_cartography.collect import CollectorRunner, collect
from tencent_cloud_cartography.gateway import (
    api,
    collect_service,
    domain,
    environment,
    link_backends,
    release,
)
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.transport import CollectionError


def service(g, rid="service-one", account="100", region="eu-frankfurt"):
    spec = next(s for s in COLLECTORS if s.kind == "apigateway.service")
    nid = g.native(account, region, spec, dict(ServiceId=rid, ServiceName=rid), "fixture")
    return g.nodes[nid]


def fn(g, account="100", region="eu-frankfurt", namespace="default", rid="lam-one"):
    nid = g.native(
        account,
        region,
        SCF_FUNCTIONS,
        dict(FunctionId=rid, FunctionName="handler", Namespace=namespace),
        "fixture",
    )
    return nid


def details(s, **fields):
    return dict(
        ServiceId=s["resource_id"],
        ApiId="api-one",
        ApiName="Endpoint",
        ServiceType="SCF",
        ServiceScfFunctionName="handler",
        ServiceScfFunctionNamespace="default",
        ServiceScfFunctionQualifier="prod",
        **fields,
    )


def test_scoped_api_identities_and_scf_namespace_owner_region_resolution():
    g = Graph()
    s = service(g)
    f = fn(g)
    fn(g, account="200")
    fn(g, region="ap-guangzhou")
    fn(g, namespace="other", rid="lam-other")
    api(g, s, details(s), True)
    s2 = service(g, "service-two")
    api(g, s2, details(s2), True)
    link_backends(g)
    apis = [n for n in g.nodes.values() if n["kind"] == "apigateway.api"]
    assert len(apis) == 2 and len({n["id"] for n in apis}) == 2
    edges = [e for e in g.edges.values() if e["relationship"] == "CONFIGURED_SCF_BACKEND"]
    assert len(edges) == 2 and {e["target"] for e in edges} == {f}
    assert len([n for n in g.nodes.values() if n["kind"] == "scf.alias"]) == 1
    assert all(icon_for(n["kind"]) != "unmapped.svg" for n in g.nodes.values())


def test_missing_namespace_and_ambiguous_function_identity_remain_unresolved():
    for namespace in ("", "default"):
        g = Graph()
        s = service(g)
        fn(g)
        fn(g, rid="lam-second")
        raw = details(s)
        raw["ServiceScfFunctionNamespace"] = namespace
        api(g, s, raw, True)
        link_backends(g)
        assert not any(e["relationship"] == "CONFIGURED_SCF_BACKEND" for e in g.edges.values())
        assert (
            next(n for n in g.nodes.values() if n["kind"] == "apigateway.integration")[
                "properties"
            ]["backend_resolved"]
            is False
        )


def test_websocket_role_backends_stay_separate_and_keep_qualifiers():
    g = Graph()
    s = service(g)
    f = fn(g)
    raw = details(s, Protocol="WEBSOCKET")
    for role in ("Register", "Cleanup", "Transport"):
        for suffix, value in [("Name", "handler"), ("Namespace", "default"), ("Qualifier", "2")]:
            raw["ServiceWebsocket" + role + "Function" + suffix] = value
    api(g, s, raw, True)
    link_backends(g)
    integrations = [n for n in g.nodes.values() if n["kind"] == "apigateway.integration"]
    assert {n["properties"]["integration_role"] for n in integrations} == {
        "backend",
        "register",
        "cleanup",
        "transport",
    }
    assert (
        len(
            [
                e
                for e in g.edges.values()
                if e["relationship"] == "CONFIGURED_SCF_BACKEND" and e["target"] == f
            ]
        )
        == 4
    )
    assert len([n for n in g.nodes.values() if n["kind"] == "scf.version"]) == 1


def test_http_backend_vpc_is_not_api_or_service_placement_and_secrets_are_omitted():
    g = Graph()
    s = service(g)
    raw = dict(
        ServiceId=s["resource_id"],
        ApiId="api-http",
        ServiceType="HTTP",
        RequestConfig=dict(Method="GET", Path="/public"),
        ServiceConfig=dict(
            Product="cvm",
            UniqVpcId="vpc-backend",
            Url="https://backend.example/path?token=SECRET#SECRET",
            Method="POST",
            Path="/private",
        ),
        ConstantParameters=[dict(Value="SECRET")],
        OauthConfig=dict(secret="SECRET"),
        ServiceMockReturnMessage="SECRET",
    )
    aid = api(g, s, raw, True)
    assert g.nodes[aid]["properties"]["Method"] == "GET"
    backend = next(n for n in g.nodes.values() if n["kind"] == "apigateway.integration")
    assert (
        backend["properties"]["Method"] == "POST"
        and backend["properties"]["Url"] == "https://backend.example/path"
    )
    assert not any(e["relationship"] == "IN_VPC" for e in g.edges.values())
    assert any(e["relationship"] == "BACKEND_VPC" for e in g.edges.values())
    assert "SECRET" not in g.dump()


def test_deployed_release_requires_environment_published_status_and_draft_conflict_visible():
    g = Graph()
    s = service(g)
    release(g, s, dict(VersionName="v1"))
    environment(g, s, dict(EnvironmentName="release", Status=1, VersionName="v1"))
    environment(
        g,
        s,
        dict(
            EnvironmentName="test",
            Status=0,
            VersionName="v2",
            Url="gateway.example/test?token=SECRET",
        ),
    )
    aid = api(
        g,
        s,
        dict(ServiceId=s["resource_id"], ApiId="api-one", Environments=["release", "test"]),
        True,
    )
    assert len([e for e in g.edges.values() if e["relationship"] == "DEPLOYS_RELEASE"]) == 1
    assert len([e for e in g.edges.values() if e["relationship"] == "LISTED_IN_ENVIRONMENT"]) == 2
    assert g.nodes[aid]["properties"]["deployment_state_conflict"] is True
    assert "SECRET" not in g.dump()


def test_custom_domain_certificate_reference_has_official_ssl_icon():
    g = Graph()
    s = service(g)
    domain(
        g,
        s,
        dict(
            DomainName="api.example.test",
            CertificateId="cert-one",
            IsForcedHttps=False,
            NetType="INNER",
            IsDefaultMapping=False,
        ),
    )
    cert = next(n for n in g.nodes.values() if n["kind"] == "ssl.certificate")
    assert cert["status"] == "reference" and cert["region"] == "global"
    assert icon_for(cert["kind"]) != "unmapped.svg"
    assert not any("PUBLIC" in e["relationship"] for e in g.edges.values())


def test_cos_backend_matches_full_collected_bucket_only():
    g = Graph()
    s = service(g)
    api(
        g,
        s,
        dict(
            ServiceId=s["resource_id"],
            ApiId="api-cos",
            ServiceType="COS",
            ServiceConfig=dict(
                CosConfig=dict(BucketName="assets-12345", Authorization=False, Action="GetObject")
            ),
        ),
        True,
    )
    expected = g.add("100", "eu-frankfurt", "cos.bucket", "assets-12345")
    g.add("200", "eu-frankfurt", "cos.bucket", "assets-12345")
    g.add("100", "ap-guangzhou", "cos.bucket", "assets-12345")
    link_backends(g)
    assert [
        e["target"] for e in g.edges.values() if e["relationship"] == "CONFIGURED_COS_BACKEND"
    ] == [expected]


def test_service_identity_mismatch_adds_no_api():
    g = Graph()
    s = service(g)
    with pytest.raises(CollectionError) as e:
        api(g, s, dict(ServiceId="wrong", ApiId="api-one"), True)
    assert e.value.code == "GatewayServiceMismatch" and len(g.nodes) == 1


def test_invalid_detail_does_not_mark_api_detail_complete():
    g = Graph()
    s = service(g)
    aid = api(g, s, dict(ServiceId=s["resource_id"], ApiId="api-one"))
    with pytest.raises(CollectionError):
        api(g, s, dict(ServiceId=s["resource_id"], ApiId="api-one", Environments="wrong"), True)
    assert g.nodes[aid]["properties"]["detail_collected"] is False


def test_denied_service_and_api_details_leave_independent_scopes_available():
    g = Graph()
    s = service(g)

    class T:
        def call(self, service, action, region=None, **params):
            assert params["ServiceId"] == "service-one"
            if action in ("DescribeService", "DescribeApi"):
                raise CollectionError("UnauthorizedOperation")
            if action == "DescribeServiceReleaseVersion":
                return dict(Result=dict(VersionList=[], TotalCount=0))
            if action == "DescribeServiceEnvironmentList":
                return dict(
                    Result=dict(
                        EnvironmentList=[dict(EnvironmentName="test", Status=0)], TotalCount=1
                    )
                )
            if action == "DescribeServiceSubDomains":
                return dict(Result=dict(DomainSet=[], TotalCount=0))
            return dict(
                Result=dict(
                    ApiIdStatusSet=[dict(ServiceId="service-one", ApiId="api-one")], TotalCount=1
                )
            )

    collect_service(CollectorRunner(g, T(), "100", [], lambda _: None), s["id"])
    assert [c["status"] for c in g.coverage] == [
        "denied",
        "empty",
        "complete",
        "empty",
        "complete",
        "denied",
    ]
    assert (
        next(n for n in g.nodes.values() if n["kind"] == "apigateway.api")["properties"][
            "detail_collected"
        ]
        is False
    )


def test_end_to_end_gateway_nested_response_and_api_detail_identity_control():
    class T:
        def call(self, service, action, region=None, **params):
            if service == "sts":
                return dict(AccountId="100", PrincipalId="reader")
            if service == "cloudrc":
                return dict(Resources=[])
            if action == "DescribeServicesStatus":
                return dict(Result=dict(ServiceSet=[dict(ServiceId="service-one")], TotalCount=1))
            if action == "DescribeService":
                return dict(ServiceId="service-one", NetTypes=["INNER"], UniqVpcId="vpc-one")
            key = {
                "DescribeServiceReleaseVersion": "VersionList",
                "DescribeServiceEnvironmentList": "EnvironmentList",
                "DescribeServiceSubDomains": "DomainSet",
            }.get(action)
            if key:
                return dict(Result={key: [], "TotalCount": 0})
            if action == "DescribeApisStatus":
                return dict(
                    Result=dict(
                        ApiIdStatusSet=[dict(ServiceId="service-one", ApiId="api-one")],
                        TotalCount=1,
                    )
                )
            assert action == "DescribeApi" and params["ApiId"] == "api-one"
            return dict(Result=dict(ServiceId="service-one", ApiId="api-other", ServiceType="MOCK"))

    data = collect(
        ["test"],
        ["eu-frankfurt"],
        services={"apigateway"},
        progress=lambda _: None,
        transport_factory=lambda _: T(),
    )
    assert (
        next(c for c in data["coverage"] if c["action"] == "DescribeApi")["error"]
        == "GatewayApiMismatch"
    )
    assert not any(n["kind"] == "apigateway.integration" for n in data["nodes"])
    assert len(data["nodes"]) == 3
