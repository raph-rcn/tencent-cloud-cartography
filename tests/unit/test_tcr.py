import json

import pytest

from tencent_cloud_cartography.catalog import ALLOWED_ACTIONS, COLLECTORS
from tencent_cloud_cartography.collect import CollectorRunner, collect
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.tcr import collect_registry, image, namespace, repository
from tencent_cloud_cartography.topology import topology
from tencent_cloud_cartography.transport import CollectionError, TccliTransport

DIGEST = "sha256:" + "a" * 64


def registry(graph, rid="tcr-one", account="100", region="eu-frankfurt"):
    spec = next(s for s in COLLECTORS if s.kind == "tcr.instance")
    nid = graph.native(account, region, spec, dict(RegistryId=rid, RegistryName=rid), "fixture")
    return graph.nodes[nid]


def test_registry_repository_tag_and_digest_identity_and_official_icons():
    g = Graph()
    for reg in (
        registry(g),
        registry(g, "tcr-two"),
        registry(g, account="200"),
        registry(g, region="ap-guangzhou"),
    ):
        namespace(g, reg, dict(Name="team", Public=False, AutoScan=False), "fixture")
        rid = repository(g, reg, dict(Name="team/app", Namespace="team", Public=False), "fixture")
        for tag in ("v1", "latest", None):
            image(
                g,
                reg,
                g.nodes[rid],
                dict(Digest=DIGEST, ImageVersion=tag, Size=0, Kind="Artifact::image"),
                "fixture",
            )
    assert len([n for n in g.nodes.values() if n["kind"] == "tcr.repository"]) == 4
    assert len([n for n in g.nodes.values() if n["kind"] == "tcr.imagereference"]) == 12
    # Same content is deduplicated only within account and region.
    assert len([n for n in g.nodes.values() if n["kind"] == "tcr.image"]) == 3
    assert all(icon_for(n["kind"]) != "unmapped.svg" for n in g.nodes.values())
    assert all(n["status"] == "enriched" for n in g.nodes.values())
    ns = next(n for n in g.nodes.values() if n["kind"] == "tcr.namespace")
    assert ns["properties"]["Public"] is False and ns["properties"]["AutoScan"] is False
    assert topology(g.snapshot())["stats"]["resources"] == 4
    assert all(n["properties"]["Size"] == 0 for n in g.nodes.values() if n["kind"] == "tcr.image")


@pytest.mark.parametrize(
    "raw",
    [
        dict(Name="wrong/app", Namespace="team"),
        dict(Name="team/../app", Namespace="team"),
        dict(Name="app", Namespace="team"),
    ],
)
def test_repository_scope_mismatch_does_not_create_nodes(raw):
    g = Graph()
    reg = registry(g)
    with pytest.raises(CollectionError):
        repository(g, reg, raw, "fixture")
    assert len(g.nodes) == 1


@pytest.mark.parametrize(
    "raw",
    [
        dict(Digest="sha256:abc"),
        dict(Digest=DIGEST, ImageVersion="../../bad"),
        dict(Digest=""),
        dict(Digest=DIGEST, ImageVersion=42),
    ],
)
def test_invalid_image_identity_does_not_create_content_or_tags(raw):
    g = Graph()
    reg = registry(g)
    rid = repository(g, reg, dict(Name="team/app", Namespace="team"), "fixture")
    before = len(g.nodes)
    with pytest.raises(CollectionError):
        image(g, reg, g.nodes[rid], raw, "fixture")
    assert len(g.nodes) == before


def test_repository_and_images_use_page_numbers_and_do_not_require_namespace_permission():
    g = Graph()
    reg = registry(g)
    calls = []

    class Transport:
        def call(self, service, action, region=None, **params):
            calls.append((action, params))
            assert service == "tcr" and region == "eu-frankfurt"
            assert "Filters" not in params
            if action == "DescribeNamespaces":
                assert params == dict(RegistryId="tcr-one", All=True)
                raise CollectionError("UnauthorizedOperation")
            if action == "DescribeRepositories":
                assert params["Offset"] in (1, 2)
                rows = (
                    [dict(Name=f"team/app{i}", Namespace="team", Public=False) for i in range(100)]
                    if params["Offset"] == 1
                    else [dict(Name="team/nested/app", Namespace="team")]
                )
                return dict(RepositoryList=rows, TotalCount=101, RequestId=str(params["Offset"]))
            assert action == "DescribeImages" and params["NamespaceName"] == "team"
            if params["RepositoryName"] != "nested/app":
                return dict(ImageInfoList=[], TotalCount=0)
            rows = (
                [dict(Digest=DIGEST, ImageVersion=f"v{i}") for i in range(100)]
                if params["Offset"] == 1
                else [dict(Digest=DIGEST, ImageVersion="last")]
            )
            return dict(ImageInfoList=rows, TotalCount=101)

    collect_registry(CollectorRunner(g, Transport(), "100", [], lambda _: None), reg["id"], {})
    assert g.coverage[0]["status"] == "denied"
    assert g.coverage[1]["count"] == 101 and g.coverage[1]["request_ids"] == ["1", "2"]
    assert g.coverage[-1]["count"] == 101
    assert [
        p["Offset"]
        for a, p in calls
        if a == "DescribeImages" and p["RepositoryName"] == "nested/app"
    ] == [1, 2]
    assert (
        next(n for n in g.nodes.values() if n["kind"] == "tcr.namespace")["status"] == "reference"
    )


def test_duplicate_tag_does_not_overwrite_prior_digest_and_marks_partial_scope():
    g = Graph()
    reg = registry(g)

    class Transport:
        def call(self, service, action, region=None, **params):
            if action == "DescribeNamespaces":
                return dict(NamespaceList=[], TotalCount=0)
            if action == "DescribeRepositories":
                return dict(RepositoryList=[dict(Name="team/app", Namespace="team")], TotalCount=1)
            return dict(
                ImageInfoList=[
                    dict(Digest=DIGEST, ImageVersion="v1"),
                    dict(Digest="sha256:" + "b" * 64, ImageVersion="v1"),
                ],
                TotalCount=2,
            )

    collect_registry(CollectorRunner(g, Transport(), "100", [], lambda _: None), reg["id"], {})
    assert g.coverage[-1]["error"] == "DuplicateTcrResource" and g.coverage[-1]["count"] == 1
    assert [n["resource_id"] for n in g.nodes.values() if n["kind"] == "tcr.image"] == [DIGEST]


def test_all_namespaces_truncation_is_visible_but_repositories_continue():
    g = Graph()
    reg = registry(g)

    class Transport:
        def call(self, service, action, region=None, **params):
            if action == "DescribeNamespaces":
                return dict(NamespaceList=[dict(Name="team")], TotalCount=2)
            return dict(RepositoryList=[], TotalCount=0)

    collect_registry(CollectorRunner(g, Transport(), "100", [], lambda _: None), reg["id"], {})
    assert g.coverage[0]["error"] == "CountMismatch"
    assert g.coverage[1]["status"] == "empty"


def test_end_to_end_collector_includes_tcr_children_without_credentials_or_payloads():
    class Transport:
        def call(self, service, action, region=None, **params):
            assert (service, action) in ALLOWED_ACTIONS
            if service == "sts":
                return dict(AccountId="100", PrincipalId="reader")
            if service == "cloudrc":
                return dict(Resources=[])
            if action == "DescribeInstances":
                return dict(
                    Registries=[
                        dict(
                            RegistryId="tcr-one",
                            RegistryName="Registry",
                            EnableAnonymous=False,
                            PublicDomain="registry.example.test",
                        )
                    ],
                    TotalCount=1,
                )
            if action == "DescribeNamespaces":
                return dict(
                    NamespaceList=[
                        dict(
                            Name="team",
                            Public=True,
                            AutoScan=False,
                            Metadata=[dict(Key="secret", Value="SENSITIVE")],
                        )
                    ],
                    TotalCount=1,
                )
            if action == "DescribeRepositories":
                return dict(
                    RepositoryList=[dict(Name="team/app", Namespace="team", Public=True)],
                    TotalCount=1,
                )
            if action == "DescribeImages":
                assert "Filters" not in params and params["Offset"] == 1
                return dict(
                    ImageInfoList=[
                        dict(
                            Digest=DIGEST,
                            ImageVersion="latest",
                            KmsSignature="SENSITIVE",
                            Config="SENSITIVE",
                        )
                    ],
                    TotalCount=1,
                )
            pytest.fail(action)

    snapshot = collect(
        ["test"],
        ["eu-frankfurt"],
        services={"tcr"},
        progress=lambda _: None,
        transport_factory=lambda _: Transport(),
    )
    assert len(snapshot["nodes"]) == 5 and len(snapshot["edges"]) == 5
    assert "SENSITIVE" not in json.dumps(snapshot)
    assert all(
        c["status"] in {"empty", "complete"}
        for c in snapshot["coverage"]
        if c["service"] in {"tcr", "sts", "cloudrc"}
    )
    reg = next(n for n in snapshot["nodes"] if n["kind"] == "tcr.instance")
    assert reg["properties"]["EnableAnonymous"] is False
    for action in ("CreateInstanceToken", "DescribeImageManifests", "DeleteImage"):
        with pytest.raises(CollectionError) as exc:
            TccliTransport().call("tcr", action)
        assert exc.value.code == "BlockedAction"


@pytest.mark.parametrize("total", [None, -1, True, "2"])
def test_tcr_missing_or_invalid_total_cannot_claim_complete(total):
    from tencent_cloud_cartography.catalog import TCR_CHILDREN
    from tencent_cloud_cartography.transport import pages

    class Transport:
        def call(self, *args, **kwargs):
            return dict(NamespaceList=[], TotalCount=total)

    with pytest.raises(CollectionError) as exc:
        list(pages(Transport(), TCR_CHILDREN["namespace"], "eu-frankfurt", {"All": True}))
    assert exc.value.code == "InvalidTotal"
