import json
from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.catalog import ALLOWED_ACTIONS
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.tags import collect_tags, link_tags
from tencent_cloud_cartography.topology import topology
from tencent_cloud_cartography.transport import CollectionError

REGION = "eu-frankfurt"
QCS = "qcs::cvm:eu-frankfurt:uin/100:instance/ins-one"


def binding(qcs=QCS, pairs=None):
    return {
        "Resource": qcs,
        "Tags": [{"TagKey": "team", "TagValue": "analytics"}] if pairs is None else pairs,
    }


def response(rows=None, token=""):
    return dict(
        ResourceTagMappingList=[binding()] if rows is None else rows,
        PaginationToken=token,
        RequestId="request",
    )


def run(responses=None, nodes=None, max_pages=10000):
    graph, calls = Graph(), []
    target = graph.add("100", REGION, "cvm.instance", "ins-one", "Worker")
    for raw in nodes or []:
        graph.add(**raw)
    values = iter([response()] if responses is None else responses)

    def call(service, action, **kwargs):
        assert (service, action) == ("tag", "GetResources")
        assert kwargs["region"] == "global" and kwargs["MaxResults"] == 200
        assert not {"ResourceList", "TagFilters"} & kwargs.keys()
        calls.append(kwargs)
        value = next(values)
        if isinstance(value, Exception):
            raise value
        return value

    runner = CollectorRunner(graph, SimpleNamespace(call=call), "100", [REGION], lambda _: None)
    collect_tags(runner, max_pages=max_pages)
    link_tags(graph)
    return graph, target, calls


def nodes(graph, kind):
    return [n for n in graph.nodes.values() if n["kind"] == kind]


def test_tags_are_graph_relationships_with_explicit_api_provenance_and_icon():
    graph, target, calls = run()
    assert not nodes(graph, "tag.resource")
    tag = nodes(graph, "tag.tag")[0]
    assert tag["account"] == "100" and tag["region"] == "global"
    assert tag["properties"]["tag_key"] == "team"
    assert tag["properties"]["tag_value"] == "analytics"
    assert list(graph.edges.values())[0] == dict(
        id=list(graph.edges)[0],
        source=target,
        target=tag["id"],
        relationship="TAGGED",
        provenance="tag.GetResources",
    )
    assert graph.nodes[target]["properties"]["tag_resolution"] == "exact-collected-identity"
    assert graph.snapshot()["status"] == "complete"
    assert graph.coverage[0]["count"] == 1 and graph.coverage[0]["scanned_count"] == 1
    assert calls[0]["PaginationToken"] == ""
    assert {a for s, a in ALLOWED_ACTIONS if s == "tag"} == {"GetResources"}
    assert icon_for("tag.tag") == "en-application-programming-interface.svg"
    assert icon_for("tag.resource") == icon_for("tag.tag")


def test_token_pagination_including_empty_intermediate_page_and_region_filter():
    graph, _, calls = run(
        [
            response([], "page2"),
            response([binding()], "page3"),
            response([binding("qcs::cvm:ap-beijing:uin/100:instance/ins-other")]),
        ]
    )
    assert [c["PaginationToken"] for c in calls] == ["", "page2", "page3"]
    assert graph.coverage[0]["scanned_count"] == 2
    assert graph.coverage[0]["out_of_scope_count"] == 1
    assert graph.coverage[0]["count"] == 1
    assert not any(n["region"] == "ap-beijing" for n in graph.nodes.values())


def test_same_tag_is_shared_without_identity_delimiter_collisions_or_case_folding():
    pairs = [
        {"TagKey": "a:b", "TagValue": "c"},
        {"TagKey": "a", "TagValue": "b:c"},
        {"TagKey": "Team", "TagValue": ""},
        {"TagKey": "team", "TagValue": "数据"},
    ]
    graph, _, _ = run(
        [
            response(
                [
                    binding(pairs=pairs),
                    binding("qcs::cvm:eu-frankfurt:uin/100:instance/ins-two", pairs),
                ]
            )
        ],
        nodes=[dict(account="100", region=REGION, kind="cvm.instance", rid="ins-two")],
    )
    assert len(nodes(graph, "tag.tag")) == 4 and len(graph.edges) == 8
    assert any(t["properties"]["tag_value"] == "" for t in nodes(graph, "tag.tag"))


def test_same_resource_id_other_account_region_and_kind_do_not_receive_tags():
    graph, target, _ = run(
        nodes=[
            dict(account="200", region=REGION, kind="cvm.instance", rid="ins-one"),
            dict(account="100", region="ap-beijing", kind="cvm.instance", rid="ins-one"),
            dict(account="100", region=REGION, kind="lighthouse.instance", rid="ins-one"),
        ]
    )
    assert {e["source"] for e in graph.edges.values()} == {target}


def test_global_cam_roles_and_regional_cbs_aliases_match_collected_ids():
    rows = [
        binding("qcs::cam::uin/100:role/123"),
        binding("qcs::cvm:eu-frankfurt:uin/100:volume/disk-a"),
    ]
    graph, _, _ = run(
        [response(rows)],
        nodes=[
            dict(account="100", region="global", kind="cam.role", rid="123"),
            dict(account="100", region=REGION, kind="cbs.disk", rid="disk-a"),
        ],
    )
    assert not nodes(graph, "tag.resource")
    tagged = {graph.nodes[e["source"]]["kind"] for e in graph.edges.values()}
    assert tagged == {"cam.role", "cbs.disk"}


@pytest.mark.parametrize(
    "qcs",
    [
        "qcs::cos:eu-frankfurt:uid/12345:prefix/assets",
        "qcs::cos:eu-frankfurt:uid/12345:prefix//12345/assets",
        "qcs::cos:eu-frankfurt:uid/12345:assets-12345",
    ],
)
def test_cos_appid_forms_require_same_account_collected_bucket(qcs):
    graph, _, _ = run(
        [response([binding(qcs)])],
        nodes=[dict(account="100", region=REGION, kind="cos.bucket", rid="assets-12345")],
    )
    assert not nodes(graph, "tag.resource")
    assert graph.nodes[next(iter(graph.edges.values()))["source"]]["kind"] == "cos.bucket"
    graph, _, _ = run(
        [response([binding(qcs)])],
        nodes=[dict(account="200", region=REGION, kind="cos.bucket", rid="assets-12345")],
    )
    assert nodes(graph, "tag.resource")[0]["properties"]["tag_resolution"] == "unresolved"
    assert all(graph.nodes[e["source"]]["account"] == "100" for e in graph.edges.values())


def test_conflicting_cos_alias_observations_do_not_apply_either_tag_set():
    rows = [
        binding("qcs::cos:eu-frankfurt:uid/12345:prefix/assets"),
        binding(
            "qcs::cos:eu-frankfurt:uid/12345:assets-12345",
            [{"TagKey": "team", "TagValue": "changed"}],
        ),
    ]
    graph, _, _ = run(
        [response(rows)],
        nodes=[dict(account="100", region=REGION, kind="cos.bucket", rid="assets-12345")],
    )
    assert {b["properties"]["tag_resolution"] for b in nodes(graph, "tag.resource")} == {
        "conflicting-observations"
    }
    assert not nodes(graph, "cos.bucket")[0]["properties"].get("tag_api_tags")
    assert graph.snapshot()["status"] == "partial"


def test_identical_cos_aliases_merge_without_duplicate_relationships():
    rows = [
        binding("qcs::cos:eu-frankfurt:uid/12345:prefix/assets"),
        binding("qcs::cos:eu-frankfurt:uid/12345:assets-12345"),
    ]
    graph, _, _ = run(
        [response(rows)],
        nodes=[dict(account="100", region=REGION, kind="cos.bucket", rid="assets-12345")],
    )
    assert len(graph.edges) == 1 and not nodes(graph, "tag.resource")
    assert len(json.loads(nodes(graph, "cos.bucket")[0]["properties"]["tag_api_resources"])) == 2


def test_unmapped_and_missing_region_resources_remain_unresolved_not_guessed():
    rows = [
        binding("qcs::unknown:eu-frankfurt:uin/100:instance/ins-one"),
        binding("qcs::cvm::uin/100:instance/ins-one"),
    ]
    graph, target, _ = run([response(rows)])
    assert len(nodes(graph, "tag.resource")) == 2
    assert not graph.nodes[target]["properties"].get("tag_api_tags")
    assert {n["region"] for n in nodes(graph, "tag.resource")} == {REGION, "unknown"}
    assert graph.snapshot()["status"] == "partial"


def test_reference_only_target_does_not_claim_native_identity_resolution():
    graph, _, _ = run(
        [response([binding("qcs::cvm:eu-frankfurt:uin/100:instance/ins-ref")])],
        nodes=[
            dict(
                account="100", region=REGION, kind="cvm.instance", rid="ins-ref", status="reference"
            )
        ],
    )
    assert len(nodes(graph, "tag.resource")) == 1


@pytest.mark.parametrize(
    "qcs,error",
    [
        ("qcs::cvm:eu-frankfurt:uin/200:instance/ins-one", "TagAccountMismatch"),
        ("qcs::cvm:eu-frankfurt:uid/100:instance/ins-one", "InvalidTagOwner"),
        ("qcs::cvm:eu-frankfurt:uin/100:instance/*", "InvalidTagResource"),
        ("qcs::cvm:eu-frankfurt:uin/100:instance/", "InvalidTagResource"),
        ("qcs::cvm:bad region:uin/100:instance/ins-one", "InvalidTagRegion"),
        ("qcs::cos:eu-frankfurt:uid/12345:prefix/assets/object", "InvalidTagBucket"),
        ("qcs::cos:eu-frankfurt:uid/12345:prefix//999/assets", "InvalidTagBucket"),
        ("qcs::cos:eu-frankfurt:uid/12345:assets-999", "InvalidTagBucket"),
    ],
)
def test_invalid_identity_fails_without_tag_graph_mutation(qcs, error):
    graph, _, _ = run([response([binding(qcs)])])
    assert not graph.edges and not nodes(graph, "tag.tag")
    assert graph.coverage[0]["error"] == error and graph.coverage[0]["count"] == 0


@pytest.mark.parametrize(
    "pairs,error",
    [
        ({}, "InvalidTagArray"),
        ([{"TagKey": "", "TagValue": "a"}], "InvalidTagField"),
        ([{"TagKey": "a", "TagValue": None}], "InvalidTagField"),
        ([{"TagKey": "a\u0000b", "TagValue": "c"}], "InvalidTagField"),
        ([{"TagKey": "a", "TagValue": "1"}, {"TagKey": "a", "TagValue": "2"}], "DuplicateTagKey"),
    ],
)
def test_invalid_tags_do_not_leave_half_written_bindings(pairs, error):
    graph, _, _ = run([response([binding(pairs=pairs)])])
    assert not graph.edges and not nodes(graph, "tag.resource")
    assert graph.coverage[0]["error"] == error


@pytest.mark.parametrize(
    "responses,error",
    [
        ([dict(ResourceTagMappingList=[])], "InvalidTagPaginationToken"),
        ([response([], None)], "InvalidTagPaginationToken"),
        ([dict(ResourceTagMappingList=None, PaginationToken="")], "InvalidTagResponse"),
        ([response([], "same"), response([], "same")], "PaginationStalled"),
        ([response([binding()], "next"), response([binding()])], "DuplicateTagResource"),
        ([CollectionError("AccessDenied")], "AccessDenied"),
    ],
)
def test_incomplete_and_denied_scopes_are_not_empty_success(responses, error):
    graph, _, _ = run(responses)
    assert graph.coverage[0]["error"] == error
    assert graph.coverage[0]["status"] in {"error", "denied"}
    assert graph.snapshot()["status"] == "partial"


def test_max_page_limit_keeps_partial_coverage():
    graph, _, _ = run([response([], "next")], max_pages=1)
    assert graph.coverage[0]["error"] == "PageLimit"


def test_empty_tag_array_preserved_and_full_view_keeps_global_tags_when_region_selected():
    graph, target, _ = run([response([binding(pairs=[])])])
    assert graph.nodes[target]["properties"]["tag_api_tags"] == "[]"
    assert not nodes(graph, "tag.tag")
    graph, _, _ = run()
    graph.accounts["100"] = {"id": "100", "name": "test", "display": "test"}
    full = topology(graph.snapshot(), view="full", region=REGION)
    assert full["stats"]["resources"] == 2 and full["stats"]["relationships"] == 1
    assert topology(graph.snapshot())["stats"]["resources"] == 1


def test_emr_node_alias_matches_only_unique_returned_native_id():
    graph = Graph()
    a = graph.add("100", REGION, "emr.node", "emr-a/EmrResourceId/emr-vm-one")
    graph.nodes[a]["properties"]["EmrResourceId"] = "emr-vm-one"
    raw = response([binding("qcs::emr:eu-frankfurt:uin/100:emr-vm/emr-vm-one")])
    runner = CollectorRunner(
        graph, SimpleNamespace(call=lambda *a, **kw: raw), "100", [REGION], lambda _: None
    )
    collect_tags(runner)
    b = graph.add("100", REGION, "emr.node", "emr-b/EmrResourceId/emr-vm-one")
    graph.nodes[b]["properties"]["EmrResourceId"] = "emr-vm-one"
    link_tags(graph)
    assert nodes(graph, "tag.resource")[0]["properties"]["tag_resolution"] == "ambiguous"
    assert not graph.nodes[a]["properties"].get("tag_api_tags")
