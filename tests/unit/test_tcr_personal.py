import pytest

from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.tcr_personal import collect
from tencent_cloud_cartography.transport import CollectionError


@pytest.mark.parametrize("failure", [None, "scope", "host", "denied", "duplicate", "count"])
def test_owned_personal_repositories_and_scoped_tags(failure):
    graph, calls = Graph(), []

    class Transport:
        def call(self, service, action, region=None, **params):
            calls.append(action)
            assert service == "tcr" and region == "eu-frankfurt"
            assert params["Limit"] == 100
            if params["Offset"]:
                assert failure == "count" and params["Offset"] == 1
                return dict(
                    Data=dict(
                        TagCount=2, Server="ccr.ccs.tencentyun.com", RepoName="team/app", TagInfo=[]
                    )
                )
            if action == "DescribeRepositoryOwnerPersonal":
                return dict(
                    Data=dict(
                        TotalCount=1,
                        Server="ccr.ccs.tencentyun.com",
                        RepoInfo=[
                            dict(RepoName="team/app", Public=0, TagCount=1, IsQcloudOfficial=False)
                        ],
                    )
                )
            assert action == "DescribeImagePersonal" and params["RepoName"] == "team/app"
            if failure == "denied":
                raise CollectionError("UnauthorizedOperation")
            row = dict(
                TagName="v1",
                TagId="opaque-id",
                ImageId="docker-id",
                Architecture="arm64",
                OS="linux",
                SizeByte=0,
                Config="NEVER_SAVE",
                Env="NEVER_SAVE",
            )
            return dict(
                Data=dict(
                    TagCount=2 if failure == "count" else 1,
                    Server="other.example" if failure == "host" else "ccr.ccs.tencentyun.com",
                    RepoName="other/app" if failure == "scope" else "team/app",
                    TagInfo=[row, row] if failure == "duplicate" else [row],
                )
            )

    collect(CollectorRunner(graph, Transport(), "100", [], lambda _: None), "eu-frankfurt")
    assert len([n for n in graph.nodes.values() if n["kind"] == "tcr.personalrepository"]) == 1
    tags = [n for n in graph.nodes.values() if n["kind"] == "tcr.personaltag"]
    if failure:
        assert graph.coverage[-1]["status"] in ("error", "denied")
        if failure != "count":
            assert not tags
    else:
        assert len(tags) == 1 and tags[0]["properties"]["SizeByte"] == 0
        assert tags[0]["properties"]["content_digest_verified"] is False
        assert "NEVER_SAVE" not in str(graph.snapshot())
    assert not any(n["kind"] == "tcr.image" for n in graph.nodes.values())
    assert calls[:2] == ["DescribeRepositoryOwnerPersonal", "DescribeImagePersonal"]
