import json

import pytest

from tencent_cloud_cartography.catalog import EXTRA_COLLECTORS
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.families import run
from tencent_cloud_cartography.international import call as international_call
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.tic_transport import call as tic_call
from tencent_cloud_cartography.transport import CollectionError


def test_tic_stack_versions_events_scoped_without_source_or_parameters():
    calls = []

    class T:
        def call(self, s, a, region=None, **params):
            calls.append((a, params))
            if a == "DescribeStacks":
                return dict(
                    TotalCount=1, Stacks=[dict(StackId="stk-one", StackName="one", Region=region)]
                )
            assert params["Filters"] == [dict(Name="StackId", Values=["stk-one"])]
            if a == "DescribeStackVersions":
                return dict(
                    TotalCount=1,
                    Versions=[dict(VersionId="ver-one", StackId="stk-one", VersionName="one")],
                )
            return dict(
                TotalCount=1,
                Events=[
                    dict(
                        EventId="event-one",
                        VersionId="ver-one",
                        StackId="stk-one",
                        Status="success",
                        Message="OMIT",
                    )
                ],
            )

    g = Graph()
    run(CollectorRunner(g, T(), "100", ["eu-frankfurt"], lambda _: None), {"tic"})
    assert {n["resource_id"] for n in g.nodes.values()} == {
        "stk-one",
        "stk-one/ver-one",
        "stk-one/event-one",
    }
    assert "OMIT" not in g.dump()
    assert any(e["relationship"] == "HAS_EVENT" for e in g.edges.values())
    assert all(r["status"] == "complete" for r in g.coverage)


@pytest.mark.parametrize(
    "kind,params",
    [
        ("DestroyStack", dict(Offset=0, Limit=100)),
        ("DescribeStacks", dict(Offset=0, Limit=100, Content="x")),
        (
            "DescribeStackVersions",
            dict(Offset=0, Limit=100, Filters=[dict(Name="StackId", Values=["../bad"])]),
        ),
    ],
)
def test_tic_common_sdk_transport_blocks_writes_payloads_and_invalid_filters(kind, params):
    with pytest.raises(CollectionError):
        tic_call("default", kind, "eu-frankfurt", params, 30)


def test_reserved_inventory_international_sdk_metadata_contract(monkeypatch):
    from tencentcloud.cvm.v20170312 import cvm_client

    from tencent_cloud_cartography import cos_transport

    monkeypatch.setattr(
        cos_transport,
        "credentials",
        lambda _: dict(SecretId="fake-id", SecretKey="fake-key", Token=None),
    )
    calls = []

    def describe(self, request):
        calls.append(
            (self.profile.httpProfile.endpoint, self.region, json.loads(request.to_json_string()))
        )

        class Response:
            def to_json_string(self):
                return json.dumps(
                    dict(
                        TotalCount=1,
                        ReservedInstancesSet=[
                            dict(ReservedInstanceId="ri-one", State="active", InstanceCount=1)
                        ],
                    )
                )

        return Response()

    monkeypatch.setattr(cvm_client.CvmClient, "DescribeReservedInstances", describe)
    result = international_call(
        "default", "DescribeReservedInstances", "eu-frankfurt", dict(Offset=0, Limit=100), 30
    )
    assert result["ReservedInstancesSet"][0]["State"] == "active"
    assert calls[0][:2] == ("cvm.intl.tencentcloudapi.com", "eu-frankfurt")
    assert {k: v for k, v in calls[0][2].items() if v is not None} == dict(Offset=0, Limit=100)
    assert next(s for s in EXTRA_COLLECTORS if s.kind == "cvm.reservedinstance").require_total
