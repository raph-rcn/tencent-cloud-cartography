import json

import pytest

from tencent_cloud_cartography.catalog import COLLECTORS
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.elasticsearch import collect
from tencent_cloud_cartography.model import Graph


@pytest.mark.parametrize("failure", [None, "owner", "region", "duplicate", "endpoint", "flag"])
def test_es_metadata_placement_capacity_and_access_flags_without_reachability_claim(failure):
    graph = Graph()
    row = dict(
        InstanceId="es-one",
        Uin="100",
        Region="eu-frankfurt",
        InstanceName="search",
        VpcUid="vpc-one",
        SubnetUid="subnet-one",
        SecurityGroups=["sg-one"],
        Status=-1,
        NodeNum=3,
        PublicAccess="OPEN",
        EsVersion="8.18",
        EsPrivateUrl="https://search.example.test:9200/path?token=OMIT",
        EsPublicAcl=dict(WhiteIpList=["0.0.0.0/0"], BlackIpList=[]),
        NodeInfoList=[dict(Type="hotData", NodeNum=3, DiskEncrypt=1, KmsKeyId="key-one")],
        EsConfig="OMIT",
        KibanaConfig="OMIT",
        EsConfigSets=[dict(EsConfig="OMIT")],
    )
    if failure == "owner":
        row["Uin"] = "200"
    if failure == "region":
        row["Region"] = "ap-guangzhou"
    if failure == "endpoint":
        row["EsPrivateUrl"] = "https://user:secret@example.test"
    if failure == "flag":
        row["PublicAccess"] = "unexpected"

    class Transport:
        def call(self, s, a, region=None, **params):
            assert (s, a, region) == ("es", "DescribeInstances", "eu-frankfurt")
            assert params == dict(Offset=0, Limit=100)
            return dict(
                InstanceList=[row, row] if failure == "duplicate" else [row],
                TotalCount=2 if failure == "duplicate" else 1,
            )

    spec = next(s for s in COLLECTORS if s.kind == "es.instance")
    collect(CollectorRunner(graph, Transport(), "100", [], lambda _: None), spec, "eu-frankfurt")
    if failure:
        assert graph.coverage[-1]["status"] == "error" and not graph.nodes
    else:
        props = next(n for n in graph.nodes.values() if n["kind"] == "es.instance")["properties"]
        assert props["Status"] == -1 and not props["internet_exposure_verified"]
        assert len(graph.edges) == 3 and "OMIT" not in json.dumps(graph.snapshot())
        assert props["PublicAccess"] == "OPEN" and "0.0.0.0/0" in props["EsPublicAcl"]
