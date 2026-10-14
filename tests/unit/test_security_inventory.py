import math

import pytest

from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.security_inventory import collect
from tencent_cloud_cartography.transport import CollectionError


def test_package_and_vendor_vulnerability_metadata_no_execution_or_private_text():
    g = Graph()
    g.add("100", "eu-frankfurt", "cwp.machine", "agent-one")
    g.add("100", "global", "tcss.image", "image-one")
    calls = []

    class T:
        def call(self, s, a, region=None, **params):
            calls.append((s, a, params))
            if a == "DescribeAssetSystemPackageList":
                return dict(
                    Total=1,
                    Packages=[dict(Uuid="agent-one", Name="libssl", Version="1.2", Type="dpkg")],
                )
            if a == "DescribeVulList":
                assert params["Filters"] == [dict(Name="Uuid", Values=["agent-one"])]
                return dict(
                    TotalCount=1,
                    VulInfoList=[
                        dict(
                            VulId=1,
                            Name="vendor advisory",
                            CveId="CVE-2026-0001",
                            Status=0,
                            Method=0,
                            CvssScore=7.5,
                            Descript="OMIT",
                        )
                    ],
                )
            assert params["ImageID"] == "image-one"
            return dict(
                TotalCount=1,
                List=[
                    dict(
                        CVEID="CVE-2026-0001",
                        Name="image advisory",
                        Component="libssl",
                        Version="1.2",
                        CVSSV3Score=7.5,
                        OfficialSolution="OMIT",
                    )
                ],
            )

    collect(CollectorRunner(g, T(), "100", ["eu-frankfurt"], lambda _: None))
    assert "OMIT" not in g.dump()
    assert all(r["status"] == "complete" for r in g.coverage)
    assert {"cwp.package", "cwp.vulnerability", "tcss.vulnerability"} <= {
        n["kind"] for n in g.nodes.values()
    }
    assert all(
        n["properties"]["independently_validated"] is False
        and n["properties"]["exploit_executed"] is False
        for n in g.nodes.values()
        if n["kind"].endswith("vulnerability")
    )
    assert not any(a.startswith(("Scan", "Fix", "Repair", "Modify")) for _, a, _ in calls)


@pytest.mark.parametrize("failure", ["asset", "score", "denied"])
def test_bad_vendor_data_preserves_machine_and_independent_queries(failure):
    g = Graph()
    g.add("100", "eu-frankfurt", "cwp.machine", "agent-one")

    class T:
        def call(self, s, a, region=None, **params):
            if a == "DescribeAssetSystemPackageList":
                if failure == "denied":
                    raise CollectionError("UnauthorizedOperation")
                return dict(
                    Total=1,
                    Packages=[
                        dict(
                            Uuid="other" if failure == "asset" else "agent-one",
                            Name="p",
                            Version="1",
                        )
                    ],
                )
            return dict(
                TotalCount=1,
                VulInfoList=[
                    dict(VulId=1, Status=0, CvssScore=math.inf if failure == "score" else 7.5)
                ],
            )

    collect(CollectorRunner(g, T(), "100", ["eu-frankfurt"], lambda _: None))
    assert any(r["status"] in ("denied", "error") for r in g.coverage)
    assert any(n["kind"] == "cwp.machine" for n in g.nodes.values())
    if failure == "score":
        assert not any(n["kind"] == "cwp.vulnerability" for n in g.nodes.values())
