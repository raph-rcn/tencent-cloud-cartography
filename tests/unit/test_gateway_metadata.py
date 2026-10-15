from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.catalog import ALLOWED_ACTIONS
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.gateway_metadata import collect
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.transport import CollectionError


def run(mutate=None):
    g = Graph()

    def call(service, action, region=None, **params):
        assert (service, action) in ALLOWED_ACTIONS
        assert region == "eu-frankfurt" and params == dict(Offset=0, Limit=100)
        if action == "DescribeHaVips":
            key, row = (
                "HaVipSet",
                dict(
                    HaVipId="havip-one",
                    HaVipName="HA",
                    Vip="10.0.0.8",
                    VpcId="vpc-one",
                    SubnetId="subnet-one",
                    NetworkInterfaceId="eni-one",
                    AddressIp="203.0.113.8",
                    Business="cvm",
                ),
            )
        elif action == "DescribeVpnGateways":
            key, row = (
                "VpnGatewaySet",
                dict(
                    VpnGatewayId="vpngw-one",
                    VpnGatewayName="VPN",
                    VpcId="vpc-one",
                    PublicIpAddress="203.0.113.10",
                    IsPrivate=False,
                    State="AVAILABLE",
                    BgpAsn=64512,
                ),
            )
        else:
            assert action == "DescribeDirectConnectGateways"
            key, row = (
                "DirectConnectGatewaySet",
                dict(
                    DirectConnectGatewayId="dcg-one",
                    DirectConnectGatewayName="DC",
                    VpcId="vpc-one",
                    CcnId="ccn-one",
                    EnableBGP=True,
                ),
            )
        row["PreShareKey"] = "fixture-not-retained"
        response = {key: [row], "TotalCount": 1, "RequestId": action}
        return mutate(action, response) if mutate else response

    collect(
        CollectorRunner(g, SimpleNamespace(call=call), "100", ["eu-frankfurt"], lambda _: None),
        "eu-frankfurt",
    )
    return g


def test_gateway_inventory_resolves_native_identities_and_uses_official_icons():
    g = run()
    assert {n["kind"] for n in g.nodes.values() if n["status"] == "enriched"} == {
        "vpc.havip",
        "vpc.vpngateway",
        "vpc.directconnectgateway",
    }
    assert len([e for e in g.edges.values() if e["relationship"] == "IN_VPC"]) == 3
    assert icon_for("vpc.vpngateway") == "en-vpn-connections.svg"
    assert icon_for("vpc.directconnectgateway") == "en-direct-connect.svg"
    assert "fixture-not-retained" not in g.dump()
    assert all(r["status"] == "complete" for r in g.coverage)


@pytest.mark.parametrize("change", ["denied", "missing-total", "wrong-id"])
def test_independent_gateway_failures_preserve_other_inventory(change):
    def mutate(action, response):
        if action == "DescribeVpnGateways":
            if change == "denied":
                raise CollectionError("UnauthorizedOperation")
            if change == "missing-total":
                response.pop("TotalCount")
            if change == "wrong-id":
                response["VpnGatewaySet"][0]["VpnGatewayId"] = "dcg-mislabeled"
        return response

    g = run(mutate)
    assert g.coverage[1]["status"] in {"denied", "error"}
    assert not any(n["kind"] == "vpc.vpngateway" for n in g.nodes.values())
    assert {n["kind"] for n in g.nodes.values()} >= {"vpc.havip", "vpc.directconnectgateway"}
