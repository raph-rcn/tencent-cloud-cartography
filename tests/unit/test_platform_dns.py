import pytest
from test_platform_metadata import RESPONSES, node, runner

from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.platform_dns import collect_shared, link
from tencent_cloud_cartography.platform_metadata import READS, checked_read


@pytest.mark.parametrize(
    "owner,expected", [("200", True), ("", False), ("100", False), (200, False)]
)
def test_shared_domain_owner_requires_explicit_native_uin(owner, expected):
    g = Graph()
    calls = []

    def call(service, action, region=None, **params):
        calls.append((action, params))
        if action == "DescribeDomainList":
            assert params["Type"] == "SHARE"
            return dict(
                DomainList=[dict(DomainId=1, Name="shared.test", Owner="owner@example.test")],
                DomainCountInfo=dict(DomainTotal=1, AllTotal=99),
            )
        if action == "DescribeDomain":
            assert params["DomainId"] == 1
            return dict(
                DomainInfo=dict(
                    DomainId=1,
                    Domain="shared.test",
                    Uin=owner,
                    Owner="owner@example.test",
                    DnspodNsList=[],
                )
            )
        if action == "DescribeRecordList":
            return dict(
                RecordList=[
                    dict(
                        RecordId=1,
                        Name="www",
                        Type="CNAME",
                        Value="db.vendor.test",
                        Status="ENABLE",
                    )
                ],
                RecordCountInfo=dict(TotalCount=1),
            )
        pytest.fail(action)

    collect_shared(runner(g, call))
    views = [n for n in g.nodes.values() if n["kind"] == "dnspod.sharedview"]
    assert len(views) == 1 and views[0]["account"] == "100"
    assert views[0]["properties"]["owner_identity_verified"] is expected
    domains = [n for n in g.nodes.values() if n["kind"] == "dnspod.domain"]
    if expected:
        assert len(domains) == 1 and domains[0]["account"] == "200"
        assert any(n["kind"] == "dnspod.record" and n["account"] == "200" for n in g.nodes.values())
        assert any(e["relationship"] == "OBSERVES_SHARED_DOMAIN" for e in g.edges.values())
    else:
        assert not domains and not any(a == "DescribeRecordList" for a, _ in calls)
        assert any(r.get("error") == "UnresolvedSharedDnsOwner" for r in g.coverage)


def test_forwarding_and_inbound_endpoint_region_ambiguity_are_visible():
    g = Graph()
    v = node(g, "vpc.vpc", "vpc-one")
    s = node(g, "vpc.subnet", "subnet-one")
    g.edge(s["id"], v["id"], "IN_VPC", "fixture")
    zone = node(g, "privatedns.zone", "zone-1", region="global")
    for action in ("DescribeForwardRuleList", "DescribeInboundEndpointList"):
        read = next(r for r in READS if r.action == action)
        checked_read(runner(g, lambda *a, **k: RESPONSES[action]), read, "global", None, {})
    link(g)
    assert any(
        e["target"] == zone["id"] and e["relationship"] == "FORWARDS_PRIVATE_ZONE"
        for e in g.edges.values()
    )
    endpoint = next(n for n in g.nodes.values() if n["kind"] == "privatedns.inboundendpoint")
    assert endpoint["properties"]["vpc_region_resolved"]
    outbound = next(n for n in g.nodes.values() if n["kind"] == "privatedns.outboundendpoint")
    assert (
        outbound["status"] == "reference"
        and not outbound["properties"]["endpoint_detail_available"]
    )
    node(g, "vpc.vpc", "vpc-one", region="ap-guangzhou")
    link(g)
    assert not endpoint["properties"]["vpc_region_resolved"]
    assert not any(e["source"] == endpoint["id"] for e in g.edges.values())
    before = g.dump()
    link(g)
    assert g.dump() == before


def test_endpoint_alias_name_matching_requires_network_scope_for_private_names():
    g = Graph()
    resource = node(g, "cdb.instance", "cdb-one", WanDomain="db.vendor.test")
    public = node(
        g,
        "dnspod.name",
        "db.vendor.test",
        region="global",
        dns_value="db.vendor.test",
        dns_scope="public",
    )
    private = node(
        g,
        "privatedns.name",
        "zone/db.vendor.test",
        region="global",
        dns_value="db.vendor.test",
        dns_scope="zone-node",
    )
    link(g)
    assert any(
        e["source"] == public["id"] and e["target"] == resource["id"] for e in g.edges.values()
    )
    assert not any(e["source"] == private["id"] for e in g.edges.values())
    v = node(g, "vpc.vpc", "vpc-one")
    g.edge("zone-node", v["id"], "ASSOCIATED_WITH_VPC", "fixture")
    g.edge(resource["id"], v["id"], "IN_VPC", "fixture")
    link(g)
    assert any(
        e["source"] == private["id"] and e["target"] == resource["id"] for e in g.edges.values()
    )
    node(g, "cdb.instance", "cdb-two", WanDomain="db.vendor.test")
    link(g)
    assert not any(e["source"] == public["id"] for e in g.edges.values())


def test_shared_response_identity_mismatch_retains_query_view_but_not_owned_domain():
    g = Graph()

    def call(s, a, *args, **params):
        if a == "DescribeDomainList":
            return dict(
                DomainList=[dict(DomainId=1, Name="shared.test")],
                DomainCountInfo=dict(DomainTotal=1),
            )
        return dict(DomainInfo=dict(DomainId=2, Domain="foreign.test", Uin="200"))

    collect_shared(runner(g, call))
    assert any(r.get("error") == "SharedDnsDomainScopeMismatch" for r in g.coverage)
    assert len(g.nodes) == 1
