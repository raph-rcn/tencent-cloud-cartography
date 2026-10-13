import pytest

from tencent_cloud_cartography.catalog import COLLECTORS
from tencent_cloud_cartography.collect import CollectorRunner, collect, status_for
from tencent_cloud_cartography.dns import add_record, collect_records, link_dns, normal_name
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph, stable_id
from tencent_cloud_cartography.topology import topology
from tencent_cloud_cartography.transport import CollectionError, failure_code


def native(graph, kind, raw, account="100", region="global"):
    spec = next(s for s in COLLECTORS if s.kind == kind)
    return graph.native(account, region, spec, raw, f"{spec.service}.{spec.action}")


def zone(graph, rid="1", name="example.test", private=False, **fields):
    if private:
        return native(
            graph, "privatedns.zone", dict(ZoneId=rid, Domain=name, OwnerUin=100, **fields)
        )
    return native(graph, "dnspod.domain", dict(DomainId=int(rid), Name=name, **fields))


def record(graph, zid, rid=1, name="@", type="A", value="192.0.2.1", **extra):
    parent = graph.nodes[zid]
    private = parent["kind"] == "privatedns.zone"
    raw = dict(RecordId=rid, Status="ENABLE", TTL=60, Weight=0)
    raw.update(extra)
    if private:
        raw.update(ZoneId=parent["resource_id"], SubDomain=name, RecordType=type, RecordValue=value)
    else:
        raw.update(Name=name, Type=type, Value=value)
    return add_record(graph, zid, raw, "fixture")


def test_all_record_types_ttl_weight_status_values_and_scoped_identity():
    graph = Graph()
    a, b = zone(graph), zone(graph, "2", "other.test")
    for rid, kind, value in [
        (1, "A", "192.0.2.1"),
        (2, "AAAA", "2001:db8::1"),
        (3, "CNAME", "TARGET.Example.Test."),
        (4, "NS", "ns.example.test."),
        (5, "MX", "mail.example.test."),
        (6, "TXT", '"configuration value"'),
        (7, "SRV", "10 20 443 server.example.test."),
        (8, "CAA", '0 issue "ca.example.test"'),
    ]:
        record(graph, a, rid, "www", kind, value)
    other = record(graph, b, 1)
    records = [n for n in graph.nodes.values() if n["kind"] == "dnspod.record"]
    assert len(records) == 9 and len({n["id"] for n in records}) == 9
    assert graph.nodes[other]["resource_id"] == "2/1"
    assert all(n["properties"]["TTL"] == 60 and n["properties"]["Weight"] == 0 for n in records)
    assert any(
        n["properties"].get("dns_value") == "target.example.test" for n in graph.nodes.values()
    )
    assert all(icon_for(n["kind"]) != "unmapped.svg" for n in graph.nodes.values())
    assert topology(graph.snapshot())["stats"]["resources"] == 2


def test_private_bindings_use_region_owner_and_ignore_deleted_vpcs():
    graph = Graph()
    zid = zone(
        graph,
        "zone-a",
        private=True,
        VpcSet=[dict(UniqVpcId="vpc-local", Region="eu-frankfurt")],
        AccountVpcSet=[
            dict(UniqVpcId="vpc-remote", Region="ap-guangzhou", Uin="200"),
            dict(UniqVpcId="vpc-unknown", Region="eu-frankfurt", AppId=999),
        ],
        DeletedVpcSet=[dict(UniqVpcId="vpc-deleted", Region="eu-frankfurt")],
    )
    targets = {e["target"] for e in graph.edges.values() if e["source"] == zid}
    assert targets == {
        stable_id("100", "eu-frankfurt", "vpc.vpc", "vpc-local"),
        stable_id("200", "ap-guangzhou", "vpc.vpc", "vpc-remote"),
    }
    assert not any(n["kind"] == "vpc.vpc" and n["region"] == "global" for n in graph.nodes.values())
    assert not any(e["relationship"] == "IN_VPC" for e in graph.edges.values())
    assert graph.nodes[zid]["properties"]["unresolved_vpc_bindings"] == 1


def test_private_address_matching_requires_bound_vpc_even_with_duplicate_ips():
    graph = Graph()
    zone_a = zone(
        graph, "zone-a", private=True, VpcSet=[dict(UniqVpcId="vpc-a", Region="eu-frankfurt")]
    )
    zone_b = zone(
        graph, "zone-b", private=True, VpcSet=[dict(UniqVpcId="vpc-b", Region="eu-frankfurt")]
    )
    pub = zone(graph)
    for zid in (zone_a, zone_b, pub):
        record(graph, zid, value="10.0.0.7")
    for owner, region, vpc in [
        ("100", "eu-frankfurt", "vpc-a"),
        ("100", "eu-frankfurt", "vpc-b"),
        ("200", "eu-frankfurt", "vpc-a"),
        ("100", "ap-guangzhou", "vpc-a"),
    ]:
        native(
            graph,
            "cvm.instance",
            dict(
                InstanceId="ins-same",
                PrivateIpAddresses=["10.0.0.7"],
                VirtualPrivateCloud=dict(VpcId=vpc),
            ),
            owner,
            region,
        )
    link_dns(graph)
    matches = [e for e in graph.edges.values() if e["relationship"] == "MATCHES_RESOURCE_ADDRESS"]
    assert len(matches) == 2
    assert {graph.nodes[e["source"]]["properties"]["dns_scope"] for e in matches} == {
        zone_a,
        zone_b,
    }
    assert all(
        graph.nodes[e["target"]]["account"] == "100"
        and graph.nodes[e["target"]]["region"] == "eu-frankfurt"
        for e in matches
    )


def test_cnames_keep_public_private_and_private_zone_views_separate():
    graph = Graph()
    zones = [zone(graph), zone(graph, "zone-a", private=True), zone(graph, "zone-b", private=True)]
    for zid in zones:
        record(graph, zid, 1, "www", "CNAME", "app.example.test.")
        record(graph, zid, 2, "app", "A", "192.0.2.1")
    link_dns(graph)
    links = [e for e in graph.edges.values() if e["relationship"] == "HAS_CONFIGURED_RECORD"]
    assert len(links) == 3
    for edge in links:
        assert (
            graph.nodes[edge["source"]]["properties"]["dns_scope"]
            == graph.nodes[edge["target"]]["properties"]["dns_scope"]
        )


def test_subzones_require_name_suffix_nameserver_and_enabled_record():
    graph = Graph()
    root = zone(graph)
    child = zone(graph, "2", "sub.example.test", EffectiveDNS=["NS2.EXAMPLE.TEST."])
    zone(graph, "3", "unrelated.test", EffectiveDNS=["ns2.example.test"])
    zone(graph, "4", "other.example.test", EffectiveDNS=["ns4.example.test"])
    zone(graph, "5", "disabled.example.test", EffectiveDNS=["ns2.example.test"])
    record(graph, root, 1, "sub", "NS", "ns2.example.test.")
    record(graph, root, 2, "other", "NS", "ns2.example.test.")
    record(graph, root, 3, "disabled", "NS", "ns2.example.test.", Status="DISABLE")
    link_dns(graph)
    assert [
        (e["source"], e["target"])
        for e in graph.edges.values()
        if e["relationship"] == "CONFIGURED_SUBZONE"
    ] == [(root, child)]


def test_failed_zone_enrichment_does_not_abort_final_dns_linking():
    graph = Graph()
    root = zone(graph)
    record(graph, root, 1, "sub", "NS", "ns.example.test.")
    with pytest.raises(CollectionError):
        zone(graph, "2", "bad..example.test")
    link_dns(graph)
    assert not any(e["relationship"] == "CONFIGURED_SUBZONE" for e in graph.edges.values())


@pytest.mark.parametrize(
    "mutate,error",
    [
        (lambda r: r.update(ZoneId="zone-wrong"), "DnsZoneMismatch"),
        (lambda r: r.update(SubDomain="outside.test."), "DnsZoneMismatch"),
        (lambda r: r.update(RecordType="AAAA"), "InvalidDnsAddress"),
        (lambda r: r.update(RecordId=""), "InvalidDnsRecord"),
    ],
)
def test_record_mismatch_creates_no_record_or_target(mutate, error):
    graph = Graph()
    zid = zone(graph, "zone-a", private=True)
    raw = dict(
        ZoneId="zone-a", RecordId="1", SubDomain="@", RecordType="A", RecordValue="192.0.2.1"
    )
    mutate(raw)
    with pytest.raises(CollectionError) as exc:
        add_record(graph, zid, raw, "fixture")
    assert exc.value.code == error and len(graph.nodes) == 1


def test_paginated_records_keep_partial_coverage_and_reject_duplicate_ids():
    graph = Graph()
    zid = zone(graph)
    calls = []

    class Transport:
        def call(self, service, action, region=None, **params):
            calls.append(params)
            assert (
                params["Domain"] == "example.test"
                and params["DomainId"] == 1
                and params["ErrorOnEmpty"] == "no"
            )
            items = (
                [dict(RecordId=i, Name=f"n{i}", Type="A", Value="192.0.2.1") for i in range(1, 101)]
                if params["Offset"] == 0
                else [dict(RecordId=100, Name="duplicate", Type="A", Value="192.0.2.2")]
            )
            return dict(
                RecordList=items,
                RecordCountInfo=dict(TotalCount=101),
                RequestId=str(params["Offset"]),
            )

    collect_records(
        CollectorRunner(graph, Transport(), "100", [], lambda _: None),
        zid,
        dict(Name="example.test"),
    )
    assert calls[1]["Offset"] == 100
    assert (
        graph.coverage[-1]["error"] == "DuplicateDnsRecord" and graph.coverage[-1]["count"] == 100
    )
    assert graph.coverage[-1]["request_ids"] == ["0", "100"]


def test_owned_public_domain_scope_uses_filtered_total_and_retains_denied_records():
    calls = []

    class Transport:
        def call(self, service, action, region=None, **params):
            calls.append((action, params))
            if service == "sts":
                return dict(AccountId="100", PrincipalId="reader")
            if service == "cloudrc":
                return dict(Resources=[])
            if action == "DescribeDomainList":
                assert params["Type"] == "MINE"
                return dict(
                    DomainList=[dict(DomainId=1, Name="example.test")],
                    DomainCountInfo=dict(DomainTotal=1, AllTotal=99),
                )
            if action == "DescribeRecordList":
                raise CollectionError("UnauthorizedOperation")
            pytest.fail(action)

    data = collect(
        ["test"],
        ["eu-frankfurt"],
        services={"dnspod"},
        progress=lambda _: None,
        transport_factory=lambda _: Transport(),
    )
    assert len(data["nodes"]) == 1
    scope = next(c for c in data["coverage"] if c["action"] == "DescribeRecordList")
    assert scope["status"] == "denied"
    assert len([c for c in calls if c[0] == "DescribeDomainList"]) == 1


def test_private_zone_foreign_owner_is_rejected_before_graph_insertion():
    graph = Graph()

    class Transport:
        def call(self, *args, **kwargs):
            return dict(
                PrivateZoneSet=[dict(ZoneId="zone-foreign", Domain="example.test", OwnerUin=200)],
                TotalCount=1,
            )

    runner = CollectorRunner(graph, Transport(), "100", [], lambda _: None)
    runner.native(next(s for s in COLLECTORS if s.kind == "privatedns.zone"), "global")
    assert not graph.nodes and graph.coverage[-1]["error"] == "AccountMismatch"


def test_idn_and_trailing_dot_normalization():
    assert normal_name("BÜCHER.Example.") == "xn--bcher-kva.example"
    with pytest.raises(CollectionError):
        normal_name("example..")


def test_dns_permission_error_retains_code_without_raw_payload():
    code = failure_code("OperationDenied.NoPermissionToOperateDomain raw-private-context")
    assert code == "OperationDenied.NoPermissionToOperateDomain"
    assert status_for(code) == "denied"


def test_null_mx_and_srv_targets_are_retained_without_destination():
    graph = Graph()
    zid = zone(graph)
    record(graph, zid, 1, "@", "MX", ".", MX=0)
    record(graph, zid, 2, "_service._tcp", "SRV", "0 0 0 .")
    assert len(graph.nodes) == 3
    assert all(e["relationship"] == "HAS_RECORD" for e in graph.edges.values())


def test_private_enabled_flag_overrides_status_for_state_without_dropping_configuration():
    graph = Graph()
    zid = zone(graph, "zone-disabled", private=True)
    rid = record(graph, zid, Status="ENABLED", Enabled=0)
    assert graph.nodes[rid]["properties"]["enabled"] is False
    assert graph.nodes[rid]["properties"]["state"] == "disabled"
    assert any(
        e["source"] == rid and e["relationship"] == "CONFIGURED_DNS_TARGET"
        for e in graph.edges.values()
    )


def test_public_address_matches_only_same_account_global_ip():
    graph = Graph()
    zid = zone(graph)
    record(graph, zid, value="1.1.1.1")
    local = native(
        graph,
        "cvm.instance",
        dict(InstanceId="ins-local", PublicIpAddresses=["1.1.1.1"]),
        region="eu-frankfurt",
    )
    native(
        graph,
        "cvm.instance",
        dict(InstanceId="ins-other", PublicIpAddresses=["1.1.1.1"]),
        account="200",
        region="eu-frankfurt",
    )
    link_dns(graph)
    matches = [e for e in graph.edges.values() if e["relationship"] == "MATCHES_RESOURCE_ADDRESS"]
    assert len(matches) == 1 and matches[0]["target"] == local
