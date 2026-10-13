from dataclasses import replace
from types import SimpleNamespace

import pytest

from tencent_cloud_cartography import network_acls as acl
from tencent_cloud_cartography.catalog import COLLECTORS
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.transport import CollectionError

REGION = "eu-frankfurt"
SPEC = next(s for s in COLLECTORS if s.kind == "vpc.networkacl")


def triple(**values):
    return dict(
        dict(
            NetworkAclIpv4EntryId="acli43-one",
            Protocol="TCP",
            Port="443",
            CidrBlock="192.0.2.0/24",
            Action="ACCEPT",
            Priority=1,
            Description="Application ingress",
            ModifyTime="2026-10-13",
        ),
        **values,
    )


def quintuple(**values):
    return dict(
        dict(
            NetworkAclQuintupleEntryId="acli45-one",
            Protocol="TCP",
            SourcePort="1024-65535",
            DestinationPort="443",
            SourceCidr="192.0.2.0/24",
            DestinationCidr="10.0.0.0/24",
            Action="ACCEPT",
            Priority=0,
            NetworkAclDirection="INGRESS",
            CreateTime="2026-10-13",
        ),
        **values,
    )


def parent(**values):
    return dict(
        dict(
            NetworkAclId="acl-one",
            VpcId="vpc-one",
            NetworkAclName="Application ACL",
            NetworkAclType="TRIPLE",
            CreatedTime="2026-10-13",
            SubnetSet=[dict(SubnetId="subnet-one", VpcId="vpc-one", NetworkAclId="acl-one")],
            IngressEntries=[triple()],
            EgressEntries=[],
        ),
        **values,
    )


def run(parents=None, rules=None, mutate=None, spec=SPEC):
    parents = [parent()] if parents is None else parents
    rules = [quintuple()] if rules is None else rules
    graph, calls = Graph(), []

    def call(service, action, **params):
        assert service == "vpc" and params["region"] == REGION
        calls.append((action, params))
        if action == "DescribeNetworkAcls":
            rows, key = parents, "NetworkAclSet"
        else:
            assert action == "DescribeNetworkAclQuintupleEntries" and "Filters" not in params
            rows, key = rules, "NetworkAclQuintupleSet"
        response = {
            key: rows[params["Offset"] : params["Offset"] + params["Limit"]],
            "TotalCount": len(rows),
            "RequestId": str(len(calls)),
        }
        return mutate(action, params, response) if mutate else response

    runner = CollectorRunner(graph, SimpleNamespace(call=call), "100", [REGION], lambda _: None)
    acl.collect(runner, spec, REGION)
    return graph, calls


def resources(g, kind="vpc.networkaclrule"):
    return [n for n in g.nodes.values() if n["kind"] == kind]


def test_triple_rules_preserve_priority_address_family_and_subnet_vpc():
    g, calls = run(
        [
            parent(
                EgressEntries=[
                    triple(
                        NetworkAclIpv4EntryId="",
                        NetworkAclIpv6EntryId="acli63-one",
                        CidrBlock="",
                        Ipv6CidrBlock="2001:db8::/64",
                        Action="DROP",
                    )
                ]
            )
        ]
    )
    assert len(calls) == 1 and g.coverage[0]["status"] == "complete"
    rules = resources(g)
    assert len(rules) == 2
    assert {n["properties"]["direction"] for n in rules} == {"INGRESS", "EGRESS"}
    assert {n["properties"]["ip_version"] for n in rules} == {4, 6}
    assert all(
        n["properties"]["Priority"] == 1 and not n["properties"]["reachability_verified"]
        for n in rules
    )
    assert all(icon_for(n["kind"]) == "en-virtual-private-cloud.svg" for n in rules)
    assert {e["relationship"] for e in g.edges.values()} == {
        "HAS_RULE",
        "IN_VPC",
        "USES_NETWORK_ACL",
    }
    assert "IsDefault" not in resources(g, "vpc.networkacl")[0]["properties"]


def test_legacy_position_fallback_is_explicit_and_does_not_invent_priority():
    raw = parent(IngressEntries=[triple(NetworkAclIpv4EntryId=None, Priority=None)])
    del raw["NetworkAclType"]
    g, _ = run([raw])
    props = resources(g)[0]["properties"]
    assert props["response_index"] == 0 and props["identity_source"] == "response_position"
    assert props["order_source"] == "response_position" and "Priority" not in props
    assert resources(g, "vpc.networkacl")[0]["properties"]["acl_type_resolution"] == "legacy_triple"


def test_quintuple_pagination_both_directions_and_ipv6(monkeypatch):
    monkeypatch.setattr(acl, "QUINTUPLE", replace(acl.QUINTUPLE, page_size=1))
    g, calls = run(
        [parent(NetworkAclType="QUINTUPLE", IngressEntries=None, EgressEntries=None)],
        [
            quintuple(),
            quintuple(
                NetworkAclQuintupleEntryId="acli65-two",
                NetworkAclDirection="EGRESS",
                SourceCidr="",
                DestinationCidr="",
                SourceIPv6Cidr="2001:db8::1",
                DestinationIPv6Cidr="::/0",
                Action="DROP",
            ),
        ],
    )
    assert [p["Offset"] for action, p in calls if action == acl.QUINTUPLE.action] == [0, 1]
    assert len(resources(g)) == 2 and g.coverage[-1]["count"] == 2
    props = next(n["properties"] for n in resources(g) if n["properties"]["ip_version"] == 6)
    assert props["SourceIPv6Cidr"] == "2001:db8::1/128" and props["SourcePort"] == "1024-65535"


@pytest.mark.parametrize(
    "field,value",
    [
        ("NetworkAclType", "FUTURE"),
        ("SubnetSet", None),
        ("SubnetSet", [dict(SubnetId="subnet-one", VpcId="vpc-other")]),
        ("SubnetSet", [dict(SubnetId="subnet-one", NetworkAclId="acl-other")]),
        ("SubnetSet", [dict(SubnetId="subnet-one"), dict(SubnetId="subnet-one")]),
        ("EgressEntries", None),
        ("IngressEntries", {}),
        ("CreatedTime", 1),
    ],
)
def test_invalid_parent_page_does_not_add_partial_nodes(field, value):
    g, _ = run([parent(NetworkAclId="acl-good", SubnetSet=[]), parent(**{field: value})])
    assert not g.nodes and g.coverage[0]["status"] in {"error", "unsupported"}


@pytest.mark.parametrize(
    "values",
    [
        dict(Priority=True),
        dict(Action="ALLOW"),
        dict(Protocol=None),
        dict(Port="65536"),
        dict(Port="443-80"),
        dict(Port=443),
        dict(CidrBlock="10.0.0.1/24"),
        dict(Ipv6CidrBlock="::/0"),
        dict(NetworkAclIpv4EntryId="acli63-wrong"),
        dict(NetworkAclIpv6EntryId="acli63-wrong"),
        dict(NetworkAclId="acl-other"),
    ],
)
def test_invalid_triple_rules_abort_parent_page(values):
    g, _ = run([parent(IngressEntries=[triple(), triple(**values)])])
    assert not g.nodes and g.coverage[0]["status"] == "error"


@pytest.mark.parametrize(
    "values",
    [
        dict(NetworkAclDirection="unknown"),
        dict(Priority=None),
        dict(NetworkAclQuintupleEntryId="wrong"),
        dict(NetworkAclId="acl-other"),
        dict(SourceCidr="", SourceIPv6Cidr="::/0"),
        dict(DestinationPort=""),
    ],
)
def test_invalid_quintuple_page_preserves_parent_only(values):
    g, _ = run([parent(NetworkAclType="QUINTUPLE")], [quintuple(), quintuple(**values)])
    assert len(resources(g, "vpc.networkacl")) == 1 and not resources(g)
    assert g.coverage[-1]["status"] == "error"


def test_duplicate_rule_identity_and_priority_are_rejected():
    for entries in ([triple(), triple()], [triple(), triple(NetworkAclIpv4EntryId="acli43-other")]):
        g, _ = run([parent(IngressEntries=entries)])
        assert not g.nodes and g.coverage[0]["status"] == "error"


def test_denied_child_scope_does_not_stop_other_parents():
    def mutate(action, params, response):
        if action == acl.QUINTUPLE.action and params["NetworkAclId"] == "acl-one":
            raise CollectionError("UnauthorizedOperation")
        return response

    g, _ = run(
        [
            parent(NetworkAclType="QUINTUPLE"),
            parent(NetworkAclType="QUINTUPLE", NetworkAclId="acl-two", SubnetSet=[]),
        ],
        mutate=mutate,
    )
    assert [r["status"] for r in g.coverage] == ["complete", "denied", "complete"]
    assert len(resources(g)) == 1 and resources(g)[0]["resource_id"].startswith("acl-two/")


def test_missing_totals_and_duplicate_parent_pages_are_visible():
    def mutate(action, params, response):
        response.pop("TotalCount")
        return response

    g, _ = run(mutate=mutate)
    assert not g.nodes and g.coverage[0]["status"] == "error"
    g, _ = run([parent(), parent()], spec=replace(SPEC, page_size=1))
    assert len(resources(g, "vpc.networkacl")) == 1 and g.coverage[0]["status"] == "error"


def test_duplicate_child_on_later_page_is_partial(monkeypatch):
    monkeypatch.setattr(acl, "QUINTUPLE", replace(acl.QUINTUPLE, page_size=1))
    g, _ = run([parent(NetworkAclType="QUINTUPLE")], [quintuple(), quintuple()])
    assert len(resources(g)) == 1 and g.coverage[-1]["status"] == "error"
