from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.catalog import COLLECTORS
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.security_groups import TEMPLATES, collect
from tencent_cloud_cartography.transport import CollectionError

REGION = "eu-frankfurt"
SPECS = [s for s in COLLECTORS if s.kind in TEMPLATES or s.kind == "vpc.securitygroup"]


def policy(**values):
    return dict(
        dict(
            PolicyIndex=0,
            Priority=0,
            Protocol="TCP",
            Port="443",
            CidrBlock="0.0.0.0/0",
            Action="ACCEPT",
            PolicyDescription="HTTPS",
        ),
        **values,
    )


def fixtures():
    return {
        "DescribeAddressTemplates": [
            dict(
                AddressTemplateId="ipm-one",
                AddressTemplateName="Clients",
                AddressSet=["10.0.0.0/24", "2001:db8::1", "192.0.2.1-192.0.2.9"],
            )
        ],
        "DescribeAddressTemplateGroups": [
            dict(
                AddressTemplateGroupId="ipmg-one",
                AddressTemplateGroupName="Trusted clients",
                AddressTemplateIdSet=["ipm-one"],
            )
        ],
        "DescribeServiceTemplates": [
            dict(ServiceTemplateId="ppm-one", ServiceTemplateName="HTTPS", ServiceSet=["tcp:443"])
        ],
        "DescribeServiceTemplateGroups": [
            dict(
                ServiceTemplateGroupId="ppmg-one",
                ServiceTemplateGroupName="Web ports",
                ServiceTemplateIdSet=["ppm-one"],
            )
        ],
        "DescribeSecurityGroups": [
            dict(
                SecurityGroupId="sg-one",
                SecurityGroupName="Web",
                SecurityGroupDesc="Frontend",
                ProjectId="0",
                IsDefault=False,
            )
        ],
    }


def run(rows=None, policies=None, mutate=None):
    rows = fixtures() if rows is None else rows
    policies = (
        {"sg-one": dict(Version="7", Ingress=[policy()], Egress=[])}
        if policies is None
        else policies
    )
    graph, calls = Graph(), []
    specs = {s.action: s for s in SPECS}

    def call(service, action, **params):
        assert service == "vpc" and params["region"] == REGION
        calls.append((action, params))
        if action == "DescribeSecurityGroupPolicies":
            response = dict(
                SecurityGroupPolicySet=policies[params["SecurityGroupId"]],
                RequestId=str(len(calls)),
            )
        else:
            values = rows.get(action, [])
            response = {
                specs[action].result: values[params["Offset"] : params["Offset"] + params["Limit"]],
                "TotalCount": len(values),
                "RequestId": str(len(calls)),
            }
        return mutate(action, params, response) if mutate else response

    runner = CollectorRunner(graph, SimpleNamespace(call=call), "100", [REGION], lambda _: None)
    for spec in SPECS:
        collect(runner, spec, REGION)
    return graph, calls


def resources(g, kind):
    return [n for n in g.nodes.values() if n["kind"] == kind]


def test_rules_link_direct_addresses_groups_and_nested_templates():
    policies = {
        "sg-one": dict(
            Version="7",
            Ingress=[
                policy(),
                policy(PolicyIndex=1, CidrBlock=None, SecurityGroupId="sg-peer"),
                policy(
                    PolicyIndex=2,
                    CidrBlock=None,
                    AddressTemplate={"AddressGroupId": "ipmg-one"},
                    Protocol=None,
                    Port=None,
                    ServiceTemplate={"ServiceGroupId": "ppmg-one"},
                ),
            ],
            Egress=[
                policy(
                    Action="DROP", CidrBlock=None, Ipv6CidrBlock="::/0", Protocol="ALL", Port="all"
                )
            ],
        )
    }
    g, _ = run(policies=policies)
    rules = resources(g, "vpc.securitygrouprule")
    assert len(rules) == 4 and all(n["properties"]["policy_version"] == "7" for n in rules)
    assert all(not n["properties"]["reachability_verified"] for n in rules)
    assert {e["relationship"] for e in g.edges.values()} == {
        "HAS_RULE",
        "HAS_MEMBER",
        "MATCHES_ADDRESS",
        "REFERENCES_SECURITY_GROUP",
        "USES_TEMPLATE",
    }
    assert resources(g, "vpc.securitygroup")[0]["properties"]["SecurityGroupDesc"] == "Frontend"
    assert len(resources(g, "vpc.ruleaddress")) == 5
    assert resources(g, "vpc.serviceselector")[0]["properties"]["service_selector"] == "tcp:443"
    assert all(icon_for(n["kind"]) != "unmapped.svg" for n in g.nodes.values())
    peer = next(n for n in g.nodes.values() if n["resource_id"] == "sg-peer")
    assert peer["account"] == "100" and peer["region"] == REGION and peer["status"] == "reference"


@pytest.mark.parametrize(
    "field,value",
    [
        ("PolicyIndex", None),
        ("PolicyIndex", -1),
        ("Priority", True),
        ("Action", "ALLOW"),
        ("CidrBlock", "not-a-network"),
        ("CidrBlock", "::/0"),
        ("ServiceTemplate", {"ServiceId": "ppm-one"}),
        ("AddressTemplate", {"AddressId": "ipm-one"}),
        ("SecurityGroupId", "sg-peer"),
    ],
)
def test_invalid_policy_is_atomic_across_directions(field, value):
    g, _ = run(
        policies={
            "sg-one": dict(Version="8", Ingress=[policy()], Egress=[policy(**{field: value})])
        }
    )
    assert not resources(g, "vpc.securitygrouprule")
    assert g.coverage[-1]["status"] == "error"


@pytest.mark.parametrize(
    "bad", ["version", "missing-egress", "duplicate-index", "bad-array", "both-template-ids"]
)
def test_invalid_policy_set_preserves_group_but_no_rules(bad):
    raw = dict(Version="7", Ingress=[policy()], Egress=[])
    if bad == "version":
        raw["Version"] = 7
    if bad == "missing-egress":
        raw.pop("Egress")
    if bad == "duplicate-index":
        raw["Ingress"] *= 2
    if bad == "bad-array":
        raw["Ingress"] = {}
    if bad == "both-template-ids":
        raw["Ingress"] = [
            policy(
                CidrBlock=None, AddressTemplate=dict(AddressId="ipm-one", AddressGroupId="ipmg-one")
            )
        ]
    g, _ = run(policies={"sg-one": raw})
    assert resources(g, "vpc.securitygroup") and not resources(g, "vpc.securitygrouprule")
    assert g.coverage[-1]["status"] == "error"


@pytest.mark.parametrize(
    "value", ["192.0.2.9-192.0.2.1", "192.0.2.1-::1", "fe80::1%en0", "example.com"]
)
def test_invalid_template_address_not_promoted(value):
    rows = fixtures()
    rows["DescribeAddressTemplates"][0]["AddressSet"] = [value]
    g, _ = run(rows=rows)
    template = resources(g, "vpc.addresstemplate")[0]
    assert template["status"] == "reference"
    assert g.coverage[0]["status"] == "error"


def test_template_group_members_require_correct_namespace():
    rows = fixtures()
    rows["DescribeServiceTemplateGroups"][0]["ServiceTemplateIdSet"] = ["ipm-one"]
    g, _ = run(rows=rows)
    assert not resources(g, "vpc.servicetemplategroup")
    assert any(c["status"] == "error" for c in g.coverage)


def test_denied_template_keeps_rule_reference_and_other_data():
    def mutate(action, params, response):
        if action == "DescribeAddressTemplates":
            raise CollectionError("UnauthorizedOperation")
        return response

    g, _ = run(mutate=mutate)
    assert resources(g, "vpc.securitygrouprule")
    assert resources(g, "vpc.addresstemplate")[0]["status"] == "reference"
    assert g.coverage[0]["status"] == "denied"


def test_pagination_and_required_totals():
    rows = {
        "DescribeAddressTemplates": [
            dict(AddressTemplateId=f"ipm-{i}", AddressSet=[]) for i in range(101)
        ]
    }
    g, calls = run(rows=rows, policies={})
    assert len(resources(g, "vpc.addresstemplate")) == 101
    assert [p["Offset"] for a, p in calls if a == "DescribeAddressTemplates"] == [0, 100]

    def mutate(action, params, response):
        response.pop("TotalCount", None)
        return response

    g, _ = run(rows=rows, policies={}, mutate=mutate)
    assert not g.nodes and all(c["status"] == "error" for c in g.coverage)


def test_duplicate_members_and_resources_rejected():
    rows = fixtures()
    rows["DescribeAddressTemplates"][0]["AddressSet"] = ["::1", "0:0:0:0:0:0:0:1"]
    g, _ = run(rows=rows)
    assert g.coverage[0]["error"] == "DuplicateSecurityTemplateMember"
    rows = fixtures()
    rows["DescribeSecurityGroups"] *= 2
    g, _ = run(rows=rows, policies={})
    assert not resources(g, "vpc.securitygroup")
    assert g.coverage[-1]["error"] == "DuplicateSecurityGroupResource"


def test_one_denied_policy_does_not_erase_other_groups_rules():
    rows = fixtures()
    rows["DescribeSecurityGroups"].append(dict(SecurityGroupId="sg-two"))

    def mutate(action, params, response):
        if action == "DescribeSecurityGroupPolicies" and params["SecurityGroupId"] == "sg-one":
            raise CollectionError("UnauthorizedOperation")
        return response

    g, _ = run(
        rows=rows,
        policies={"sg-one": {}, "sg-two": dict(Version="0", Ingress=[], Egress=[policy()])},
        mutate=mutate,
    )
    assert len(resources(g, "vpc.securitygrouprule")) == 1
    assert resources(g, "vpc.securitygrouprule")[0]["resource_id"].startswith("sg-two/")


def test_member_descriptions_are_scoped_to_template_and_raw_addresses_retained():
    import json

    rows = fixtures()
    rows["DescribeAddressTemplates"][0]["AddressExtraSet"] = [
        dict(Address="10.0.0.0/24", Description="Clients", UpdatedTime="2026-10-13")
    ]
    g, _ = run(rows=rows)
    props = resources(g, "vpc.addresstemplate")[0]["properties"]
    assert json.loads(props["member_metadata"])[0]["Description"] == "Clients"
    assert json.loads(props["AddressSet"])[0] == "10.0.0.0/24"
    assert all("Description" not in n["properties"] for n in resources(g, "vpc.ruleaddress"))
    rows["DescribeAddressTemplates"][0]["AddressExtraSet"][0]["Address"] = "203.0.113.99"
    g, _ = run(rows=rows)
    assert g.coverage[0]["error"] == "ConflictingTemplateMemberMetadata"
