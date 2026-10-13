import json
from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.catalog import ALLOWED_ACTIONS, COLLECTORS, SES_ENDPOINTS
from tencent_cloud_cartography.collect import CollectorRunner, collect
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.ses import collect_domains, link_dns_checks
from tencent_cloud_cartography.transport import CollectionError, TccliTransport

SPEC = next(s for s in COLLECTORS if s.kind == "ses.domain")
REGION = "ap-singapore"


def identity(name="example.com", **extra):
    return dict(
        IdentityName=name, IdentityType="DOMAIN", SendingEnabled=False, DKIMOption=0, **extra
    )


def detail(name="example.com"):
    return dict(
        IdentityType="DOMAIN",
        VerifiedForSendingStatus=True,
        DKIMOption=2,
        Attributes=[
            dict(
                Type="TXT",
                SendDomain="qcloud._domainkey." + name,
                ExpectedValue="v=DKIM1; p=public-fixture",
                CurrentValue="",
                Status=False,
            )
        ],
    )


def run(rows=None, response=None, region=REGION, owner="100"):
    graph, calls = Graph(), []

    def call(service, action, **kw):
        calls.append((service, action, kw))
        if action == "ListEmailIdentities":
            values = [identity()] if rows is None else rows
            return dict(EmailIdentities=values, Total=len(values), RequestId="list-id")
        result = detail() if response is None else response
        if isinstance(result, Exception):
            raise result
        return {**result, "RequestId": "detail-id"}

    runner = CollectorRunner(graph, SimpleNamespace(call=call), owner, [region], lambda _: None)
    collect_domains(runner, SPEC, region)
    return graph, calls


def test_domain_and_dns_check_keep_distinct_statuses_and_official_icons():
    graph, calls = run(
        [
            identity(
                "EXAMPLE.com.",
                CurrentReputationLevel=8,
                DailyQuota=1000,
                SendIp=["192.0.2.7"],
                TagList=[dict(TagKey="team", TagValue="mail", Password="omit")],
            )
        ]
    )
    node = next(n for n in graph.nodes.values() if n["kind"] == "ses.domain")
    props = node["properties"]
    assert node["resource_id"] == "example.com"
    assert props["SendingEnabled"] is False and props["VerifiedForSendingStatus"] is True
    assert props["verification_changed_since_list"] and props["dkim_changed_since_list"]
    assert props["list_DKIMOption"] == 0 and props["dkim_key_bits"] == "1024,2048"
    assert props["DailyQuota"] == 1000 and json.loads(props["SendIp"]) == ["192.0.2.7"]
    assert json.loads(props["tags"]) == [dict(TagKey="team", TagValue="mail")]
    assert set(node["sources"]) == {"ses.ListEmailIdentities", "ses.GetEmailIdentity"}
    check = next(n for n in graph.nodes.values() if n["kind"] == "ses.dnscheck")
    assert check["properties"]["provider_check_passed"] is False
    assert check["properties"]["delivery_verified"] is False
    assert len(graph.edges) == 1
    assert calls[1][2] == dict(region=REGION, EmailIdentity="example.com")
    assert graph.coverage[1]["request_ids"] == ["detail-id"]
    assert all(icon_for(n["kind"]) == "en-simple-email-service.svg" for n in graph.nodes.values())
    assert "Password" not in graph.dump()


@pytest.mark.parametrize(
    "patch,error",
    [
        ({"IdentityType": "EMAIL_ADDRESS"}, "InvalidSesIdentityType"),
        ({"IdentityName": "victim@example.com"}, "InvalidDnsName"),
        ({"IdentityName": "*.example.com"}, "InvalidSesDomain"),
        ({"IdentityName": "example..com"}, "InvalidDnsName"),
        ({"SendingEnabled": 1}, "InvalidSesVerificationStatus"),
        ({"DKIMOption": True}, "InvalidSesDkimOption"),
        ({"DKIMOption": 3}, "InvalidSesDkimOption"),
        ({"DailyQuota": -1}, "InvalidSesQuota"),
        ({"SendIp": [{}]}, "InvalidSesSendIp"),
        ({"TagList": [{"TagKey": "team", "TagValue": {}}]}, "InvalidSesTags"),
    ],
)
def test_invalid_list_metadata_is_partial_without_native_nodes(patch, error):
    graph, calls = run([{**identity(), **patch}])
    assert graph.coverage[0]["error"] == error
    assert not graph.nodes and len(calls) == 1


@pytest.mark.parametrize(
    "patch,error",
    [
        ({"IdentityName": "other.example"}, "SesIdentityMismatch"),
        ({"IdentityType": "EMAIL_ADDRESS"}, "InvalidSesIdentityType"),
        ({"VerifiedForSendingStatus": "true"}, "InvalidSesVerificationStatus"),
        ({"Attributes": None}, "InvalidSesDnsAttributes"),
        (
            {
                "Attributes": [
                    {**detail()["Attributes"][0], "SendDomain": "example.com.attacker.test"}
                ]
            },
            "SesDnsDomainMismatch",
        ),
        ({"Attributes": [{**detail()["Attributes"][0], "Status": 1}]}, "InvalidSesDnsStatus"),
        (
            {"Attributes": [{**detail()["Attributes"][0], "ExpectedValue": ""}]},
            "InvalidSesDnsValue",
        ),
        ({"Attributes": [{**detail()["Attributes"][0], "Type": "UNKNOWN"}]}, "InvalidSesDnsType"),
        ({"Attributes": detail()["Attributes"] * 2}, "DuplicateSesDnsCheck"),
    ],
)
def test_bad_detail_keeps_list_identity_without_partial_detail_mutation(patch, error):
    graph, _ = run(response={**detail(), **patch})
    assert len(graph.nodes) == 1 and not graph.edges
    props = next(iter(graph.nodes.values()))["properties"]
    assert not props.get("detail_collected") and props["DKIMOption"] == 0
    assert graph.coverage[1]["error"] == error
    assert graph.coverage[1]["request_ids"] == ["detail-id"]


def test_alias_duplicates_are_detected_before_merging():
    graph, calls = run([identity(), identity("EXAMPLE.COM.")])
    assert graph.coverage[0]["error"] == "DuplicateSesIdentity"
    assert graph.coverage[0]["count"] == 1
    assert len([n for n in graph.nodes.values() if n["kind"] == "ses.domain"]) == 1
    assert len(calls) == 2  # First valid identity still gets independent details.


def test_pagination_uses_total_and_visits_each_identity():
    graph, offsets, details = Graph(), [], []

    def call(service, action, **kw):
        if action == "ListEmailIdentities":
            offsets.append(kw["Offset"])
            assert kw["Limit"] == 100
            return dict(
                EmailIdentities=[identity(f"d{i}.example.com") for i in range(101)][
                    kw["Offset"] : kw["Offset"] + 100
                ],
                Total=101,
            )
        details.append(kw["EmailIdentity"])
        return detail(kw["EmailIdentity"])

    collect_domains(
        CollectorRunner(graph, SimpleNamespace(call=call), "100", [REGION], lambda _: None),
        SPEC,
        REGION,
    )
    assert offsets == [0, 100] and len(details) == 101
    assert len(graph.nodes) == 202 and len(graph.edges) == 101
    assert all(c["status"] == "complete" for c in graph.coverage)


@pytest.mark.parametrize("total", [None, True, -1, "1"])
def test_missing_or_malformed_total_is_not_empty(total):
    graph = Graph()
    runner = CollectorRunner(
        graph,
        SimpleNamespace(call=lambda *a, **kw: dict(EmailIdentities=[], Total=total)),
        "100",
        [REGION],
        lambda _: None,
    )
    collect_domains(runner, SPEC, REGION)
    assert graph.coverage[0]["error"] == "InvalidTotal"


def test_detail_denial_preserves_list_and_continues_other_domains():
    graph = Graph()

    def call(service, action, **kw):
        if action == "ListEmailIdentities":
            return dict(EmailIdentities=[identity(), identity("second.example")], Total=2)
        if kw["EmailIdentity"] == "example.com":
            raise CollectionError("UnauthorizedOperation")
        return detail("second.example")

    collect_domains(
        CollectorRunner(graph, SimpleNamespace(call=call), "100", [REGION], lambda _: None),
        SPEC,
        REGION,
    )
    assert [c["status"] for c in graph.coverage] == ["complete", "denied", "complete"]
    assert len(graph.nodes) == 3


def test_frankfurt_is_explicit_unsupported_without_ses_request():
    graph, calls = run(region="eu-frankfurt")
    assert not calls and not graph.nodes
    assert graph.coverage[0]["status"] == "unsupported"
    assert graph.coverage[0]["error"] == "UnsupportedSesRegion"


@pytest.mark.parametrize("region,endpoint", list(SES_ENDPOINTS.items()))
def test_transport_uses_documented_regional_endpoint(monkeypatch, region, endpoint):
    commands = []

    def execute(args, **kw):
        commands.append(args)
        return SimpleNamespace(
            returncode=0, stdout='{"EmailIdentities": [], "Total": 0}', stderr=""
        )

    monkeypatch.setattr("subprocess.run", execute)
    TccliTransport().call("ses", "ListEmailIdentities", region=region, Limit=100, Offset=0)
    args = commands[0]
    assert args[args.index("--endpoint") + 1] == endpoint
    assert args[args.index("--region") + 1] == region
    assert args[args.index("--version") + 1] == "2020-10-02"


def test_endpoint_not_chosen_from_default_profile_or_unknown_region(monkeypatch):
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: pytest.fail("must not execute"))
    for region in (None, "global", "eu-frankfurt"):
        with pytest.raises(CollectionError, match="Collection failed") as err:
            TccliTransport().call(
                "ses", "GetEmailIdentity", region=region, EmailIdentity="example.com"
            )
        assert err.value.code == "UnsupportedSesRegion"


def test_dns_links_require_same_account_public_scope_and_exact_name_type_value():
    graph, _ = run()
    check = next(n for n in graph.nodes.values() if n["kind"] == "ses.dnscheck")
    p = check["properties"]
    for i, (owner, scope, name, rtype, value, status) in enumerate(
        [
            ("100", "public", p["dns_name"], "TXT", p["expected_value"], "enriched"),
            ("200", "public", p["dns_name"], "TXT", p["expected_value"], "enriched"),
            ("100", "private", p["dns_name"], "TXT", p["expected_value"], "enriched"),
            ("100", "public", "other.example", "TXT", p["expected_value"], "enriched"),
            ("100", "public", p["dns_name"], "CNAME", p["expected_value"], "enriched"),
            ("100", "public", p["dns_name"], "TXT", "wrong", "enriched"),
            ("100", "public", p["dns_name"], "TXT", p["expected_value"], "reference"),
        ]
    ):
        nid = graph.add(owner, "global", "dnspod.record", str(i), status=status)
        graph.nodes[nid]["properties"].update(
            dns_scope=scope, dns_name=name, record_type=rtype, record_value=value
        )
    link_dns_checks(graph)
    links = [e for e in graph.edges.values() if e["relationship"] == "MATCHES_EXPECTED_DNS_RECORD"]
    assert len(links) == 1 and graph.nodes[links[0]["target"]]["resource_id"] == "0"
    assert p["matching_dns_record_count"] == 1


def test_only_configuration_apis_are_allowlisted_and_nested_fields_cannot_add_networks():
    assert {a for s, a in ALLOWED_ACTIONS if s == "ses"} == {
        "ListEmailIdentities",
        "GetEmailIdentity",
    }
    graph, _ = run(
        [identity(Extra=dict(VpcId="vpc-wrong", Password="omit", Body="omit"))],
        {**detail(), "PrivateKey": "omit", "Body": "omit"},
    )
    assert {n["kind"] for n in graph.nodes.values()} == {"ses.domain", "ses.dnscheck"}
    assert "omit" not in graph.dump() and "vpc-wrong" not in graph.dump()


def test_collect_wiring_and_account_isolation():
    class Transport:
        def __init__(self, account):
            self.account = account

        def call(self, service, action, **kw):
            if service == "sts":
                return dict(
                    AccountId=self.account, PrincipalId=self.account, Arn="fixture:" + self.account
                )
            if service == "cloudrc":
                return dict(Resources=[], NextToken="")
            if action == "ListEmailIdentities":
                return dict(EmailIdentities=[identity()], Total=1)
            if action == "GetEmailIdentity":
                return detail()
            pytest.fail(action)

    data = collect(
        ["100", "200"],
        [REGION],
        services=["ses"],
        progress=lambda _: None,
        transport_factory=Transport,
    )
    assert len(data["nodes"]) == 4 and len(data["edges"]) == 2
    assert {n["account"] for n in data["nodes"]} == {"100", "200"}
    assert all(n["region"] == REGION for n in data["nodes"])
    assert (
        sum(
            c["action"] == "GetEmailIdentity" and c["status"] == "complete"
            for c in data["coverage"]
        )
        == 2
    )
