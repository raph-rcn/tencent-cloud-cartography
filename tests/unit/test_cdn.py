from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.catalog import ALLOWED_ACTIONS
from tencent_cloud_cartography.cdn import collect_domains
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.transport import CollectionError, TccliTransport


def run(rows=None, mutate=None):
    graph, calls = Graph(), []
    rows = (
        [
            dict(
                Domain="WWW.Example.com.",
                CertId="cert-deployed",
                Status="online",
                HttpsBillingSwitch="1",
            )
        ]
        if rows is None
        else rows
    )

    def call(service, action, **params):
        assert (service, action) == ("ssl", "DescribeHostCdnInstanceList")
        assert set(params) == {"region", "IsCache", "AsyncCache", "Offset", "Limit"}
        assert params["region"] == "global" and params["IsCache"] == params["AsyncCache"] == 0
        calls.append(params)
        result = dict(
            InstanceList=rows[params["Offset"] : params["Offset"] + params["Limit"]],
            TotalCount=len(rows),
            RequestId=str(len(calls)),
        )
        return mutate(result) if mutate else result

    collect_domains(
        CollectorRunner(graph, SimpleNamespace(call=call), "100", ["eu-frankfurt"], lambda _: None)
    )
    return graph, calls


def test_deployed_certificate_and_global_metadata_without_billing_inference():
    graph, calls = run()
    node = next(n for n in graph.nodes.values() if n["kind"] == "cdn.domain")
    assert node["resource_id"] == "www.example.com"
    assert node["region"] == "global" and node["account"] == "100"
    assert node["properties"]["HttpsBillingSwitch"] == "1"
    assert "https_enabled" not in node["properties"]
    assert not node["properties"]["origin_configuration_collected"]
    assert icon_for(node["kind"]) == "en-content-delivery-network.svg"
    edge = next(iter(graph.edges.values()))
    assert edge["relationship"] == "USES_CERTIFICATE"
    target = graph.nodes[edge["target"]]
    assert target["resource_id"] == "cert-deployed" and target["status"] == "reference"
    assert target["account"] == "100" and target["region"] == "global"
    assert graph.coverage[0]["status"] == "unsupported"
    assert graph.coverage[1]["count"] == 1 and len(calls) == 1


def test_empty_deployment_view_does_not_claim_full_cdn_coverage():
    graph, _ = run([])
    assert not graph.nodes
    assert [c["status"] for c in graph.coverage] == ["unsupported", "empty"]


def test_pagination_and_domains_without_managed_certificate():
    rows = [dict(Domain=f"d{i}.example.com", CertId="") for i in range(201)]
    rows[0]["Domain"] = "*.example.com"
    graph, calls = run(rows)
    assert [p["Offset"] for p in calls] == [0, 200]
    assert len(graph.nodes) == 201 and not graph.edges
    assert graph.coverage[-1]["count"] == 201


@pytest.mark.parametrize(
    "row",
    [
        {},
        dict(Domain=None),
        dict(Domain="localhost"),
        dict(Domain="a/b.example.com"),
        dict(Domain="x.example.com", CertId=42),
        dict(Domain="x.example.com", CertId="bad/id"),
        dict(Domain="x.example.com", Status=False),
        dict(Domain="x.example.com", HttpsBillingSwitch="bad\n"),
    ],
)
def test_invalid_rows_do_not_leave_partial_page_nodes(row):
    graph, _ = run([dict(Domain="valid.example.com"), row])
    assert not graph.nodes and graph.coverage[-1]["status"] == "error"


def test_normalized_duplicate_domains_fail_before_page_mutation():
    graph, _ = run([dict(Domain="a.example.com"), dict(Domain="A.EXAMPLE.COM.")])
    assert not graph.nodes and graph.coverage[-1]["error"] == "DuplicateCdnDomain"


@pytest.mark.parametrize(
    "field,value", [("TotalCount", None), ("TotalCount", True), ("InstanceList", None)]
)
def test_unavailable_results_are_errors(field, value):
    graph, _ = run(mutate=lambda r: {**r, field: value})
    assert not graph.nodes and graph.coverage[-1]["status"] == "error"


@pytest.mark.parametrize("action", ["DescribeDomains", "DescribeDomainsConfig"])
def test_sensitive_cdn_operations_blocked_before_subprocess(action, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Sensitive operation reached subprocess")

    monkeypatch.setattr("subprocess.run", forbidden)
    assert ("cdn", action) not in ALLOWED_ACTIONS
    with pytest.raises(CollectionError, match="outside the metadata allowlist"):
        TccliTransport().call("cdn", action)


def test_denied_ssl_inventory_preserves_cdn_gap():
    def denied(_):
        raise CollectionError("UnauthorizedOperation")

    graph, _ = run(mutate=denied)
    assert [c["status"] for c in graph.coverage] == ["unsupported", "denied"]


def test_permission_inventory_matches_transport_allowlist():
    import json
    from pathlib import Path

    actions = json.loads(
        (Path(__file__).resolve().parents[2] / "docs/api-actions.json").read_text()
    )["actions"]
    assert {(r["service"], r["action"]) for r in actions} == ALLOWED_ACTIONS
    assert all(r.get("api_version") for r in actions)
    assert all(r.get("cam_action") for r in actions if r["service"] == "cos")
