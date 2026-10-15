import pytest

from tencent_cloud_cartography.exposure import analyze
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph


def fixture(direct=False):
    g = Graph()
    ids = {}
    for key, kind in [
        ("vpc", "vpc.vpc"),
        ("lb", "clb.clb"),
        ("listener", "clb.listener"),
        ("rule", "clb.rule"),
        ("instance", "cvm.instance"),
        ("eni", "vpc.networkinterface"),
        ("address", "vpc.interfaceaddress"),
        ("target", "clb.target"),
    ]:
        ids[key] = g.add(
            "100",
            "eu-frankfurt",
            kind,
            key,
            "10.0.0.8" if key == "target" else key,
            source="synthetic",
        )
    g.nodes[ids["address"]]["properties"].update(address="10.0.0.8", NetworkInterfaceId="eni")
    for key in ("lb", "instance", "eni", "address"):
        g.edge(ids[key], ids["vpc"], "IN_VPC")
    for a, b, relationship in [
        ("lb", "listener", "HAS_LISTENER"),
        ("listener", "rule", "HAS_RULE"),
        ("eni", "address", "HAS_ADDRESS"),
        ("eni", "instance", "ATTACHED_TO"),
    ]:
        g.edge(ids[a], ids[b], relationship)
    g.edge(ids["rule"], ids["instance" if direct else "target"], "FORWARDS_TO")
    if not direct:
        g.edge(ids["target"], ids["address"], "MATCHES_INTERFACE_ADDRESS")
    return g, ids


def paths(g):
    return [n for n in g.nodes.values() if n["kind"] == "clb.exposurepath"]


def expose(g):
    return [e for e in g.edges.values() if e["relationship"] == "EXPOSE"]


def remove(g, a, b, relation):
    g.edges = {
        eid: e
        for eid, e in g.edges.items()
        if not (e["source"] == a and e["target"] == b and e["relationship"] == relation)
    }


def test_configured_ip_and_instance_paths_have_explicit_frontend_evidence():
    g, ids = fixture()
    analyze(g)
    assert {e["target"] for e in expose(g)} == {ids["address"], ids["instance"]}
    assert len(paths(g)) == 2
    assert all(not n["properties"]["reachability_verified"] for n in paths(g))
    assert all(icon_for(n["kind"]) == "en-cloud-load-balancer.svg" for n in paths(g))
    assert g.coverage[-1]["status"] == "complete" and g.coverage[-1]["count"] == 2
    assert {"VIA_FRONTEND", "VIA_BACKEND", "TARGETS_RESOURCE"} <= {
        e["relationship"] for e in g.edges.values()
    }


def test_explicit_instance_backend_creates_direct_exposure_path():
    g, ids = fixture(direct=True)
    analyze(g)
    assert [e["target"] for e in expose(g)] == [ids["instance"]]
    assert paths(g)[0]["properties"]["resolution"] == "explicit-instance"


@pytest.mark.parametrize(
    "field,value", [("account", "200"), ("region", "ap-singapore"), ("status", "reference")]
)
def test_cross_account_region_and_uncollected_address_cannot_expose(field, value):
    g, ids = fixture()
    g.nodes[ids["address"]][field] = value
    analyze(g)
    assert not paths(g) and g.coverage[-1]["status"] == "error"


def test_wrong_vpc_or_ambiguous_address_has_no_exposure():
    for change in ("vpc", "duplicate"):
        g, ids = fixture()
        if change == "vpc":
            other = g.add("100", "eu-frankfurt", "vpc.vpc", "other")
            remove(g, ids["address"], ids["vpc"], "IN_VPC")
            g.edge(ids["address"], other, "IN_VPC")
        else:
            other = g.add("100", "eu-frankfurt", "vpc.interfaceaddress", "duplicate")
            g.edge(ids["target"], other, "MATCHES_INTERFACE_ADDRESS")
        analyze(g)
        assert not expose(g) and g.coverage[-1]["status"] == "error"


@pytest.mark.parametrize("value", ["10.0.0.9", "not-an-ip"])
def test_target_address_conflicts_are_partial(value):
    g, ids = fixture()
    g.nodes[ids["target"]]["properties"]["TargetAddress"] = value
    analyze(g)
    assert not expose(g) and g.coverage[-1]["status"] == "error"


@pytest.mark.parametrize("reported_id", ["eni-other", "ins-other"])
def test_target_id_and_ip_contradiction_does_not_expose_ip_match(reported_id):
    g, ids = fixture()
    g.nodes[ids["target"]]["properties"]["TargetId"] = reported_id
    analyze(g)
    assert not expose(g) and g.coverage[-1]["status"] == "error"


def test_address_without_unique_collected_attachment_keeps_only_ip_exposure():
    g, ids = fixture()
    remove(g, ids["eni"], ids["instance"], "ATTACHED_TO")
    analyze(g)
    assert [e["target"] for e in expose(g)] == [ids["address"]]


def test_foreign_instance_attachment_is_not_exposed():
    g, ids = fixture()
    g.nodes[ids["instance"]]["account"] = "200"
    analyze(g)
    assert [e["target"] for e in expose(g)] == [ids["address"]]


def test_wrong_interface_identity_cannot_resolve_instance():
    g, ids = fixture()
    g.nodes[ids["address"]]["properties"]["NetworkInterfaceId"] = "other"
    analyze(g)
    assert [e["target"] for e in expose(g)] == [ids["address"]]


def test_foreign_intermediate_frontend_and_scope_container_do_not_expose():
    g, ids = fixture()
    g.nodes[ids["listener"]]["account"] = "200"
    analyze(g)
    assert not expose(g)
    g, ids = fixture()
    g.nodes[ids["vpc"]]["account"] = "200"
    analyze(g)
    assert not expose(g)


def test_multiple_frontends_keep_separate_paths_and_one_direct_edge():
    g, ids = fixture(direct=True)
    other = g.add("100", "eu-frankfurt", "clb.listener", "other")
    g.edge(ids["lb"], other, "HAS_LISTENER")
    g.edge(other, ids["instance"], "FORWARDS_TO")
    analyze(g)
    assert len(expose(g)) == 1 and len(paths(g)) == 2


def test_partial_backend_does_not_discard_confirmed_path():
    g, ids = fixture(direct=True)
    missing = g.add("100", "eu-frankfurt", "clb.target", "missing")
    g.edge(ids["listener"], missing, "FORWARDS_TO")
    analyze(g)
    assert len(expose(g)) == 1 and g.coverage[-1]["status"] == "error"


def test_cycles_terminate_and_reanalysis_removes_stale_exposure():
    g, ids = fixture()
    g.edge(ids["rule"], ids["listener"], "HAS_RULE")
    analyze(g)
    first = g.dump()
    analyze(g)
    assert g.dump() == first
    remove(g, ids["target"], ids["address"], "MATCHES_INTERFACE_ADDRESS")
    analyze(g)
    assert not paths(g) and not expose(g)
