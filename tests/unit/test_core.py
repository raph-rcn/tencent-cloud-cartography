import json
import os
import subprocess
from xml.etree import ElementTree as ET

import pytest

from tencent_cloud_cartography.catalog import COLLECTORS, SERVICE_ICONS
from tencent_cloud_cartography.collect import CollectorRunner, collect
from tencent_cloud_cartography.demo import demo
from tencent_cloud_cartography.drawio import export
from tencent_cloud_cartography.icons import icon_for, manifest, names
from tencent_cloud_cartography.model import Graph, stable_id
from tencent_cloud_cartography.storage import load, save
from tencent_cloud_cartography.topology import topology
from tencent_cloud_cartography.transport import (
    CollectionError,
    TccliTransport,
    pages,
    parse_buckets,
)


class Fake:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def call(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        value = next(self.responses)
        if isinstance(value, Exception):
            raise value
        return value


def test_pagination_crosses_page_and_preserves_request_ids():
    f = Fake(
        [
            dict(VpcSet=[{"VpcId": str(i)} for i in range(100)], TotalCount=101, RequestId="r1"),
            dict(VpcSet=[{"VpcId": "100"}], TotalCount=101, RequestId="r2"),
        ]
    )
    result = list(pages(f, next(s for s in COLLECTORS if s.kind == "vpc.vpc"), "eu-frankfurt"))
    assert sum(len(p[0]) for p in result) == 101
    assert [p[1] for p in result] == ["r1", "r2"]
    assert f.calls[1][1]["Offset"] == 100


@pytest.mark.parametrize(
    "responses,code",
    [
        ([{}], "InvalidResponse"),
        ([dict(VpcSet=[], TotalCount=1)], "IncompletePagination"),
        ([dict(VpcSet=[{}], TotalCount=0)], "CountMismatch"),
        ([dict(VpcSet=[{}], TotalCount="no")], "InvalidTotal"),
        (
            [dict(VpcSet=[{"id": 1}], TotalCount=2), dict(VpcSet=[{"id": 1}], TotalCount=2)],
            "PaginationStalled",
        ),
        (
            [dict(VpcSet=[{"id": 1}], TotalCount=2), dict(VpcSet=[{"id": 2}], TotalCount=3)],
            "InventoryChanged",
        ),
    ],
)
def test_pagination_negative_controls(responses, code):
    with pytest.raises(CollectionError) as e:
        list(
            pages(
                Fake(responses), next(s for s in COLLECTORS if s.kind == "vpc.vpc"), "eu-frankfurt"
            )
        )
    assert e.value.code == code


@pytest.mark.parametrize(
    "service,action",
    [
        ("cvm", "TerminateInstances"),
        ("ssm", "GetSecretValue"),
        ("ssl", "DescribeCertificateDetail"),
        ("ssl", "DownloadCertificate"),
        ("cloudaudit", "LookUpEvents"),
        ("cloudaudit", "DescribeEvents"),
        ("monitor", "DescribeAlarmHistories"),
        ("monitor", "GetMonitorData"),
        ("cls", "SearchLog"),
        ("cls", "DownloadLog"),
        ("cls", "GetAlarmLog"),
        ("cls", "DescribeAlertRecordHistory"),
        ("cos", "get_object"),
        ("scf", "GetFunction"),
        ("kms", "GetDataKeyPlaintext"),
        ("kms", "GetDataKeyCiphertextBlob"),
        ("kms", "DescribeWhiteBoxDecryptKey"),
        ("cdb", "DescribeBackupDecryptionKey"),
    ],
)
def test_blocked_operations_never_start_process(monkeypatch, service, action):
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: pytest.fail("spawned blocked action"))
    with pytest.raises(CollectionError, match="allowlist"):
        TccliTransport().call(service, action)


def test_cli_transport_validates_json_without_name_false_positive(monkeypatch):
    def run(args, **kwargs):
        assert "--version" in args and "2017-03-12" in args
        assert "--region" in args and "eu-frankfurt" in args
        assert kwargs["timeout"] == 120
        return subprocess.CompletedProcess(
            args, 0, json.dumps({"VpcSet": [{"VpcName": "AuthFailure"}]}), ""
        )

    monkeypatch.setattr(subprocess, "run", run)
    assert TccliTransport().call("vpc", "DescribeVpcs", "eu-frankfurt")["VpcSet"]


@pytest.mark.parametrize("payload", ["[]", "null", '{"Response":[]}', "not-json"])
def test_invalid_cli_json(monkeypatch, payload):
    monkeypatch.setattr(TccliTransport, "_run", lambda *a: payload)
    with pytest.raises(CollectionError):
        TccliTransport().call("sts", "GetCallerIdentity")


def test_error_does_not_leak_raw_payload(monkeypatch):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess(
            a, 1, "", "AuthFailure.SecretIdNotFound secret-material"
        ),
    )
    with pytest.raises(CollectionError) as e:
        TccliTransport().call("sts", "GetCallerIdentity")
    assert "secret-material" not in str(e.value)
    assert e.value.code == "AuthFailure.SecretIdNotFound"


def test_rate_limit_retries(monkeypatch):
    responses = iter(['{"Error":{"Code":"RequestLimitExceeded"}}', '{"AccountId":"1"}'])
    monkeypatch.setattr(TccliTransport, "_run", lambda *a: next(responses))
    monkeypatch.setattr("time.sleep", lambda _: None)
    assert TccliTransport().call("sts", "GetCallerIdentity")["AccountId"] == "1"


def test_cos_table_strict_parser():
    assert parse_buckets(
        "BucketName Region CreationDate\nassets-10001 eu-frankfurt 2026-10-13T00:00:00Z\n共 1 个存储桶"
    ) == [dict(name="assets-10001", region="eu-frankfurt")]
    assert parse_buckets("当前账号下没有存储桶") == []
    with pytest.raises(CollectionError):
        parse_buckets("BucketName Region CreationDate\n共 1 个存储桶")


def test_graph_reconciles_baseline_references_and_native():
    graph = Graph()
    nid = graph.add("1", "eu-frankfurt", "cvm.instance", "ins-1", status="inventory-only")
    graph.add("1", "eu-frankfurt", "cvm.instance", "ins-1", status="reference")
    assert graph.nodes[nid]["status"] == "inventory-only"
    cvm = next(s for s in COLLECTORS if s.kind == "cvm.instance")
    graph.native(
        "1",
        "eu-frankfurt",
        cvm,
        {
            "InstanceId": "ins-1",
            "InstanceName": "web",
            "VirtualPrivateCloud": {"VpcId": "vpc-1", "SubnetId": "subnet-1"},
            "Password": "secret",
            "UserData": "secret",
            "Environment": {"Variables": ["secret"]},
        },
        "cvm.DescribeInstances",
    )
    assert graph.nodes[nid]["status"] == "enriched"
    assert len(graph.nodes) == 3 and len(graph.edges) == 2
    assert "secret" not in graph.dump()
    assert graph.add("2", "eu-frankfurt", "cvm.instance", "ins-1") != nid
    assert graph.add("1", "ap-guangzhou", "cvm.instance", "ins-1") != nid


def test_baseline_coverage_retains_partial_and_provenance():
    f = Fake(
        [
            dict(
                Resources=[
                    dict(
                        Uin="1",
                        RegionCode="eu-frankfurt",
                        ResourceType="qcs::cvm::instance",
                        ResourceId="ins-1",
                    )
                ],
                NextToken="next",
                RequestId="a",
            ),
            CollectionError("UnauthorizedOperation"),
        ]
    )
    g = Graph()
    runner = CollectorRunner(g, f, "1", ["eu-frankfurt"], lambda _: None)
    coverage = runner.baseline("eu-frankfurt")
    assert coverage["status"] == "denied" and coverage["count"] == 1
    assert coverage["request_ids"] == ["a"]
    assert g.snapshot()["status"] == "partial"


@pytest.mark.parametrize(
    "field,value,error",
    [("Uin", "2", "AccountMismatch"), ("RegionCode", "ap-guangzhou", "RegionMismatch")],
)
def test_baseline_scope_controls(field, value, error):
    item = dict(
        Uin="1", RegionCode="eu-frankfurt", ResourceType="qcs::cvm::instance", ResourceId="ins-1"
    )
    item[field] = value
    g = Graph()
    record = CollectorRunner(
        g, Fake([dict(Resources=[item])]), "1", ["eu-frankfurt"], lambda _: None
    ).baseline("eu-frankfurt")
    assert record["error"] == error and not g.nodes


def test_identity_changes_fail_before_publication(monkeypatch):
    monkeypatch.setattr(CollectorRunner, "run", lambda *args: None)
    f = Fake([dict(AccountId="1", PrincipalId="alice"), dict(AccountId="1", PrincipalId="bob")])
    with pytest.raises(CollectionError) as e:
        collect(["default"], ["eu-frankfurt"], transport_factory=lambda _: f)
    assert e.value.code == "IdentityChanged"


def test_all_catalog_icons_exist():
    assert len(manifest()["icons"]) == 896
    for title, asset in SERVICE_ICONS.values():
        assert asset in names(), title
    for spec in COLLECTORS:
        assert icon_for(spec.kind) != "unmapped.svg"
    assert icon_for("unknown.resource") == "unmapped.svg"


def test_topology_factual_containment_and_full_edges():
    data = demo()
    result = topology(data, view="full", include_inventory=True)
    nodes = {e["data"]["id"]: e["data"] for e in result["elements"] if "source" not in e["data"]}
    actual = {n["resource_id"]: n for n in data["nodes"]}
    assert nodes[actual["ins-web"]["id"]]["locationParent"] == actual["subnet-web"]["id"]
    assert nodes[actual["subnet-web"]["id"]]["parent"].startswith("zone-")
    assert all(not n.get("parent") or n["parent"] in nodes for n in nodes.values())
    assert result["stats"]["relationships"] == len(data["edges"])
    arch = topology(data)
    assert arch["stats"]["resources"] < result["stats"]["resources"]
    assert topology(data, account="other")["elements"] == []
    assert topology(data, limit=1)["truncated"]


def test_multi_subnet_stays_in_vpc():
    data = demo()
    n = next(n for n in data["nodes"] if n["resource_id"] == "ins-web")
    target = next(n for n in data["nodes"] if n["resource_id"] == "subnet-data")
    data["edges"].append(
        dict(
            id="multi",
            source=n["id"],
            target=target["id"],
            relationship="IN_SUBNET",
            provenance="fixture",
        )
    )
    result = topology(data)
    item = next(e["data"] for e in result["elements"] if e["data"]["id"] == n["id"])
    assert item["locationParent"] == stable_id(n["account"], n["region"], "vpc.vpc", "vpc-demo")


def test_atomic_private_snapshot_roundtrip(tmp_path):
    path = tmp_path / "data.json"
    save(demo(), path)
    assert load(path)["mode"] == "demo"
    assert os.stat(path).st_mode & 0o777 == 0o600
    bad = demo()
    bad["edges"][0]["target"] = "missing"
    save(bad, path)
    with pytest.raises(ValueError, match="endpoints"):
        load(path)


def test_drawio_embedded_icons_nested_geometry_and_escaping():
    nodes = [
        dict(id="vpc", label="VPC <one>", type="vpc", x=100, y=100, width=500, height=500),
        dict(
            id="vm",
            label="VM & test",
            type="resource",
            icon=icon_for("cvm.instance"),
            parent="vpc",
            x=150,
            y=180,
            width=80,
            height=80,
        ),
    ]
    root = ET.fromstring(export(dict(nodes=nodes, edges=[])))
    cells = root.findall(".//mxCell")
    vm = next(c for c in cells if c.get("value") == "VM & test")
    assert vm.get("parent") == "n0" and "data:image/svg+xml," in vm.get("style")
    assert vm.find("mxGeometry").get("x") == "50.0"
    assert b"aws4" not in export(dict(nodes=nodes, edges=[]))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda n: n.update(x=float("nan")),
        lambda n: n.update(parent="a"),
        lambda n: n.update(width=-1),
    ],
)
def test_drawio_rejects_invalid_geometry_or_cycles(mutate):
    n = dict(id="a", width=100, height=100)
    mutate(n)
    with pytest.raises(ValueError):
        export(dict(nodes=[n], edges=[]))


def test_end_to_end_collection_all_scopes_and_clb_field_selection():
    from tencent_cloud_cartography.catalog import (
        CHILDREN,
        SCF_DETAILS,
        SCF_FUNCTIONS,
        SCF_NAMESPACES,
    )

    specs = {
        (s.service, s.action): s
        for s in (
            *COLLECTORS,
            *CHILDREN.values(),
            *SCF_DETAILS.values(),
            SCF_FUNCTIONS,
            SCF_NAMESPACES,
        )
    }

    class InventoryTransport:
        def call(self, service, action, region=None, **params):
            if service == "sts":
                return dict(AccountId="12345", PrincipalId="reader")
            if service == "cloudrc":
                return dict(Resources=[], RequestId="baseline")
            if service == "config" and action == "DescribeConfigRecorder":
                return dict(Status=0, Items=[])
            if service == "config" and action == "DescribeConfigDeliver":
                raise CollectionError("ResourceNotFound.DeliverIsNotExist")
            if service == "clb" and action == "DescribeListeners":
                return dict(Listeners=[], TotalCount=0)
            if service == "cos":
                if action == "get_bucket_acl":
                    return dict(
                        Owner={"ID": "qcs::cam::uin/12345:uin/12345"}, AccessControlList=None
                    )
                if action == "get_bucket_encryption":
                    return {
                        "Rule": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
                    }
                if action == "get_bucket_policy":
                    raise CollectionError("AccessDenied")
                return {}
            if action == "DescribeHostCdnInstanceList":
                return dict(InstanceList=[], TotalCount=0)
            if service == "tag":
                return dict(ResourceTagMappingList=[], PaginationToken="", RequestId="tags")
            spec = specs[service, action]
            result = {}
            current = result
            parts = spec.result.split(".")
            for part in parts[:-1]:
                current = current.setdefault(part, {})
            items = []
            if action == "DescribeLoadBalancersDetail":
                assert {"ListenerId", "TargetId", "TargetAddress"} <= set(params["Fields"])
                items = [
                    dict(
                        LoadBalancerId="lb-test",
                        LoadBalancerName="test",
                        ListenerId="lbl-test",
                        Protocol="HTTPS",
                        Port=443,
                        TargetId="ins-test",
                    )
                ]
            if service == "cvm" and action == "DescribeInstances":
                items = [dict(InstanceId="ins-test", InstanceName="server")]
            current[parts[-1]] = items
            if spec.total:
                current = result
                parts = spec.total.split(".")
                for part in parts[:-1]:
                    current = current.setdefault(part, {})
                current[parts[-1]] = len(items)
            result["RequestId"] = action
            return result

        def buckets(self):
            return [
                dict(name="assets-12345", region="eu-frankfurt"),
                dict(name="out-of-scope-12345", region="ap-guangzhou"),
            ]

    data = collect(
        ["test"],
        ["eu-frankfurt"],
        progress=lambda _: None,
        transport_factory=lambda _: InventoryTransport(),
    )
    assert data["status"] == "partial"
    assert len(data["nodes"]) == 5
    assert len(data["coverage"]) == 97
    assert {"DescribeCmqQueues", "DescribeCmqTopics"} <= {c["action"] for c in data["coverage"]}
    assert any(c["action"] == "ListLayers" and c["status"] == "empty" for c in data["coverage"])
    assert any(e["relationship"] == "FORWARDS_TO" for e in data["edges"])
    assert all(
        n["region"] == ("global" if n["kind"].startswith("config.") else "eu-frankfurt")
        for n in data["nodes"]
    )
    assert [c["action"] for c in data["coverage"] if c["status"] not in {"empty", "complete"}] == [
        "ListEmailIdentities",
        "DescribeLaunchConfigurations",
        "DescribeDomains",
        "get_bucket_policy",
    ]
    ses_scope = next(c for c in data["coverage"] if c["action"] == "ListEmailIdentities")
    assert ses_scope["status"] == "unsupported" and ses_scope["error"] == "UnsupportedSesRegion"
