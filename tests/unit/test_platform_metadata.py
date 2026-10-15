"""Explicit provider fixtures, rejected scopes and metadata-only platform behavior."""

import copy
import json
from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.catalog import ALLOWED_ACTIONS, DETAIL_KINDS
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.platform_metadata import (
    ACTIONS,
    KINDS,
    READS,
    checked_read,
    link,
    parameters,
)
from tencent_cloud_cartography.storage import validate

REGION = "eu-frankfurt"
RESPONSES = {
    "DescribeBillingResourceGroup": dict(
        InstanceSet=[
            dict(
                InstanceId="resource-1",
                CvmInstanceId="ins-one",
                InstanceStatus="Running",
                UsedResource=dict(Cpu=2, Memory=4),
                TotalResource=dict(Cpu=4, Memory=8),
            )
        ],
        TotalCount=1,
    ),
    "DescribeBillingResourceInstanceRunningJobs": dict(
        ResourceInstanceRunningJobInfos=[
            dict(
                PodName="training-1", TaskType="Training", TaskId="task-1", TaskName="Training job"
            )
        ]
    ),
    "DescribeKnowledgeUsage": dict(
        AvailableCharSize="10000", UsedCharSize="5000", ExceedCharSize="0"
    ),
    "GetUserSyncProvisioning": dict(
        UserProvisioning=dict(UserProvisioningId="provision-1", TargetUin=200, Status="Enabled")
    ),
    "DescribeForwardRuleList": dict(
        ForwardRuleSet=[
            dict(
                RuleId="fr-1",
                Domain="corp.test",
                EndPointId="ep-1",
                ZoneId="zone-1",
                VpcSet=[dict(UniqVpcId="vpc-one", Region=REGION)],
                ForwardAddress=["10.0.0.3"],
            )
        ],
        TotalCount=1,
    ),
    "DescribeInboundEndpointList": dict(
        InboundEndpointSet=[
            dict(
                EndPointId="iep-1",
                UniqVpcId="vpc-one",
                EndPointService=[
                    dict(EndPointVip="10.0.0.4", UniqSubnetId="subnet-one", EndPointState=1)
                ],
            )
        ],
        TotalCount=1,
    ),
    "DescribeDomainAliasList": dict(
        DomainAliasList=[dict(Id=1, DomainAlias="alias.test", Status=1)]
    ),
    "DescribeDomainShareUserList": dict(
        DomainShareList=[dict(DomainShareId=1, QCloudUIN="200", Mode="rw", Status="enabled")]
    ),
    "DescribeDeployedResources": dict(
        DeployedResources=[
            dict(
                CertificateId="parent-1",
                Type="clb",
                Count=1,
                ResourceIds=["lb-one"],
                Resources=["lb-one"],
            )
        ]
    ),
    "DescribeScanVulSetting": dict(
        VulCategories="1,2", EnableScan=1, TimerInterval=7, Uuids=["host-1"]
    ),
    "DescribeMalwareTimingScanSetting": dict(
        EnableScan=1, IsGlobal=1, Cycle=1, QuuidList=["host-1"]
    ),
    "DescribeOverviewStatistics": dict(OnlineMachineNum=1, VulNum=2),
    "DescribeVulInfoCvss": dict(
        VulId=1,
        VulName="Vendor definition",
        Description="Public vulnerability advisory",
        CvssScoreFloat=7.5,
    ),
    "DescribeAssetSummary": dict(ContainerCnt=2, ScannedImageCnt=1, UnScannedImageCnt=1),
    "DescribeAssetImageScanSetting": dict(
        Enable=True, ScanPeriod=1, ScanVul=True, Images=["sha256:abc"]
    ),
    "DescribeVirusScanSetting": dict(EnableScan=True, Cycle=1, ScanIds=["host-1"]),
    "DescribeComplianceTaskAssetSummary": dict(
        AssetSummaryList=[
            dict(
                AssetType="ASSET_CONTAINER",
                PassedAssetCount=1,
                FailedAssetCount=1,
                CheckProgress=100.0,
            )
        ]
    ),
    "DescribeComplianceTaskPolicyItemSummaryList": dict(
        PolicyItemSummaryList=[
            dict(
                CustomerPolicyItemId=1,
                Name="Vendor control",
                AssetType="ASSET_CONTAINER",
                CheckResult="passed",
            )
        ],
        TotalCount=1,
    ),
    "DescribeRiskScanCronConfig": dict(
        CronConfig=dict(PlanContent="0 0 * * *", CronStatus=1, AddRuleEnableStatus=True)
    ),
    "DescribeVulScanPeriodic": dict(Status=1, CycleType=1, VulCategory=["cve"]),
    "DescribeAssetOverview": dict(AssetOverview=dict(AssetTotalCount=2, RiskAssetCount=1)),
    "DescribeComplianceOverview": dict(
        AllCheckItems=dict(TotalCount=10, PassRate=80),
        Standards=[dict(ID=1, Name="Vendor standard", TotalCount=10, PassRate=80)],
    ),
    "DescribeRiskRules": dict(
        RiskRuleList=[dict(ItemId="rule-1", RiskTitle="Vendor rule", Severity="high")], TotalCount=1
    ),
    "ListAggregators": dict(
        Items=[dict(AccountGroupId="agg-1", OwnerUin=100, AccountCount=2, Name="Org inventory")],
        Total=1,
    ),
    "DescribeAggregator": dict(
        Name="Org inventory",
        Type="ORG",
        AggregatorStatus=1,
        AggregatorAccounts=[dict(MemberName="Member", MemberUin=200)],
    ),
    "DescribeAggregateConfigDeliver": dict(
        DeliverType="COS",
        TargetArn=f"qcs::cos:{REGION}:uid/12345:config-12345",
        DeliverUin=200,
        Status=1,
    ),
    "ListAudits": dict(
        AuditSummarys=[dict(AuditName="parent-1", CosBucketName="logs-12345", AuditStatus=1)]
    ),
    "DescribeAudit": dict(
        AuditName="parent-1", CosBucketName="logs-12345", CosRegion=REGION, AuditStatus=1
    ),
    "DescribeProductList": dict(
        ProductList=[dict(Namespace="QCE/CVM", ProductName="CVM")], TotalCount=1
    ),
    "DescribeBaseMetrics": dict(
        MetricSet=[
            dict(
                Namespace="parent-1",
                MetricName="CpuUsage",
                Unit="%",
                Dimensions=[dict(Dimensions=["InstanceId"])],
            )
        ]
    ),
    "GetZoneSAMLServiceProviderInfo": dict(
        SAMLServiceProvider=dict(
            EntityId="entity-1", ZoneId="parent-1", AcsUrl="https://sso.example.test/acs"
        )
    ),
    "ListExternalSAMLIdPCertificates": dict(
        SAMLIdPCertificates=[
            dict(CertificateId="cert-1", Issuer="Public issuer", Version=3, NotAfter="2027-10-01")
        ],
        TotalCounts=1,
    ),
    "ListCatalog": dict(Data=dict(Items=[dict(Name="catalog-1")], TotalCount=1)),
    "ListDatabase": dict(
        Data=dict(
            Items=[dict(Guid="db-guid", Name="warehouse", CatalogName="catalog-1", DatasourceId=1)],
            TotalCount=1,
        )
    ),
    "ListSchema": dict(
        Data=dict(
            Items=[dict(Guid="schema-guid", Name="public", DatabaseName="warehouse")], TotalCount=1
        )
    ),
    "ListTable": dict(
        Data=dict(
            Items=[
                dict(
                    Guid="table-guid",
                    Name="events",
                    DatabaseName="warehouse",
                    CatalogName="catalog-1",
                    DatasourceId=1,
                    TechnicalMetadata=dict(
                        Owner="team", Location="cosn://bucket/path", StorageSize=100
                    ),
                    BusinessMetadata=dict(TagNames=["audit"]),
                )
            ],
            TotalCount=1,
        )
    ),
    "GetTableColumns": dict(
        Data=[dict(Name="id", Type="bigint", Length=8, Position=1, IsPartition=False)]
    ),
    "ListResourceGroups": dict(
        Data=dict(
            Items=[
                dict(
                    Id="rg-1",
                    Region=REGION,
                    VpcId="vpc-one",
                    SubNet="subnet-one",
                    AssociateProjects=[dict(ProjectId="project-1")],
                )
            ],
            TotalCount=1,
        )
    ),
    "DescribeParamTemplates": dict(
        Items=[dict(TemplateId=1, Name="Template", EngineVersion="8.0")], TotalCount=1
    ),
    "DescribeProxySupportParam": dict(ProxyVersion="1.0", SupportPool=True, PoolMin=1, PoolMax=100),
    "DescribeProxyCustomConf": dict(
        CustomConfInfo=[dict(Device="node-1", Cpu=2, Memory=4096)], Count=1
    ),
    "DescribeSupportedProducts": dict(Products=["Mysql", "PostgreSQL"], TotalCount=2),
}


def node(g, kind, rid="parent-1", region=REGION, owner="100", **props):
    n = g.nodes[g.add(owner, region, kind, rid)]
    n["properties"].update(props)
    return n


def runner(g, call):
    return CollectorRunner(g, SimpleNamespace(call=call), "100", [REGION], lambda _: None)


def parent(g, read):
    if not read.parent:
        return None
    n = node(g, read.parent, "1" if read.service == "dnspod" else "parent-1")
    n["properties"].update(
        ZoneId="zone-1",
        UserProvisioningId="provision-1",
        InstanceId="instance-1",
        parent_resource_id="rg-one",
        OwnerUin=100,
        VulId=1,
        Name="catalog-1" if read.action == "ListDatabase" else "warehouse",
        CatalogName="catalog-1",
        DatasourceId=1,
        Guid="table-guid",
    )
    return n


@pytest.mark.parametrize("read", READS, ids=lambda r: r.service + "." + r.action)
def test_each_platform_operation_with_explicit_native_fixture(read):
    g = Graph()
    p = parent(g, read)
    params = parameters(read, p)
    if read.action == "DescribeComplianceTaskPolicyItemSummaryList":
        params["AssetType"] = "ASSET_CONTAINER"
    data = copy.deepcopy(RESPONSES[read.action])
    data.update(RequestId="request-1", PrivateKey="OMIT", Password="OMIT", Environment="OMIT")
    calls = []

    def call(service, action, region=None, **query):
        calls.append(query)
        assert (service, action) in ACTIONS
        assert all(query[k] == v for k, v in params.items())
        return data

    checked_read(runner(g, call), read, REGION, p, params)
    assert g.coverage[-1]["status"] == "complete", g.coverage
    assert g.coverage[-1]["request_ids"] == ["request-1"]
    assert any(n["kind"] == read.kind for n in g.nodes.values())
    assert "OMIT" not in g.dump()
    validate(g.snapshot())
    assert ACTIONS <= ALLOWED_ACTIONS and KINDS <= DETAIL_KINDS
    assert all(icon_for(k) != "unmapped.svg" for k in KINDS)


@pytest.mark.parametrize(
    "action,key,wrong",
    [
        ("DescribeDeployedResources", "CertificateId", "foreign"),
        ("DescribeVulInfoCvss", "VulId", 2),
        ("DescribeComplianceTaskPolicyItemSummaryList", "AssetType", "ASSET_HOST"),
        ("ListDatabase", "CatalogName", "foreign"),
        ("DescribeBaseMetrics", "Namespace", "foreign"),
        ("DescribeAudit", "AuditName", "foreign"),
    ],
)
def test_foreign_response_scope_is_rejected_before_publication(action, key, wrong):
    from tencent_cloud_cartography.transport import path_value

    g = Graph()
    r = next(r for r in READS if r.action == action)
    p = parent(g, r)
    params = parameters(r, p)
    if action == "DescribeComplianceTaskPolicyItemSummaryList":
        params["AssetType"] = "ASSET_CONTAINER"
    data = copy.deepcopy(RESPONSES[action])
    rows = path_value(data, r.result) if r.result else [data]
    rows[0][key] = wrong
    before = set(g.nodes)
    checked_read(runner(g, lambda *a, **k: data), r, REGION, p, params)
    assert g.coverage[-1]["status"] == "error" and set(g.nodes) == before


def test_links_do_not_merge_ambiguous_foreign_owners_or_regions():
    g = Graph()
    cert = node(g, "ssl.deploymentview", ResourceIds=json.dumps(["lb-one"]), Type="clb")
    node(g, "clb.clb", "lb-one", owner="200")
    a = node(g, "clb.clb", "lb-one")
    link(g)
    assert any(e["source"] == cert["id"] and e["target"] == a["id"] for e in g.edges.values())
    node(g, "clb.clb", "lb-one", region="ap-guangzhou")
    link(g)
    assert not any(e["source"] == cert["id"] for e in g.edges.values())
    assert not cert["properties"].get("effective_access_verified")


def test_aggregate_delivery_and_legacy_audit_are_configuration_only():
    g = Graph()
    target = node(g, "cos.bucket", "config-12345", owner="200")
    wrong = node(g, "cos.bucket", "config-12345", owner="300")
    d = node(
        g,
        "config.aggregatedelivery",
        DeliverType="COS",
        TargetArn=f"qcs::cos:{REGION}:uid/12345:config-12345",
        DeliverUin=200,
    )
    member = node(g, "organization.member", "200", region="global")
    a = node(
        g, "config.aggregatorconfiguration", AggregatorAccounts=json.dumps([dict(MemberUin=200)])
    )
    link(g)
    assert any(e["source"] == d["id"] and e["target"] == target["id"] for e in g.edges.values())
    assert not any(e["source"] == d["id"] and e["target"] == wrong["id"] for e in g.edges.values())
    assert any(e["source"] == a["id"] and e["target"] == member["id"] for e in g.edges.values())
    assert d["properties"]["delivery_verified"] is False
    before = g.dump()
    link(g)
    assert g.dump() == before


def test_tcaplus_tag_reads_keep_exact_cluster_scope_and_offline_parent_links():
    from tencent_cloud_cartography.platform_metadata import collect_tcaplus_tags

    g = Graph()
    cluster = node(g, "tcaplusdb.cluster", "123")
    group = node(g, "tcaplusdb.tablegroup", "group-key", TableGroupId="1")
    node(
        g,
        "tcaplusdb.tablereference",
        "table-key",
        ClusterId="123",
        TableGroupId="1",
        TableName="events",
    )
    g.edge(cluster["id"], group["id"], "HAS_METADATA", "fixture")

    def call(service, action, region=None, **params):
        assert service == "tcaplusdb"
        if action == "DescribeClusterTags":
            assert params == dict(ClusterIds=["123"])
            row = dict(ClusterId="123")
        elif action == "DescribeTableGroupTags":
            assert params == dict(ClusterId="123", TableGroupIds=["1"])
            row = dict(ClusterId="123", TableGroupId="1")
        else:
            assert action == "DescribeTableTags" and params == dict(
                ClusterId="123", SelectedTables=[dict(TableGroupId="1", TableName="events")]
            )
            row = dict(TableGroupId="1", TableName="events", TableInstanceId="table-1")
        return dict(Rows=[dict(**row, Tags=[dict(TagKey="team", TagValue="audit")])], TotalCount=1)

    collect_tcaplus_tags(runner(g, call))
    assert all(r["status"] == "complete" for r in g.coverage)
    assert len([e for e in g.edges.values() if e["relationship"] == "HAS_TAG_METADATA"]) == 3
    link(g)
    assert len([e for e in g.edges.values() if e["relationship"] == "HAS_TAG_METADATA"]) == 3
    before = g.dump()
    link(g)
    assert g.dump() == before


@pytest.mark.parametrize(
    "identity,resolved",
    [
        (f"qcs::scf:{REGION}:uin/100:namespace/team/function/evaluate", True),
        (f"qcs::scf:{REGION}:uin/200:namespace/team/function/evaluate", False),
        (f"qcs::scf:{REGION}:uin/100:namespace/other/function/evaluate", False),
        (f"qcs::scf:{REGION}:uin/100:function/team/evaluate", False),
        ("evaluate", False),
    ],
)
def test_custom_config_function_requires_documented_canonical_identity(identity, resolved):
    g = Graph()
    rule = node(g, "config.rule", "cr-one", region="global", ServiceFunction=identity)
    fn = node(g, "scf.function", "lam-one", Namespace="team")
    fn["name"] = "evaluate"
    link(g)
    edges = [
        e
        for e in g.edges.values()
        if e["source"] == rule["id"] and e["relationship"] == "CONFIGURED_EVALUATION_FUNCTION"
    ]
    assert bool(edges) is resolved
    if edges:
        assert edges[0]["target"] == fn["id"]


def test_wedata_group_requires_native_region_and_retains_subnet_reference():
    read = next(r for r in READS if r.action == "ListResourceGroups")
    for region in (REGION, "ap-guangzhou"):
        g = Graph()
        data = copy.deepcopy(RESPONSES[read.action])
        data["Data"]["Items"][0]["Region"] = region
        checked_read(runner(g, lambda *a, **k: data), read, REGION, None, {})
        link(g)
        if region == REGION:
            assert any(e["relationship"] == "IN_SUBNET" for e in g.edges.values())
        else:
            assert not g.nodes and g.coverage[-1]["error"] == "WeDataResourceGroupRegionMismatch"


def test_compliance_summary_cannot_add_unrequested_asset_class():
    g = Graph()
    read = next(r for r in READS if r.action == "DescribeComplianceTaskAssetSummary")
    checked_read(
        runner(g, lambda *a, **k: RESPONSES[read.action]),
        read,
        "global",
        None,
        dict(AssetTypeSet=["ASSET_HOST"]),
    )
    assert not g.nodes and g.coverage[-1]["error"] == "AssessmentAssetTypeMismatch"
