"""Provider configuration and reported security posture, without workload content."""

import json
import re

from .data_metadata import Read, collect_read, schema
from .platform_dns import ACTIONS as DNS_ACTIONS
from .platform_dns import KINDS as DNS_KINDS
from .transport import CollectionError, path_value

TAGS = schema("TagKey TagValue")
VPC = schema("UniqVpcId Region")
ENDPOINT_SERVICE = schema(
    "EndPointVip UniqSubnetId EndPointRemark", "EndPointState EndPointStatus EndPointIsolateFlag"
)
COMPLIANCE_TYPES = ("ASSET_CONTAINER", "ASSET_IMAGE", "ASSET_HOST", "ASSET_K8S")

RESOURCE_INFO = schema(
    "GpuType", "Cpu Memory Gpu RealGpu RdmaNumber RootDisk DataDisk Rdma", "EnableRDMA"
)
READS = (
    Read(
        "tione",
        "DescribeBillingResourceGroup",
        "tione.resourceinstance",
        schema(
            "InstanceId InstanceStatus SubUin CreateTime ExpireTime AutoRenewFlag SpecId SpecAlias CvmInstanceId InstanceIP InstanceName CvmInstanceType ZoneName",
            booleans="AutoRenew Isolated",
            arrays="SpecFeatures",
            UsedResource=RESOURCE_INFO,
            TotalResource=RESOURCE_INFO,
            AvailableResource=RESOURCE_INFO,
        ),
        "InstanceSet",
        ("InstanceId",),
        "TotalCount",
        "offset",
        parent="tione.resourcegroup",
        argument="ResourceGroupId",
    ),
    Read(
        "tione",
        "DescribeBillingResourceInstanceRunningJobs",
        "tione.runningjob",
        schema("PodName TaskType TaskId TaskName"),
        "ResourceInstanceRunningJobInfos",
        ("PodName", "TaskId"),
        parent="tione.resourceinstance",
        argument="ResourceInstanceId",
    ),
    Read(
        "lke",
        "DescribeKnowledgeUsage",
        "lke.knowledgequota",
        schema("AvailableCharSize ExceedCharSize UsedCharSize"),
    ),
    Read(
        "organization",
        "GetUserSyncProvisioning",
        "organization.cicusersyncdetail",
        schema(
            UserProvisioning=schema(
                "UserProvisioningId Description Status PrincipalId PrincipalName PrincipalType TargetName DuplicationStrategy DeletionStrategy CreateTime UpdateTime TargetType",
                "TargetUin",
            )
        ),
        parent="organization.cicusersync",
        argument="UserProvisioningId",
    ),
    Read(
        "privatedns",
        "DescribeForwardRuleList",
        "privatedns.forwardrule",
        schema(
            "Domain RuleName RuleId RuleType CreatedAt UpdatedAt EndPointName EndPointId ZoneId",
            arrays="ForwardAddress",
            VpcSet=[VPC],
        ),
        "ForwardRuleSet",
        ("RuleId",),
        "TotalCount",
        "offset",
    ),
    Read(
        "privatedns",
        "DescribeInboundEndpointList",
        "privatedns.inboundendpoint",
        schema(
            "EndPointId EndPointName UniqVpcId CreatedAt UpdatedAt",
            EndPointService=[ENDPOINT_SERVICE],
        ),
        "InboundEndpointSet",
        ("EndPointId",),
        "TotalCount",
        "offset",
    ),
    Read(
        "dnspod",
        "DescribeDomainAliasList",
        "dnspod.alias",
        schema("DomainAlias", "Id Status"),
        "DomainAliasList",
        ("Id",),
        parent="dnspod.domain",
        argument="DomainId",
    ),
    Read(
        "dnspod",
        "DescribeDomainShareUserList",
        "dnspod.sharegrant",
        schema("Mode Nickname QCloudUIN Status SubDomain", "DomainShareId"),
        "DomainShareList",
        ("DomainShareId",),
        parent="dnspod.domain",
        argument="DomainId",
    ),
    Read(
        "ssl",
        "DescribeDeployedResources",
        "ssl.deploymentview",
        schema("CertificateId Type", "Count", arrays="ResourceIds Resources"),
        "DeployedResources",
        ("CertificateId", "Type"),
        parent="ssl.certificate",
        argument="CertificateIds",
    ),
    Read(
        "cwp",
        "DescribeScanVulSetting",
        "cwp.vulnerabilityscansettings",
        schema(
            "VulCategories VulLevels TimerTime StartTime EndTime",
            "TimerInterval VulEmergency EnableScan ClickTimeout ScanMethod",
            arrays="Uuids",
        ),
    ),
    Read(
        "cwp",
        "DescribeMalwareTimingScanSetting",
        "cwp.malwarescansettings",
        schema(
            "StartTime EndTime",
            "CheckPattern IsGlobal MonitoringPattern Cycle EnableScan Id RealTimeMonitoring AutoIsolation ClickTimeout KillProcess EngineType EnableInspiredEngine EnableMemShellScan ProtectMode ProtectFileScope DoClean QuaraScope",
            arrays="CustomPaths QuuidList MonitorCustomPaths QuaraUuids",
        ),
    ),
    Read(
        "cwp",
        "DescribeOverviewStatistics",
        "cwp.posturesummary",
        schema(
            integers="OnlineMachineNum ProVersionMachineNum MalwareNum NonlocalLoginNum BruteAttackSuccessNum VulNum BaseLineNum"
        ),
    ),
    Read(
        "cwp",
        "DescribeVulInfoCvss",
        "cwp.vulnerabilitydefinition",
        schema(
            "VulName Description RepairPlan CveId Reference CVSS PublicDate CveInfo Labels",
            "VulId VulLevel VulType CvssScore DefenseAttackCount SuccessFixCount FixSwitch SupportDefence",
            floats="CvssScoreFloat",
        ),
        parent="cwp.vulnerability",
        argument="VulId",
    ),
    Read(
        "tcss",
        "DescribeAssetSummary",
        "tcss.assessmentcoverage",
        schema(
            "CreateTime LatestImageScanTime",
            "AppCnt ContainerCnt ContainerPause ContainerRunning ContainerStop DbCnt ImageCnt HostOnline HostCnt ImageHasRiskInfoCnt ImageHasVirusCnt ImageHasVulsCnt ImageUntrustCnt ListenPortCnt ProcessCnt WebServiceCnt ImageUnsafeCnt HostUnInstallCnt SuperNodeCnt SuperNodeRunningCnt TodayNewImageCnt TodayUnsafeImageCnt RecommendedFixImageCnt ScannedImageCnt UnScannedImageCnt",
        ),
    ),
    Read(
        "tcss",
        "DescribeAssetImageScanSetting",
        "tcss.imagescansettings",
        schema(
            "ScanTime ScanEndTime LastScanTime ScanResult",
            "ScanPeriod ScanScope",
            "Enable ScanVirus ScanRisk ScanVul All ContainerRunning",
            "Images ExcludeImages ClusterIDs",
        ),
    ),
    Read(
        "tcss",
        "DescribeVirusScanSetting",
        "tcss.virusscansettings",
        schema(
            "BeginScanAt ScanPathMode",
            "Cycle ScanPathType Timeout ScanRangeType ClickTimeout",
            "EnableScan ScanPathAll ScanRangeAll",
            "ScanIds ScanPath",
        ),
    ),
    Read(
        "tcss",
        "DescribeComplianceTaskAssetSummary",
        "tcss.compliancecoverage",
        schema(
            "AssetType CheckStatus LastCheckTime",
            "PassedPolicyItemCount FailedPolicyItemCount FailedCriticalPolicyItemCount FailedHighRiskPolicyItemCount FailedMediumRiskPolicyItemCount FailedLowRiskPolicyItemCount NoticePolicyItemCount PassedAssetCount FailedAssetCount ScanFailedAssetCount OpenPolicyItemCount IgnoredPolicyItemCount TotalPolicyItemCount DetectHostCount LeftTime",
            "IsCustomerFirstCheck",
            floats="CheckProgress AssetPassedRate CheckCostTime",
        ),
        "AssetSummaryList",
        ("AssetType",),
    ),
    Read(
        "tcss",
        "DescribeComplianceTaskPolicyItemSummaryList",
        "tcss.complianceitem",
        schema(
            "Name Category BenchmarkStandardName RiskLevel AssetType LastCheckTime CheckStatus CheckResult FixSuggestion ApplicableVersion Description AuditProcedure",
            "CustomerPolicyItemId BasePolicyItemId PassedAssetCount FailedAssetCount WhitelistId BenchmarkStandardId IsEnable",
        ),
        "PolicyItemSummaryList",
        ("CustomerPolicyItemId",),
        "TotalCount",
        "offset",
    ),
    Read(
        "csip",
        "DescribeRiskScanCronConfig",
        "csip.riskscansettings",
        schema(
            CronConfig=schema(
                "PlanContent ScanPlanTimezone",
                "CreateAppID CronStatus",
                "AddRuleEnableStatus IncrementAssetScanRisk",
            )
        ),
    ),
    Read(
        "csip",
        "DescribeVulScanPeriodic",
        "csip.vulnerabilityscansettings",
        schema(
            "Method StartTime EndTime",
            "Status CycleType AssetRange Timeout AllowSync EnableSync",
            arrays="VulCategory Level AssetList",
        ),
    ),
    Read(
        "csip",
        "DescribeAssetOverview",
        "csip.assessmentcoverage",
        schema(
            AssetOverview=schema(
                integers="AssetTotalCount AssetAddCount RiskAssetCount AlarmAssetCount PublicAssetCount ExposeAssetCount CloudHostAssetCount"
            )
        ),
    ),
    Read(
        "csip",
        "DescribeComplianceOverview",
        "csip.compliancecoverage",
        schema(
            AllCheckItems=schema(integers="TotalCount PassRate"),
            Standards=[schema("Name", "ID TotalCount PassRate")],
        ),
    ),
    Read(
        "csip",
        "DescribeRiskRules",
        "csip.riskdefinition",
        schema(
            "ItemId Provider InstanceType InstanceName RiskTitle CheckType Severity RiskInfluence"
        ),
        "RiskRuleList",
        ("ItemId",),
        "TotalCount",
        "offset",
    ),
    Read(
        "config",
        "ListAggregators",
        "config.aggregatorview",
        schema(
            "Name Description CreateTime Type AccountGroupId MemberName",
            "OwnerUin AccountCount AggregatorStatus",
        ),
        "Items",
        ("AccountGroupId",),
        "Total",
        "offset",
    ),
    Read(
        "config",
        "DescribeAggregator",
        "config.aggregatorconfiguration",
        schema(
            "Name Description Type",
            "AggregatorStatus",
            AggregatorAccounts=[schema("MemberName", "MemberUin")],
        ),
        parent="config.aggregatorview",
        argument="AccountGroupId",
    ),
    Read(
        "config",
        "DescribeAggregateConfigDeliver",
        "config.aggregatedelivery",
        schema(
            "DeliverName TargetArn CreateTime DeliverPrefix DeliverType",
            "Status DeliverUin DeliverContentType",
        ),
        parent="config.aggregatorview",
        argument="AccountGroupId",
    ),
    Read(
        "cloudaudit",
        "ListAudits",
        "cloudaudit.legacyaudit",
        schema("AuditName CosBucketName LogFilePrefix", "AuditStatus"),
        "AuditSummarys",
        ("AuditName",),
    ),
    Read(
        "cloudaudit",
        "DescribeAudit",
        "cloudaudit.legacyconfiguration",
        schema(
            "AuditName KeyId CosRegion CmqQueueName KmsAlias KmsRegion CosBucketName CmqRegion LogFilePrefix",
            "IsEnableCmqNotify ReadWriteAttribute AuditStatus IsEnableKmsEncry",
        ),
        parent="cloudaudit.legacyaudit",
        argument="AuditName",
    ),
    Read(
        "monitor",
        "DescribeProductList",
        "monitor.productnamespace",
        schema("Namespace ProductName ProductEnName"),
        "ProductList",
        ("Namespace",),
        "TotalCount",
        "offset",
    ),
    Read(
        "monitor",
        "DescribeBaseMetrics",
        "monitor.metricdefinition",
        schema(
            "Namespace MetricName Unit UnitCname MetricCName MetricEName",
            Dimensions=[schema(arrays="Dimensions")],
        ),
        "MetricSet",
        ("MetricName",),
        parent="monitor.productnamespace",
        argument="Namespace",
    ),
    Read(
        "organization",
        "GetZoneSAMLServiceProviderInfo",
        "organization.cicserviceprovider",
        schema(SAMLServiceProvider=schema("EntityId ZoneId AcsUrl")),
        parent="organization.ciczone",
        argument="ZoneId",
    ),
    Read(
        "organization",
        "ListExternalSAMLIdPCertificates",
        "organization.cicidpcertificate",
        schema(
            "SerialNumber Issuer CertificateId SignatureAlgorithm NotAfter NotBefore Subject",
            "Version",
        ),
        "SAMLIdPCertificates",
        ("CertificateId",),
        "TotalCounts",
        parent="organization.ciczone",
        argument="ZoneId",
    ),
    Read(
        "wedata",
        "ListCatalog",
        "wedata.catalog",
        schema("Name"),
        "Data.Items",
        ("Name",),
        "Data.TotalCount",
        "number-page",
    ),
    Read(
        "wedata",
        "ListDatabase",
        "wedata.database",
        schema(
            "Guid Name CatalogName Description Location DatasourceType", "StorageSize DatasourceId"
        ),
        "Data.Items",
        ("Guid",),
        "Data.TotalCount",
        "number-page",
        parent="wedata.catalog",
        argument="CatalogName",
    ),
    Read(
        "wedata",
        "ListSchema",
        "wedata.schema",
        schema("Guid Name DatabaseName"),
        "Data.Items",
        ("Guid",),
        "Data.TotalCount",
        "number-page",
        parent="wedata.database",
        argument="DatabaseName",
    ),
    Read(
        "wedata",
        "ListTable",
        "wedata.table",
        schema(
            "Guid Name Description DatabaseName SchemaName TableType CreateTime UpdateTime CatalogName DatasourceType",
            "DatasourceId",
            TechnicalMetadata=schema("Owner Location", "StorageSize"),
            BusinessMetadata=schema(arrays="TagNames"),
        ),
        "Data.Items",
        ("Guid",),
        "Data.TotalCount",
        "number-page",
        parent="wedata.database",
        argument="DatabaseName",
    ),
    Read(
        "wedata",
        "GetTableColumns",
        "wedata.column",
        schema("Type Name Description", "Length Position", "IsPartition"),
        "Data",
        ("Name",),
        parent="wedata.table",
        argument="TableGuid",
    ),
    Read(
        "wedata",
        "ListResourceGroups",
        "wedata.resourcegroup",
        schema(
            "Id Name Description ResourceGroupType Region VpcId SubNet",
            booleans="AutoRenewEnabled",
            AssociateProjects=[schema("ProjectId ProjectName")],
        ),
        "Data.Items",
        ("Id",),
        "Data.TotalCount",
        "number-page",
    ),
    Read(
        "cdb",
        "DescribeParamTemplates",
        "cdb.parametertemplate",
        schema("Name Description EngineVersion TemplateType EngineType", "TemplateId"),
        "Items",
        ("TemplateId",),
        "TotalCount",
    ),
    Read(
        "cdb",
        "DescribeProxySupportParam",
        "cdb.proxycapabilities",
        schema(
            "ProxyVersion SupportPoolMinVersion SupportTransSplitMinVersion",
            "PoolMin PoolMax",
            "SupportPool SupportTransSplit SupportReadOnly SupportAutoLoadBalance SupportAccessMode",
        ),
        parent="cdb.instance",
    ),
    Read(
        "cdb",
        "DescribeProxyCustomConf",
        "cdb.proxyconfiguration",
        schema("Device Type DeviceType", "Memory Cpu"),
        "CustomConfInfo",
        total="Count",
        paging="offset",
        parent="cdb.instance",
    ),
    Read(
        "ssm",
        "DescribeSupportedProducts",
        "ssm.supportedproducts",
        schema("", "TotalCount", arrays="Products"),
    ),
)
ACTIONS_EXTRA = {
    ("tcaplusdb", "DescribeClusterTags"),
    ("tcaplusdb", "DescribeTableGroupTags"),
    ("tcaplusdb", "DescribeTableTags"),
}
KINDS_EXTRA = {"tcaplusdb.clustertags", "tcaplusdb.tablegrouptags", "tcaplusdb.tabletags"}

GLOBAL = {"privatedns", "dnspod", "ssl", "tcss", "csip", "config", "monitor", "organization"}
ACTIONS = {(r.service, r.action) for r in READS} | ACTIONS_EXTRA | DNS_ACTIONS
KINDS = {r.kind for r in READS} | KINDS_EXTRA | DNS_KINDS


def parents(runner, read, region):
    return [
        n
        for n in list(runner.graph.nodes.values())
        if n["account"] == runner.account
        and n["region"] == region
        and n["kind"] == read.parent
        and n["status"] == "enriched"
    ]


def parameters(read, parent):
    p = parent["properties"] if parent else {}
    result = {read.argument: parent["resource_id"]} if parent else {}
    if read.action == "DescribeBillingResourceInstanceRunningJobs":
        result = dict(ResourceGroupId=p["parent_resource_id"], ResourceInstanceId=p["InstanceId"])
    elif read.action == "GetUserSyncProvisioning":
        result = dict(ZoneId=p["ZoneId"], UserProvisioningId=p["UserProvisioningId"])
    elif read.service == "dnspod":
        result = dict(DomainId=int(parent["resource_id"]))
    elif read.action == "DescribeDeployedResources":
        result = dict(CertificateIds=[parent["resource_id"]])
    elif read.action == "DescribeVulInfoCvss":
        result = dict(VulId=p["VulId"], Source="cwp")
    elif read.action == "DescribeComplianceTaskAssetSummary":
        result = dict(AssetTypeSet=list(COMPLIANCE_TYPES))
    elif read.action == "DescribeProductList":
        result["Module"] = "monitor"
    elif read.action == "DescribeAggregator":
        if type(p.get("OwnerUin")) is not int or p["OwnerUin"] <= 0:
            raise CollectionError("UnknownAggregatorOwner")
        result["OwnerUin"] = p["OwnerUin"]
    elif read.service == "wedata" and parent:
        if read.action == "ListDatabase":
            result = dict(CatalogName=p["Name"])
        elif read.action in {"ListSchema", "ListTable"}:
            result = dict(
                CatalogName=p["CatalogName"], DatasourceId=p["DatasourceId"], DatabaseName=p["Name"]
            )
        elif read.action == "GetTableColumns":
            result = dict(TableGuid=p["Guid"])
    return result


def collect(runner, services=None):
    if not services or "dnspod" in services:
        from .platform_dns import collect_shared

        collect_shared(runner)
    for read in READS:
        if services and read.service not in services:
            continue
        regions = ["global"] if read.service in GLOBAL else runner.regions_for(read.service)
        for region in regions:
            for parent in parents(runner, read, region) if read.parent else [None]:
                try:
                    params = parameters(read, parent)
                except (ValueError, TypeError, KeyError, CollectionError):

                    def invalid(record):
                        raise CollectionError("MissingPlatformMetadataScope")

                    runner.scope(
                        read.service,
                        read.action,
                        region,
                        invalid,
                        parent["resource_id"] if parent else "",
                    )
                    continue
                for asset_type in (
                    COMPLIANCE_TYPES
                    if read.action == "DescribeComplianceTaskPolicyItemSummaryList"
                    else [None]
                ):
                    selected = {**params, "AssetType": asset_type} if asset_type else params
                    checked_read(runner, read, region, parent, selected)
    if not services or "tcaplusdb" in services:
        collect_tcaplus_tags(runner)
    link(runner.graph)


def link(graph):
    from .platform_dns import link as link_dns

    link_dns(graph)
    from .monitor import link_bindings

    link_bindings(graph)
    source = "analysis.platform-metadata-links"
    graph.edges = {i: e for i, e in graph.edges.items() if e.get("provenance") != source}
    for n in list(graph.nodes.values()):
        p = n["properties"]
        if n["kind"].startswith(("csip.", "cwp.", "tcss.")):
            p.update(
                evidence_scope="vendor_reported_configuration_or_metadata",
                independently_validated=False,
            )
        if n["kind"] in KINDS_EXTRA:
            parent = graph.nodes.get(p.get("tag_parent_node_id"))
            if parent and (
                parent["account"],
                parent["region"],
                parent["kind"],
                parent["resource_id"],
            ) == (
                n["account"],
                n["region"],
                p.get("tag_parent_kind"),
                p.get("tag_parent_resource_id"),
            ):
                graph.edge(parent["id"], n["id"], "HAS_TAG_METADATA", source)
        elif n["kind"] == "tione.resourceinstance":
            p["running_job_inventory_scope"] = "current_jobs_in_collected_billing_pool_only"
            matches = [
                t
                for t in graph.nodes.values()
                if t["kind"] == "cvm.instance"
                and t["resource_id"] == p.get("CvmInstanceId")
                and t["account"] == n["account"]
                and t["region"] == n["region"]
                and t["status"] == "enriched"
            ]
            if len(matches) == 1:
                graph.edge(n["id"], matches[0]["id"], "USES_RESOURCE_INSTANCE", source)
        elif n["kind"] in {"lke.model", "lke.knowledgequota"}:
            p.update(
                owned_hunyuan_asset_census_complete=False,
                runtime_entitlement_verified=False,
                entitlement_scope="provider_reported_catalog_or_quota",
            )
        elif n["kind"] == "ssl.deploymentview":
            ids = json.loads(p.get("Resources", "[]")) or json.loads(p.get("ResourceIds", "[]"))
            kind = {
                "clb": "clb.clb",
                "cdn": "cdn.domain",
                "cos": "cos.bucket",
                "tke": "tke.cluster",
                "apigateway": "apigateway.service",
                "lighthouse": "lighthouse.instance",
            }.get(p.get("Type", "").lower())
            for rid in ids:
                matches = [
                    t
                    for t in graph.nodes.values()
                    if t["kind"] == kind
                    and t["resource_id"] == rid
                    and t["account"] == n["account"]
                    and t["status"] == "enriched"
                ]
                if len(matches) == 1:
                    graph.edge(n["id"], matches[0]["id"], "DEPLOYED_TO_RESOURCE", source)
        elif n["kind"] == "wedata.resourcegroup":
            if re.fullmatch(r"subnet-[a-zA-Z0-9]+", p.get("SubNet", "")):
                sid = graph.add(
                    n["account"],
                    n["region"],
                    "vpc.subnet",
                    p["SubNet"],
                    status="reference",
                    source=source,
                )
                graph.edge(n["id"], sid, "IN_SUBNET", source)
            for project in json.loads(p.get("AssociateProjects", "[]")):
                matches = [
                    t
                    for t in graph.nodes.values()
                    if t["kind"] == "wedata.project"
                    and t["account"] == n["account"]
                    and t["region"] == n["region"]
                    and t["resource_id"] == project.get("ProjectId")
                ]
                if len(matches) == 1:
                    graph.edge(n["id"], matches[0]["id"], "ASSOCIATED_PROJECT", source)
        elif n["kind"] == "config.rule" and p.get("ServiceFunction"):
            # Only an explicit canonical SCF identity can establish the binding.
            match = re.fullmatch(
                r"qcs::scf:([a-z]+-[a-z0-9-]+):uin/([1-9][0-9]*):namespace/([^/]+)/function/([^/]+)",
                p["ServiceFunction"],
            )
            if match:
                region, owner, namespace, name = match.groups()
                candidates = [
                    t
                    for t in graph.nodes.values()
                    if t["kind"] == "scf.function"
                    and t["account"] == owner
                    and t["region"] == region
                    and t["properties"].get("Namespace") == namespace
                    and t["name"] == name
                ]
                if len(candidates) == 1:
                    graph.edge(
                        n["id"], candidates[0]["id"], "CONFIGURED_EVALUATION_FUNCTION", source
                    )
        elif n["kind"] == "config.aggregatorconfiguration":
            p.update(
                aggregate_role_metadata_available=False,
                aggregate_encryption_metadata_available=False,
                compliance_independently_verified=False,
            )
            for member in json.loads(p.get("AggregatorAccounts", "[]")):
                if type(member.get("MemberUin")) is int and member["MemberUin"] > 0:
                    matches = [
                        t
                        for t in graph.nodes.values()
                        if t["kind"] == "organization.member"
                        and t["account"] == n["account"]
                        and t["resource_id"] == str(member["MemberUin"])
                    ]
                    if len(matches) == 1:
                        graph.edge(n["id"], matches[0]["id"], "AGGREGATES_ACCOUNT_METADATA", source)
        elif n["kind"] == "config.aggregatedelivery":
            from .cloudconfig import cos_target

            p["delivery_verified"] = False
            if p.get("DeliverType", "").lower() == "cos":
                parsed = cos_target(p.get("TargetArn", ""))
                matches = [
                    t
                    for t in graph.nodes.values()
                    if parsed
                    and t["kind"] == "cos.bucket"
                    and t["region"] == parsed[0]
                    and t["resource_id"] == parsed[1]
                    and type(p.get("DeliverUin")) is int
                    and t["account"] == str(p["DeliverUin"])
                ]
                if len(matches) == 1:
                    graph.edge(n["id"], matches[0]["id"], "CONFIGURED_LOG_DESTINATION", source)
        elif n["kind"] == "cloudaudit.legacyconfiguration":
            p.update(
                delivery_verified=False,
                delivery_validation_scope="configuration_only_no_log_or_probe",
            )
            matches = [
                t
                for t in graph.nodes.values()
                if t["kind"] == "cos.bucket"
                and t["resource_id"] == p.get("CosBucketName")
                and t["region"] == p.get("CosRegion")
                and t["status"] == "enriched"
            ]
            if len(matches) == 1:
                graph.edge(n["id"], matches[0]["id"], "CONFIGURED_LOG_DESTINATION", source)
            from .kms import KEY_ID

            if (
                p.get("IsEnableKmsEncry") == 1
                and KEY_ID.fullmatch(p.get("KeyId", ""))
                and re.fullmatch(r"[a-z]+-[a-z0-9-]+", p.get("KmsRegion", ""))
            ):
                key = graph.add(
                    n["account"],
                    p["KmsRegion"],
                    "kms.key",
                    p["KeyId"],
                    status="reference",
                    source=source,
                )
                graph.edge(n["id"], key, "CONFIGURED_ENCRYPTION_KEY", source)


def collect_tcaplus_tags(runner):
    """Read tags for already identified clusters/groups/tables, never IDL/passwords."""
    reads = {
        "tcaplusdb.cluster": Read(
            "tcaplusdb",
            "DescribeClusterTags",
            "tcaplusdb.clustertags",
            schema("ClusterId", Tags=[schema("TagKey TagValue")]),
            "Rows",
            ("ClusterId",),
            "TotalCount",
        ),
        "tcaplusdb.tablegroup": Read(
            "tcaplusdb",
            "DescribeTableGroupTags",
            "tcaplusdb.tablegrouptags",
            schema("ClusterId TableGroupId", Tags=[schema("TagKey TagValue")]),
            "Rows",
            ("TableGroupId",),
            "TotalCount",
        ),
        "tcaplusdb.tablereference": Read(
            "tcaplusdb",
            "DescribeTableTags",
            "tcaplusdb.tabletags",
            schema("TableInstanceId TableName TableGroupId", Tags=[schema("TagKey TagValue")]),
            "Rows",
            ("TableGroupId", "TableName"),
            "TotalCount",
        ),
    }
    for parent in list(runner.graph.nodes.values()):
        if (
            parent["account"] != runner.account
            or parent["kind"] not in reads
            or parent["region"] not in runner.regions_for("tcaplusdb")
        ):
            continue
        read = reads[parent["kind"]]
        p = parent["properties"]
        if parent["kind"] == "tcaplusdb.cluster":
            if not parent["resource_id"].isdigit():
                continue
            params = dict(ClusterIds=[parent["resource_id"]])
        elif parent["kind"] == "tcaplusdb.tablereference":
            params = dict(
                ClusterId=p["ClusterId"],
                SelectedTables=[dict(TableGroupId=p["TableGroupId"], TableName=p["TableName"])],
            )
        else:
            clusters = [
                runner.graph.nodes[e["source"]]
                for e in runner.graph.edges.values()
                if e["target"] == parent["id"]
                and runner.graph.nodes[e["source"]]["kind"] == "tcaplusdb.cluster"
            ]
            if len(clusters) != 1 or not p.get("TableGroupId"):
                continue
            params = dict(ClusterId=clusters[0]["resource_id"], TableGroupIds=[p["TableGroupId"]])
        checked_read(runner, read, parent["region"], None, params)
        # The query was constrained to this exact native identity; link its tag
        # view without using the generic InstanceId-parent validation for groups.
        for tag in list(runner.graph.nodes.values()):
            tp = tag["properties"]
            if (
                tag["kind"] != read.kind
                or tag["account"] != parent["account"]
                or tag["region"] != parent["region"]
            ):
                continue
            matches = (
                tp.get("ClusterId") == parent["resource_id"]
                if parent["kind"] == "tcaplusdb.cluster"
                else tp.get("query_cluster_id") == params["ClusterId"]
                and tp.get("TableGroupId") == p.get("TableGroupId")
                and (
                    parent["kind"] != "tcaplusdb.tablereference"
                    or tp.get("TableName") == p.get("TableName")
                )
            )
            if matches:
                tp.update(
                    tag_parent_node_id=parent["id"],
                    tag_parent_kind=parent["kind"],
                    tag_parent_resource_id=parent["resource_id"],
                )
                runner.graph.edge(
                    parent["id"], tag["id"], "HAS_TAG_METADATA", "tcaplusdb." + read.action
                )


def checked_read(runner, read, region, parent, params):
    from .collect import CollectorRunner

    class ScopedTransport:
        def call(self, service, action, region=None, **query):
            data = runner.transport.call(service, action, region, **query)
            rows = path_value(data, read.result) if read.result else [data]
            if not isinstance(rows, list):
                raise CollectionError("InvalidPlatformMetadata")
            for row in rows:
                if not isinstance(row, dict):
                    raise CollectionError("InvalidPlatformMetadata")
                if (
                    action == "DescribeDeployedResources"
                    and row.get("CertificateId") not in query["CertificateIds"]
                ):
                    raise CollectionError("CertificateDeploymentScopeMismatch")
                if action == "DescribeVulInfoCvss" and row.get("VulId") != query["VulId"]:
                    raise CollectionError("VulnerabilityDefinitionMismatch")
                if (
                    action == "DescribeComplianceTaskPolicyItemSummaryList"
                    and row.get("AssetType") != query["AssetType"]
                ):
                    raise CollectionError("AssessmentAssetTypeMismatch")
                if action == "GetZoneSAMLServiceProviderInfo" and (
                    not isinstance(row.get("SAMLServiceProvider"), dict)
                    or row["SAMLServiceProvider"].get("ZoneId") != query["ZoneId"]
                ):
                    raise CollectionError("IdentityCenterServiceProviderScopeMismatch")
                if action == "GetUserSyncProvisioning" and (
                    not isinstance(row.get("UserProvisioning"), dict)
                    or row["UserProvisioning"].get("UserProvisioningId")
                    != query["UserProvisioningId"]
                ):
                    raise CollectionError("IdentityCenterProvisioningScopeMismatch")
                if action == "DescribeAudit" and row.get("AuditName") != query["AuditName"]:
                    raise CollectionError("LegacyAuditIdentityMismatch")
                if action == "DescribeBaseMetrics" and row.get("Namespace") != query["Namespace"]:
                    raise CollectionError("MetricNamespaceMismatch")
                if (
                    action == "DescribeComplianceTaskAssetSummary"
                    and row.get("AssetType") not in query["AssetTypeSet"]
                ):
                    raise CollectionError("AssessmentAssetTypeMismatch")
                if service == "wedata":
                    if action == "ListResourceGroups" and row.get("Region") not in (
                        None,
                        "",
                        region,
                    ):
                        raise CollectionError("WeDataResourceGroupRegionMismatch")
                    for key in ("CatalogName", "DatasourceId", "DatabaseName"):
                        if key in query and row.get(key) is not None and row[key] != query[key]:
                            raise CollectionError("WeDataMetadataScopeMismatch")
                if service == "tcaplusdb":
                    if (
                        action == "DescribeClusterTags"
                        and row.get("ClusterId") not in query["ClusterIds"]
                    ):
                        raise CollectionError("TcaplusTagScopeMismatch")
                    if action == "DescribeTableGroupTags" and (
                        row.get("ClusterId") != query["ClusterId"]
                        or row.get("TableGroupId") not in query["TableGroupIds"]
                    ):
                        raise CollectionError("TcaplusTagScopeMismatch")
                    if action == "DescribeTableTags" and (
                        row.get("TableGroupId"),
                        row.get("TableName"),
                    ) not in {(p["TableGroupId"], p["TableName"]) for p in query["SelectedTables"]}:
                        raise CollectionError("TcaplusTagScopeMismatch")
            if action == "DescribeSupportedProducts" and (
                not isinstance(data.get("Products"), list)
                or type(data.get("TotalCount")) is not int
                or data["TotalCount"] != len(data["Products"])
            ):
                raise CollectionError("SupportedProductsCountMismatch")
            return data

    scoped = CollectorRunner(
        runner.graph,
        ScopedTransport(),
        runner.account,
        runner.regions,
        runner.progress,
        runner.plan,
    )
    collect_read(scoped, read, region, parent, parameters=params)
