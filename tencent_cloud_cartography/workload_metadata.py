"""Audited registry, runtime, gateway and edge configuration; no workload reads."""

import json
import re

from .data_metadata import Read, collect_read, schema
from .transport import CollectionError, path_value

FILTER = schema("Decoration Pattern")
RETENTION = schema("Key", "Value")
TARGET = schema("Host Health CreatedTime Source CvmInstanceId CvmInstanceName", "Port Weight")
UPSTREAM = schema(
    "Host SourceID Namespace ServiceName SourceType ScfType ScfNamespace ScfLambdaName ScfLambdaQualifier Algorithm AutoScalingGroupID SourceName RealSourceType HealthStatus",
    "Port SlowStart AutoScalingCvmPort",
    "ScfCamAuthEnable ScfIsBase64Encoded ScfIsIntegratedResponse",
    Targets=[TARGET],
)
READS = (
    Read(
        "tcr",
        "DescribeReplicationInstances",
        "tcr.replicationinstance",
        schema(
            "RegistryId ReplicationRegistryId ReplicationRegionName Status CreatedAt",
            "ReplicationRegionId",
        ),
        "ReplicationRegistries",
        ("ReplicationRegistryId",),
        "TotalCount",
        "offset",
        "tcr.instance",
        "RegistryId",
    ),
    Read(
        "tke",
        "DescribeUserPermissions",
        "tke.userpermission",
        schema("ClusterId RoleName RoleType Namespace", booleans="IsCustom"),
        "Permissions",
        parent="cam.user",
        argument="TargetUin",
    ),
    Read(
        "tcr",
        "DescribeImmutableTagRules",
        "tcr.immutabletagrule",
        schema(
            "RepositoryPattern TagPattern RepositoryDecoration TagDecoration NsName",
            "RuleId",
            "Disabled",
        ),
        "Rules",
        ("RuleId",),
        "Total",
        "page-size",
        "tcr.instance",
        "RegistryId",
    ),
    Read(
        "tcr",
        "DescribeTagRetentionRules",
        "tcr.retentionpolicy",
        schema(
            "NamespaceName CronSetting NextExecutionTime",
            "RetentionId",
            "Disabled",
            RetentionRuleList=[RETENTION],
            AdvancedRuleItems=[
                schema(RetentionPolicy=RETENTION, TagFilter=FILTER, RepositoryFilter=FILTER)
            ],
        ),
        "RetentionPolicyList",
        ("RetentionId",),
        "TotalCount",
        "offset",
        "tcr.instance",
        "RegistryId",
    ),
    Read(
        "tcr",
        "DescribeTagRetentionExecution",
        "tcr.retentionexecution",
        schema("StartTime EndTime Status", "ExecutionId RetentionId"),
        "RetentionExecutionList",
        ("ExecutionId",),
        "TotalCount",
        "offset",
        "tcr.retentionpolicy",
    ),
    Read(
        "tcr",
        "DescribeTagRetentionExecutionTask",
        "tcr.retentiontask",
        schema("StartTime EndTime Status Repository", "TaskId ExecutionId Total Retained"),
        "RetentionTaskList",
        ("TaskId",),
        "TotalCount",
        "offset",
        "tcr.retentionexecution",
    ),
    Read(
        "tcr",
        "DescribeSecurityPolicies",
        "tcr.networkpolicy",
        schema("Description CidrBlock PolicyVersion", "PolicyIndex"),
        "SecurityPolicySet",
        ("PolicyIndex",),
        parent="tcr.instance",
        argument="RegistryId",
    ),
    Read(
        "tcr",
        "DescribeReplicationExecutions",
        "tcr.replicationexecution",
        schema("Status StartTime EndTime", "ExecutionID PolicyID Total Succeed"),
        "ReplicationExecutionList",
        ("ExecutionID",),
        "TotalCount",
        "page-size",
        "tcr.replicationpolicy",
    ),
    Read(
        "tcr",
        "DescribeReplicationTasks",
        "tcr.replicationtask",
        schema("ResourceType SrcResource DstResource JobID Status StartTime EndTime"),
        "ReplicationTaskList",
        ("JobID",),
        "TotalCount",
        "page-size",
        "tcr.replicationexecution",
    ),
    Read(
        "tke",
        "DescribeClusterVirtualNodePools",
        "tke.virtualnodepool",
        schema(
            "NodePoolId Name LifeState",
            arrays="SubnetIds",
            Labels=[schema("Name Value")],
            Taints=[schema("Key Value Effect")],
            SubnetAllocationPolicy=schema(Allocations=[schema("SubnetId", "Ratio")]),
        ),
        "NodePoolSet",
        ("NodePoolId",),
        "TotalCount",
        parent="tke.cluster",
        argument="ClusterId",
    ),
    Read(
        "tke",
        "DescribeClusterVirtualNode",
        "tke.virtualnode",
        schema("Name SubnetId Phase CreatedTime"),
        "Nodes",
        ("Name",),
        "TotalCount",
        parent="tke.virtualnodepool",
    ),
    Read(
        "tke",
        "DescribeClusterRouteTables",
        "tke.clusterroutetable",
        schema("RouteTableName RouteTableCidrBlock VpcId"),
        "RouteTableSet",
        ("RouteTableName",),
        "TotalCount",
    ),
    Read(
        "tke",
        "DescribeClusterRoutes",
        "tke.clusterroute",
        schema("RouteTableName DestinationCidrBlock GatewayIp"),
        "RouteSet",
        ("DestinationCidrBlock",),
        "TotalCount",
        parent="tke.clusterroutetable",
        argument="RouteTableName",
    ),
    Read(
        "tke",
        "DescribeClusterControllers",
        "tke.controller",
        schema("Name", booleans="Enabled"),
        "ControllerStatusSet",
        ("Name",),
        parent="tke.cluster",
        argument="ClusterId",
    ),
    Read(
        "tke",
        "DescribeEncryptionStatus",
        "tke.encryptionstatus",
        schema("Status"),
        parent="tke.cluster",
        argument="ClusterId",
    ),
    Read(
        "scf",
        "GetFunctionEventInvokeConfig",
        "scf.asyncconfiguration",
        schema(
            AsyncTriggerConfig=schema(integers="MsgTTL", RetryConfig=[schema(integers="RetryNum")])
        ),
        parent="scf.function",
    ),
    Read(
        "scf",
        "GetReservedConcurrencyConfig",
        "scf.reservedconcurrency",
        schema(integers="ReservedMem"),
        parent="scf.function",
    ),
    Read(
        "scf",
        "GetProvisionedConcurrencyConfig",
        "scf.provisionedconcurrency",
        schema(
            integers="UnallocatedConcurrencyNum",
            Allocated=[
                schema(
                    "Status Qualifier",
                    "AllocatedProvisionedConcurrencyNum AvailableProvisionedConcurrencyNum",
                    TriggerActions=[
                        schema(
                            "TriggerName TriggerCronConfig ProvisionedType",
                            "TriggerProvisionedConcurrencyNum",
                        )
                    ],
                )
            ],
        ),
        parent="scf.function",
    ),
    Read(
        "scf",
        "ListCustomDomains",
        "scf.customdomain",
        schema(
            "Domain Protocol",
            EndpointsConfig=[
                schema(
                    "Namespace FunctionName Qualifier PathMatch",
                    PathRewrite=[schema("Path Type Rewrite")],
                )
            ],
            CertConfig=schema("CertificateId"),
            WafConfig=schema("WafOpen WafInstanceId"),
        ),
        "Domains",
        ("Domain",),
        "Total",
        "offset",
    ),
    Read(
        "apigateway",
        "DescribeServiceEnvironmentStrategy",
        "apigateway.servicestrategy",
        schema("EnvironmentName VersionName", "Status Strategy MaxStrategy"),
        "Result.EnvironmentList",
        ("EnvironmentName",),
        "Result.TotalCount",
        "offset",
        "apigateway.service",
        "ServiceId",
    ),
    Read(
        "apigateway",
        "DescribeApiEnvironmentStrategy",
        "apigateway.apistrategy",
        schema(
            "ApiId ApiName Path Method", EnvironmentStrategySet=[schema("EnvironmentName", "Quota")]
        ),
        "Result.ApiEnvironmentStrategySet",
        ("ApiId",),
        "Result.TotalCount",
        "offset",
        "apigateway.api",
    ),
    Read(
        "apigateway",
        "DescribeExclusiveInstancesStatus",
        "apigateway.dedicatedinstance",
        schema(
            "InstanceId InstanceName InstanceChargeType InstanceType InstanceState CreatedTime UniqVpcId",
            arrays="OuterIpList InnerIpList",
            InstanceChargePrepaid=schema("RenewFlag ExpiredTime"),
        ),
        "Result.InstanceSet",
        ("InstanceId",),
        "Result.TotalCount",
        "offset",
    ),
    Read(
        "tse",
        "DescribeCloudNativeAPIGateways",
        "tse.gateway",
        schema(
            "GatewayId Status Name Type GatewayVersion Description CreateTime FeatureVersion CurDeadline EngineRegion IngressClassName GatewayMinorVersion LoadBalancerType",
            "InternetMaxBandwidthOut",
            "EnableCls EnableInternet DeleteProtect ForceHTTPSRedirect",
            "PublicIpAddresses",
            NodeConfig=schema("Specification", "Number"),
            VpcConfig=schema("VpcId SubnetId"),
            InstancePort=schema("HttpPort HttpsPort TcpPort UdpPort"),
        ),
        "Result.GatewayList",
        ("GatewayId",),
        "Result.TotalCount",
        "offset",
    ),
    Read(
        "tse",
        "DescribeNativeGatewayServerGroups",
        "tse.gatewaygroup",
        schema(
            "GroupId Name Status CreateTime GatewayId SubnetIds",
            "DefaultWeight ElasticNumber",
            "SupportTOA SupportIPV6",
            NodeConfig=schema("Specification", "Number"),
        ),
        "Result.GatewayGroupList",
        ("GroupId",),
        "Result.TotalCount",
        "offset",
        "tse.gateway",
        "GatewayId",
    ),
    Read(
        "tse",
        "DescribeCloudNativeAPIGatewayNodes",
        "tse.gatewaynode",
        schema("NodeId NodeIp ZoneId Zone GroupId GroupName Status", "Weight", "IsDefaultWeight"),
        "Result.NodeList",
        ("NodeId",),
        "Result.TotalCount",
        "offset",
        "tse.gateway",
        "GatewayId",
    ),
    Read(
        "tse",
        "DescribeCloudNativeAPIGatewayServicesLight",
        "tse.gatewayservice",
        schema(
            "ID Name UpstreamType CreatedTime Path Protocol",
            "Retries Timeout",
            UpstreamInfo=UPSTREAM,
        ),
        "Result.ServiceList",
        ("ID",),
        "Result.TotalCount",
        "offset",
        "tse.gateway",
        "GatewayId",
    ),
    Read(
        "tse",
        "DescribeCloudNativeAPIGatewayPorts",
        "tse.gatewayports",
        schema(
            Result=schema(
                "GatewayId", GatewayInstancePortList=[schema("Scheme", integer_arrays="PortList")]
            )
        ),
        parent="tse.gateway",
        argument="GatewayId",
    ),
    Read(
        "tse",
        "DescribeCloudNativeAPIGatewayUpstream",
        "tse.gatewayupstream",
        schema("ID Name", Target=[TARGET]),
        "Result.UpstreamList",
        ("ID",),
        parent="tse.gatewayservice",
    ),
    Read(
        "teo",
        "DescribeZones",
        "teo.zone",
        schema(
            "ZoneId ZoneName AliasZoneName Area Type CreatedOn ModifiedOn Status CnameStatus ActiveStatus LockStatus",
            booleans="Paused",
            arrays="NameServers OriginalNameServers",
            Tags=[schema("TagKey TagValue")],
            WorkModeInfos=[schema("ConfigGroupType WorkMode")],
        ),
        "Zones",
        ("ZoneId",),
        "TotalCount",
        "offset",
    ),
    Read(
        "teo",
        "DescribeL7AccSetting",
        "teo.accelerationsettings",
        schema(
            ZoneSetting=schema(
                "ZoneName",
                ZoneConfig=schema(
                    SmartRouting=schema("Switch"),
                    Cache=schema(
                        FollowOrigin=schema(
                            "Switch DefaultCache DefaultCacheStrategy", "DefaultCacheTime"
                        ),
                        NoCache=schema("Switch"),
                        CustomTime=schema("Switch", "CacheTime"),
                    ),
                    MaxAge=schema("FollowOrigin", "CacheTime"),
                    CacheKey=schema(
                        "FullURLCache IgnoreCase",
                        QueryString=schema("Switch Action", arrays="Values"),
                    ),
                    CachePrefresh=schema("Switch", "CacheTimePercent"),
                    OfflineCache=schema("Switch"),
                    Compression=schema("Switch", arrays="Algorithms"),
                    ForceRedirectHTTPS=schema("Switch", "RedirectStatusCode"),
                    HSTS=schema("Switch IncludeSubDomains Preload", "Timeout"),
                    TLSConfig=schema("CipherSuite", arrays="Version"),
                    OCSPStapling=schema("Switch"),
                    HTTP2=schema("Switch"),
                    QUIC=schema("Switch"),
                    UpstreamHTTP2=schema("Switch"),
                    IPv6=schema("Switch"),
                    WebSocket=schema("Switch", "Timeout"),
                    PostMaxSize=schema("Switch", "MaxSize"),
                    Grpc=schema("Switch"),
                    ClientIPHeader=schema("Switch HeaderName"),
                    ClientIPCountry=schema("Switch HeaderName"),
                    NetworkErrorLogging=schema("Switch"),
                    AccelerateMainland=schema("Switch"),
                    StandardDebug=schema("Switch Expires", arrays="AllowClientIPList"),
                ),
            )
        ),
        parent="teo.zone",
        argument="ZoneId",
    ),
    Read(
        "teo",
        "DescribeDDoSProtection",
        "teo.ddosprotection",
        schema(
            DDoSProtection=schema(
                "ProtectionOption",
                DomainDDoSProtections=[schema("Domain Switch")],
                SharedCNAMEDDoSProtections=[schema("Domain Switch")],
            )
        ),
        parent="teo.zone",
        argument="ZoneId",
    ),
    Read(
        "teo",
        "DescribeAliasDomains",
        "teo.aliasdomain",
        schema("AliasName ZoneId TargetName Status CreatedOn ModifiedOn", "ForbidMode"),
        "AliasDomains",
        ("AliasName",),
        "TotalCount",
        "offset",
        "teo.zone",
        "ZoneId",
    ),
    Read(
        "teo",
        "DescribeDefaultCertificates",
        "teo.defaultcertificate",
        schema(
            "CertId Alias Type ExpireTime EffectiveTime CommonName Status SignAlgo",
            arrays="SubjectAltName",
        ),
        "DefaultServerCertInfo",
        ("CertId",),
        "TotalCount",
        "offset",
        "teo.zone",
        "ZoneId",
    ),
    Read(
        "ses",
        "ListEmailAddress",
        "ses.senderidentity",
        schema("EmailAddress EmailSenderName", "CreatedTimestamp SmtpPwdType"),
        "EmailSenders",
        ("EmailAddress",),
    ),
    Read(
        "tse",
        "DescribeWafProtection",
        "tse.wafprotection",
        schema(
            Result=schema(
                "GlobalStatus ObjectStatus",
                ServicesStatus=[schema("Name Id Type Status")],
                RouteStatus=[
                    schema("Name Id Status ServiceName ServiceId", arrays="Methods Paths Hosts")
                ],
            )
        ),
        parent="tse.gateway",
        argument="GatewayId",
    ),
    Read(
        "tse",
        "DescribeWafDomains",
        "tse.wafdomains",
        schema(Result=schema(arrays="Domains")),
        parent="tse.gateway",
        argument="GatewayId",
    ),
)
ACTIONS = {(r.service, r.action) for r in READS}
KINDS = {r.kind for r in READS}
GLOBAL = {"teo"}
BOUNDARIES = (
    (
        "ciam",
        "ApplicationFederation",
        "The audited public CIAM API exposes user-store inventory, not an application/client/provider federation census.",
    ),
    (
        "tdmq",
        "CmqPolicyEncryptionFifo",
        "Collected CMQ configuration does not expose resource-policy, encryption-key, FIFO/deduplication or subscription-confirmation correspondence; absent fields are unknown.",
    ),
    (
        "tcr",
        "PullThroughCacheEquivalence",
        "Replication and acceleration are native features, not established pull-through-cache rules.",
    ),
    (
        "tke",
        "CompleteWorkloadNetworking",
        "Workload Tables omit definitions, owner references, volumes, service accounts and full network configuration; mixed workload reads remain disabled.",
    ),
)


def ancestor(graph, node, kind):
    """Follow collected ownership edges; never recover IDs by splitting hashes."""
    found, seen, pending = {}, set(), [node["id"]]
    while pending:
        nid = pending.pop()
        if nid in seen:
            continue
        seen.add(nid)
        if len(seen) > 1000:
            raise CollectionError("WorkloadMetadataAncestryLimit")
        candidate = graph.nodes[nid]
        if candidate["account"] != node["account"] or candidate["region"] != node["region"]:
            continue
        if candidate["kind"] == kind:
            found[nid] = candidate
            continue
        pending.extend(
            e["source"]
            for e in graph.edges.values()
            if e["target"] == nid
            and e["relationship"] in {"HAS_METADATA", "HAS_REPLICATION_POLICY", "HAS_API"}
        )
    if len(found) != 1:
        raise CollectionError("AmbiguousWorkloadMetadataParent")
    return next(iter(found.values()))


def parameters(graph, read, parent):
    if not parent:
        return {}
    p = parent["properties"]
    result = {read.argument: parent["resource_id"]}
    if read.service == "tcr":
        result = {"RegistryId": ancestor(graph, parent, "tcr.instance")["resource_id"]}
        identity = {
            "DescribeTagRetentionExecution": ("RetentionId", "RetentionId"),
            "DescribeTagRetentionExecutionTask": ("ExecutionId", "ExecutionId"),
            "DescribeReplicationExecutions": ("PolicyId", "ID"),
            "DescribeReplicationTasks": ("ExecutionId", "ExecutionID"),
        }.get(read.action)
        if identity:
            key, field = identity
            result[key] = p[field]
        if read.action == "DescribeTagRetentionExecutionTask":
            result["RetentionId"] = ancestor(graph, parent, "tcr.retentionpolicy")["properties"][
                "RetentionId"
            ]
    elif read.service == "scf" and parent["kind"] == "scf.function":
        result = dict(FunctionName=parent["name"], Namespace=p["Namespace"])
    elif read.action == "DescribeClusterVirtualNode":
        result = dict(
            ClusterId=ancestor(graph, parent, "tke.cluster")["resource_id"],
            NodePoolId=p["NodePoolId"],
        )
    elif read.action == "DescribeApiEnvironmentStrategy":
        result = dict(
            ServiceId=ancestor(graph, parent, "apigateway.service")["resource_id"], ApiId=p["ApiId"]
        )
    elif read.action == "DescribeCloudNativeAPIGatewayUpstream":
        result = dict(
            GatewayId=ancestor(graph, parent, "tse.gateway")["resource_id"], ServiceName=p["Name"]
        )
    elif read.action == "DescribeWafProtection":
        result["TypeList"] = ["Global", "Service", "Route", "Object"]
    return result


def checked_read(runner, read, region, parent, params):
    from .collect import CollectorRunner

    class ScopedTransport:
        def call(self, service, action, region=None, **query):
            data = runner.transport.call(service, action, region, **query)
            if action == "DescribeUserPermissions" and data.get("TargetUin") != query["TargetUin"]:
                raise CollectionError("TkePermissionPrincipalMismatch")
            rows = path_value(data, read.result) if read.result else [data]
            if not isinstance(rows, list):
                raise CollectionError("InvalidWorkloadMetadata")
            for row in rows:
                if not isinstance(row, dict):
                    raise CollectionError("InvalidWorkloadMetadata")
                for key in (
                    "RegistryId",
                    "ClusterId",
                    "ZoneId",
                    "GatewayId",
                    "ApiId",
                    "RouteTableName",
                    "RetentionId",
                    "ExecutionId",
                    "PolicyID",
                    "ExecutionID",
                ):
                    qkey = {"PolicyID": "PolicyId", "ExecutionID": "ExecutionId"}.get(key, key)
                    if qkey in query and row.get(key) not in (None, query[qkey]):
                        raise CollectionError("WorkloadMetadataScopeMismatch")
                if action == "DescribeCloudNativeAPIGateways" and row.get("EngineRegion") not in (
                    None,
                    "",
                    region,
                ):
                    raise CollectionError("GatewayRegionMismatch")
                if action == "DescribeCloudNativeAPIGatewayPorts" and (
                    not isinstance(row.get("Result"), dict)
                    or row["Result"].get("GatewayId") != query["GatewayId"]
                ):
                    raise CollectionError("GatewayPortScopeMismatch")
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


def collect(runner, services=None):
    from .catalog import SES_ENDPOINTS

    for read in READS:
        if services and read.service not in services:
            continue
        for region in ["global"] if read.service in GLOBAL else runner.regions_for(read.service):
            if read.service == "ses" and region not in SES_ENDPOINTS:

                def unsupported(record):
                    raise CollectionError("UnsupportedSesRegion")

                runner.scope(
                    "ses",
                    read.action,
                    region,
                    unsupported,
                    "Supported regions: " + ", ".join(SES_ENDPOINTS),
                )
                continue
            parents = (
                [
                    n
                    for n in list(runner.graph.nodes.values())
                    if n["kind"] == read.parent
                    and n["account"] == runner.account
                    and n["region"] == ("global" if read.parent == "cam.user" else region)
                    and n["status"] == "enriched"
                ]
                if read.parent
                else [None]
            )
            for parent in parents:
                try:
                    params = parameters(runner.graph, read, parent)
                except (KeyError, TypeError, CollectionError):

                    def invalid(record):
                        raise CollectionError("MissingWorkloadMetadataScope")

                    runner.scope(read.service, read.action, region, invalid, parent["resource_id"])
                    continue
                checked_read(runner, read, region, parent, params)
    for service, capability, detail in BOUNDARIES:
        if services and service not in services:
            continue
        for region in runner.regions_for(service):
            action = "capability:" + capability
            if not any(
                r["account"] == runner.account
                and r["region"] == region
                and r["service"] == service
                and r["action"] == action
                for r in runner.graph.coverage
            ):
                runner.graph.coverage.append(
                    dict(
                        account=runner.account,
                        region=region,
                        service=service,
                        action=action,
                        status="unsupported",
                        count=0,
                        request_ids=[],
                        error="UnestablishedMetadataCorrespondence",
                        detail=detail,
                    )
                )
    link(runner.graph)


def link(graph):
    """Exact same-account configuration joins, also rebuilt for offline imports."""
    source = "analysis.workload-metadata-links"
    graph.edges = {i: e for i, e in graph.edges.items() if e.get("provenance") != source}
    nodes = list(graph.nodes.values())
    index, functions = {}, {}
    for node in nodes:
        if node["status"] != "enriched":
            continue
        index.setdefault(
            (node["account"], node["region"], node["kind"], node["resource_id"]), []
        ).append(node)
        if node["kind"] == "scf.function":
            functions.setdefault(
                (
                    node["account"],
                    node["region"],
                    node["name"],
                    node["properties"].get("Namespace"),
                ),
                [],
            ).append(node)

    def exact(node, kind, rid, relation, region=None):
        matches = index.get((node["account"], region or node["region"], kind, rid), [])
        if len(matches) == 1:
            graph.edge(node["id"], matches[0]["id"], relation, source)

    def function(node, name, namespace, qualifier=None):
        matches = functions.get((node["account"], node["region"], name, namespace), [])
        for target in matches if len(matches) == 1 else []:
            graph.edge(node["id"], target["id"], "CONFIGURED_FUNCTION_BACKEND", source)
            if qualifier:
                exact(
                    node,
                    "scf.version" if qualifier == "$LATEST" or qualifier.isdigit() else "scf.alias",
                    target["resource_id"] + "/" + qualifier,
                    "CONFIGURED_FUNCTION_QUALIFIER",
                )

    def network(node, kind, rid, relation):
        prefix = "vpc" if kind == "vpc.vpc" else "subnet"
        if (
            isinstance(rid, str)
            and re.fullmatch(prefix + r"-[A-Za-z0-9]+", rid)
            and node["region"] != "global"
        ):
            nid = graph.add(
                node["account"], node["region"], kind, rid, source=source, status="reference"
            )
            graph.edge(node["id"], nid, relation, source)

    for n in nodes:
        p, kind = n["properties"], n["kind"]
        if kind in KINDS:
            n["name"] = next(
                (
                    p[k]
                    for k in (
                        "Name",
                        "ZoneName",
                        "Domain",
                        "EmailAddress",
                        "AliasName",
                        "Repository",
                    )
                    if p.get(k)
                ),
                n["name"],
            )
            p.update(runtime_verified=False)
        if kind == "tse.gateway":
            vpc = json.loads(p.get("VpcConfig", "{}"))
            network(n, "vpc.vpc", vpc.get("VpcId"), "IN_VPC")
            network(n, "vpc.subnet", vpc.get("SubnetId"), "IN_SUBNET")
        elif kind == "tke.userpermission":
            exact(n, "tke.cluster", p.get("ClusterId"), "CONFIGURED_CLUSTER_PERMISSION")
            p.update(effective_access_verified=False, complete_principal_inventory_verified=False)
        elif kind == "tse.gatewayservice":
            u = json.loads(p.get("UpstreamInfo", "{}"))
            function(n, u.get("ScfLambdaName"), u.get("ScfNamespace"), u.get("ScfLambdaQualifier"))
            for t in u.get("Targets", []):
                exact(n, "cvm.instance", t.get("CvmInstanceId"), "CONFIGURED_CVM_BACKEND")
            p.update(backend_probe_performed=False, full_route_inventory_collected=False)
        elif kind == "tse.gatewayupstream":
            for target in json.loads(p.get("Target", "[]")):
                exact(n, "cvm.instance", target.get("CvmInstanceId"), "CONFIGURED_CVM_BACKEND")
            p["backend_probe_performed"] = False
        elif kind == "tse.wafprotection":
            configuration = json.loads(p.get("Result", "{}"))
            service_ids = {row.get("Id") for row in configuration.get("ServicesStatus", [])}
            service_ids.update(row.get("ServiceId") for row in configuration.get("RouteStatus", []))
            for service in nodes:
                if (
                    service["kind"] == "tse.gatewayservice"
                    and service["account"] == n["account"]
                    and service["region"] == n["region"]
                    and service["properties"].get("parent_resource_id")
                    == p.get("parent_resource_id")
                    and service["properties"].get("ID") in service_ids
                ):
                    graph.edge(n["id"], service["id"], "REPORTED_WAF_SERVICE_CONFIGURATION", source)
            p.update(full_route_inventory_collected=False, waf_enforcement_verified=False)
        elif kind == "tcr.replicationinstance":
            region, rid = p.get("ReplicationRegionName"), p.get("ReplicationRegistryId")
            if (
                isinstance(region, str)
                and re.fullmatch(r"[a-z]+-[a-z0-9-]+", region)
                and isinstance(rid, str)
                and re.fullmatch(r"tcr-[A-Za-z0-9-]+", rid)
            ):
                nid = graph.add(
                    n["account"], region, "tcr.instance", rid, source=source, status="reference"
                )
                graph.edge(n["id"], nid, "CONFIGURED_REPLICA_REGISTRY", source)
            p["replication_verified"] = False
        elif kind == "scf.customdomain":
            for endpoint in json.loads(p.get("EndpointsConfig", "[]")):
                function(
                    n,
                    endpoint.get("FunctionName"),
                    endpoint.get("Namespace"),
                    endpoint.get("Qualifier"),
                )
            exact(
                n,
                "ssl.certificate",
                json.loads(p.get("CertConfig", "{}")).get("CertificateId"),
                "USES_CERTIFICATE",
                "global",
            )
        elif kind == "teo.aliasdomain":
            # This is an alias configuration, not evidence of an effective DNS answer.
            p["effective_dns_verified"] = False
        elif kind == "teo.zone":
            p.update(
                acceleration_domain_inventory_complete=False, origin_configuration_collected=False
            )
        elif kind == "ses.senderidentity":
            p.update(
                identity_scope="sender-address",
                delivery_verified=False,
                individual_dkim_state="not-exposed",
            )
            address = p["EmailAddress"]
            if address.count("@") == 1:
                exact(n, "ses.domain", address.rsplit("@", 1)[1].lower(), "SENDS_FROM_DOMAIN")
        elif kind == "tke.virtualnodepool":
            for subnet in json.loads(p.get("SubnetIds", "[]")):
                network(n, "vpc.subnet", subnet, "USES_SUBNET")
        elif kind == "tse.gatewaynode" and p.get("GroupId"):
            matches = [
                group
                for group in nodes
                if group["kind"] == "tse.gatewaygroup"
                and group["account"] == n["account"]
                and group["region"] == n["region"]
                and group["properties"].get("GroupId") == p["GroupId"]
                and group["properties"].get("parent_resource_id") == p.get("parent_resource_id")
            ]
            if len(matches) == 1:
                graph.edge(n["id"], matches[0]["id"], "MEMBER_OF_GATEWAY_GROUP", source)
        elif kind == "apigateway.servicestrategy":
            exact(
                n,
                "apigateway.environment",
                p.get("parent_resource_id", "") + "/" + p.get("EnvironmentName", ""),
                "CONFIGURES_ENVIRONMENT_QUOTA",
            )
        elif kind == "apigateway.apistrategy":
            try:
                service = ancestor(graph, n, "apigateway.service")
            except CollectionError:
                continue
            for environment in json.loads(p.get("EnvironmentStrategySet", "[]")):
                exact(
                    n,
                    "apigateway.environment",
                    service["resource_id"] + "/" + environment.get("EnvironmentName", ""),
                    "CONFIGURES_API_ENVIRONMENT_QUOTA",
                )
        elif kind == "apigateway.service":
            exact(n, "apigateway.dedicatedinstance", p.get("InstanceId"), "DEPLOYED_ON_INSTANCE")
        elif kind in {"tdmq.cmqqueue", "tdmq.cmqtopic", "tdmq.cmqsubscription"}:
            p.update(
                resource_policy_state="not-exposed-by-collected-api",
                encryption_state="not-exposed-by-collected-api",
            )
            if kind == "tdmq.cmqqueue":
                p.update(
                    aws_fifo_equivalence="not-established",
                    aws_deduplication_equivalence="not-established",
                )
            if kind == "tdmq.cmqsubscription":
                p.update(confirmation_state="not-exposed-by-collected-api", delivery_verified=False)
        elif kind == "tcr.image":
            p.update(
                manifest_membership_collected=False,
                signature_verified=False,
                image_layers_collected=False,
                image_configuration_collected=False,
                attestations_collected=False,
            )
