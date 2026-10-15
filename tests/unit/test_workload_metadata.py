"""Provider-shaped contracts, isolation controls and offline analysis evidence."""

import copy
from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.catalog import ALLOWED_ACTIONS, DETAIL_KINDS
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.collection_plan import RegionPlan, service_modes
from tencent_cloud_cartography.data_metadata import project, schema
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.storage import validate
from tencent_cloud_cartography.workload_metadata import (
    ACTIONS,
    KINDS,
    READS,
    checked_read,
    collect,
    link,
    parameters,
)

REGION = "eu-frankfurt"
# These are explicit native API fixtures, independent of the projection schemas.
RESPONSES = {
    "DescribeReplicationInstances": dict(
        ReplicationRegistries=[
            dict(
                RegistryId="tcr-one",
                ReplicationRegistryId="tcr-one-5-replica",
                ReplicationRegionName="ap-hongkong",
                ReplicationRegionId=5,
                Status="Running",
            )
        ],
        TotalCount=1,
    ),
    "DescribeCloudNativeAPIGatewayUpstream": dict(
        Result=dict(
            UpstreamList=[
                dict(
                    ID="upstream-one",
                    Name="worker-upstream",
                    Target=[
                        dict(
                            Host="10.0.0.10",
                            Port=8080,
                            Weight=100,
                            Health="HEALTHY",
                            CvmInstanceId="ins-one",
                        )
                    ],
                )
            ]
        )
    ),
    "DescribeUserPermissions": dict(
        TargetUin="101",
        Permissions=[
            dict(
                ClusterId="cls-one",
                RoleName="reader",
                RoleType="custom",
                Namespace="apps",
                IsCustom=True,
            )
        ],
    ),
    "DescribeImmutableTagRules": dict(
        Rules=[
            dict(
                RuleId=7,
                NsName="apps",
                RepositoryPattern="**",
                TagPattern="release-*",
                RepositoryDecoration="repoMatches",
                TagDecoration="matches",
                Disabled=False,
            )
        ],
        EmptyNs=[],
        Total=1,
    ),
    "DescribeTagRetentionRules": dict(
        RetentionPolicyList=[
            dict(
                RetentionId=8,
                NamespaceName="apps",
                CronSetting="0 0 * * *",
                Disabled=False,
                RetentionRuleList=[dict(Key="latestPushedK", Value=10)],
                AdvancedRuleItems=[
                    dict(
                        RetentionPolicy=dict(Key="nDaysSinceLastPush", Value=30),
                        TagFilter=dict(Decoration="matches", Pattern="release-*"),
                        RepositoryFilter=dict(Decoration="repoMatches", Pattern="**"),
                    )
                ],
            )
        ],
        TotalCount=1,
    ),
    "DescribeTagRetentionExecution": dict(
        RetentionExecutionList=[
            dict(ExecutionId=9, RetentionId=8, StartTime="2026-10-15T00:00:00Z", Status="Success")
        ],
        TotalCount=1,
    ),
    "DescribeTagRetentionExecutionTask": dict(
        RetentionTaskList=[
            dict(
                TaskId=10,
                ExecutionId=9,
                Repository="apps/web",
                Status="Success",
                Total=5,
                Retained=3,
            )
        ],
        TotalCount=1,
    ),
    "DescribeSecurityPolicies": dict(
        SecurityPolicySet=[dict(PolicyIndex=0, CidrBlock="192.0.2.0/24", PolicyVersion="1")]
    ),
    "DescribeReplicationExecutions": dict(
        ReplicationExecutionList=[
            dict(ExecutionID=12, PolicyID=11, Status="Succeed", Total=1, Succeed=1)
        ],
        TotalCount=1,
    ),
    "DescribeReplicationTasks": dict(
        ReplicationTaskList=[
            dict(
                JobID="job-one",
                ResourceType="image",
                SrcResource="apps/web:v1",
                DstResource="apps/web:v1",
                Status="Succeed",
            )
        ],
        TotalCount=1,
    ),
    "DescribeClusterVirtualNodePools": dict(
        NodePoolSet=[
            dict(
                NodePoolId="np-one",
                Name="Super nodes",
                LifeState="normal",
                SubnetIds=["subnet-one"],
                Labels=[dict(Name="pool", Value="virtual")],
                Taints=[dict(Key="dedicated", Value="batch", Effect="NoSchedule")],
                SubnetAllocationPolicy=dict(Allocations=[dict(SubnetId="subnet-one", Ratio=100)]),
            )
        ],
        TotalCount=1,
    ),
    "DescribeClusterVirtualNode": dict(
        Nodes=[dict(Name="virtual-one", SubnetId="subnet-one", Phase="Running")], TotalCount=1
    ),
    "DescribeClusterRouteTables": dict(
        RouteTableSet=[
            dict(RouteTableName="pod-routes", RouteTableCidrBlock="10.42.0.0/16", VpcId="vpc-one")
        ],
        TotalCount=1,
    ),
    "DescribeClusterRoutes": dict(
        RouteSet=[
            dict(
                RouteTableName="pod-routes",
                DestinationCidrBlock="10.42.1.0/24",
                GatewayIp="10.0.0.10",
            )
        ],
        TotalCount=1,
    ),
    "DescribeClusterControllers": dict(
        ControllerStatusSet=[dict(Name="node-controller", Enabled=True)]
    ),
    "DescribeEncryptionStatus": dict(Status="Enabled"),
    "GetFunctionEventInvokeConfig": dict(
        AsyncTriggerConfig=dict(MsgTTL=3600, RetryConfig=[dict(RetryNum=2)])
    ),
    "GetReservedConcurrencyConfig": dict(ReservedMem=256),
    "GetProvisionedConcurrencyConfig": dict(
        UnallocatedConcurrencyNum=0,
        Allocated=[
            dict(
                Qualifier="1",
                Status="Done",
                AllocatedProvisionedConcurrencyNum=2,
                AvailableProvisionedConcurrencyNum=2,
                TriggerActions=[
                    dict(
                        TriggerName="office-hours",
                        TriggerCronConfig="0 0 9 * * * *",
                        ProvisionedType="Default",
                        TriggerProvisionedConcurrencyNum=2,
                    )
                ],
            )
        ],
    ),
    "ListCustomDomains": dict(
        Domains=[
            dict(
                Domain="api.example.test",
                Protocol="HTTPS",
                EndpointsConfig=[
                    dict(
                        Namespace="default",
                        FunctionName="worker",
                        Qualifier="1",
                        PathMatch="/jobs",
                        PathRewrite=[dict(Path="/jobs", Type="Exact", Rewrite="/")],
                    )
                ],
                CertConfig=dict(CertificateId="cert-one"),
                WafConfig=dict(WafOpen="OPEN", WafInstanceId="waf-one"),
            )
        ],
        Total=1,
    ),
    "DescribeServiceEnvironmentStrategy": dict(
        Result=dict(
            EnvironmentList=[
                dict(
                    EnvironmentName="release",
                    VersionName="v1",
                    Status=1,
                    Strategy=-1,
                    MaxStrategy=1000,
                )
            ],
            TotalCount=1,
        )
    ),
    "DescribeApiEnvironmentStrategy": dict(
        Result=dict(
            ApiEnvironmentStrategySet=[
                dict(
                    ApiId="api-one",
                    ApiName="Jobs",
                    Path="/jobs",
                    Method="GET",
                    EnvironmentStrategySet=[dict(EnvironmentName="release", Quota=100)],
                )
            ],
            TotalCount=1,
        )
    ),
    "DescribeExclusiveInstancesStatus": dict(
        Result=dict(
            InstanceSet=[
                dict(
                    InstanceId="instance-one",
                    InstanceName="Dedicated gateway",
                    UniqVpcId="vpc-one",
                    OuterIpList=["192.0.2.10"],
                    InnerIpList=["10.0.0.10"],
                    InstanceState="RUNNING",
                    InstanceChargePrepaid=dict(
                        RenewFlag="NOTIFY_AND_AUTO_RENEW", ExpiredTime="2027-01-01"
                    ),
                )
            ],
            TotalCount=1,
        )
    ),
    "DescribeCloudNativeAPIGateways": dict(
        Result=dict(
            GatewayList=[
                dict(
                    GatewayId="gateway-one",
                    Name="Kong",
                    EngineRegion=REGION,
                    Status="Running",
                    EnableInternet=True,
                    ForceHTTPSRedirect=True,
                    NodeConfig=dict(Specification="1c2g", Number=2),
                    VpcConfig=dict(VpcId="vpc-one", SubnetId="subnet-one"),
                    InstancePort=dict(HttpPort="80", HttpsPort="443"),
                    PublicIpAddresses=["192.0.2.11"],
                )
            ],
            TotalCount=1,
        )
    ),
    "DescribeNativeGatewayServerGroups": dict(
        Result=dict(
            GatewayGroupList=[
                dict(
                    GroupId="group-one",
                    GatewayId="gateway-one",
                    Name="Default",
                    Status="Running",
                    SubnetIds="subnet-one",
                    DefaultWeight=100,
                )
            ],
            TotalCount=1,
        )
    ),
    "DescribeCloudNativeAPIGatewayNodes": dict(
        Result=dict(
            NodeList=[
                dict(
                    NodeId="node-one",
                    NodeIp="10.0.0.20",
                    Zone=REGION + "-1",
                    GroupId="group-one",
                    Status="Running",
                    Weight=100,
                )
            ],
            TotalCount=1,
        )
    ),
    "DescribeCloudNativeAPIGatewayServicesLight": dict(
        Result=dict(
            ServiceList=[
                dict(
                    ID="service-one",
                    Name="worker-service",
                    Protocol="http",
                    Path="/",
                    Retries=2,
                    Timeout=60,
                    UpstreamInfo=dict(
                        ScfLambdaName="worker",
                        ScfNamespace="default",
                        ScfLambdaQualifier="1",
                        ScfCamAuthEnable=True,
                        Targets=[
                            dict(
                                Host="10.0.0.10",
                                Port=8080,
                                CvmInstanceId="ins-one",
                                Weight=100,
                                Health="HEALTHY",
                            )
                        ],
                    ),
                )
            ],
            TotalCount=1,
        )
    ),
    "DescribeCloudNativeAPIGatewayPorts": dict(
        Result=dict(
            GatewayId="gateway-one",
            GatewayInstancePortList=[
                dict(Scheme="HTTP", PortList=[80]),
                dict(Scheme="HTTPS", PortList=[443]),
            ],
        )
    ),
    "DescribeZones": dict(
        Zones=[
            dict(
                ZoneId="zone-one",
                ZoneName="example.test",
                Area="overseas",
                Type="full",
                Status="active",
                Paused=False,
                NameServers=["ns.example.test"],
                WorkModeInfos=[dict(ConfigGroupType="l7_acceleration", WorkMode="work")],
            )
        ],
        TotalCount=1,
    ),
    "DescribeL7AccSetting": dict(
        ZoneSetting=dict(
            ZoneName="example.test",
            ZoneConfig=dict(
                Cache=dict(CustomTime=dict(Switch="on", CacheTime=600)),
                HSTS=dict(Switch="on", IncludeSubDomains="on", Timeout=31536000),
                TLSConfig=dict(Version=["TLSv1.2", "TLSv1.3"], CipherSuite="strict"),
                ForceRedirectHTTPS=dict(Switch="on", RedirectStatusCode=301),
                WebSocket=dict(Switch="on", Timeout=120),
            ),
        )
    ),
    "DescribeDDoSProtection": dict(
        DDoSProtection=dict(
            ProtectionOption="platform",
            DomainDDoSProtections=[dict(Domain="example.test", Switch="on")],
            SharedCNAMEDDoSProtections=[],
        )
    ),
    "DescribeAliasDomains": dict(
        AliasDomains=[
            dict(
                AliasName="alias.example.test",
                TargetName="example.test",
                ZoneId="zone-one",
                Status="online",
                ForbidMode=0,
            )
        ],
        TotalCount=1,
    ),
    "DescribeDefaultCertificates": dict(
        DefaultServerCertInfo=[
            dict(
                CertId="cert-edge",
                CommonName="example.test",
                SubjectAltName=["*.example.test"],
                Status="deployed",
                SignAlgo="RSA",
                ExpireTime="2027-01-01",
            )
        ],
        TotalCount=1,
    ),
    "ListEmailAddress": dict(
        EmailSenders=[
            dict(
                EmailAddress="sender@example.test",
                EmailSenderName="Sender",
                CreatedTimestamp=1700000000,
                SmtpPwdType=1,
            )
        ]
    ),
}


def runner(graph, callback, regions=None):
    return CollectorRunner(
        graph, SimpleNamespace(call=callback), "100", regions or [REGION], lambda _: None
    )


def parent_graph(kind, region=REGION):
    g = Graph()
    definitions = {
        "tcr.instance": ("tcr-one", {}, None, None),
        "tcr.retentionpolicy": (
            "retention-parent",
            dict(RetentionId=8),
            "tcr.instance",
            "HAS_METADATA",
        ),
        "tcr.retentionexecution": (
            "execution-parent",
            dict(ExecutionId=9, RetentionId=8),
            "tcr.retentionpolicy",
            "HAS_METADATA",
        ),
        "tcr.replicationpolicy": (
            "replication-parent",
            dict(ID=11),
            "tcr.instance",
            "HAS_REPLICATION_POLICY",
        ),
        "tcr.replicationexecution": (
            "replication-execution",
            dict(ExecutionID=12, PolicyID=11),
            "tcr.replicationpolicy",
            "HAS_METADATA",
        ),
        "tke.cluster": ("cls-one", {}, None, None),
        "tke.virtualnodepool": (
            "virtual-parent",
            dict(NodePoolId="np-one"),
            "tke.cluster",
            "HAS_METADATA",
        ),
        "tke.clusterroutetable": ("pod-routes", {}, None, None),
        "scf.function": ("function-one", dict(Namespace="default"), None, None),
        "apigateway.service": ("service-one", {}, None, None),
        "apigateway.api": ("api-parent", dict(ApiId="api-one"), "apigateway.service", "HAS_API"),
        "tse.gateway": ("gateway-one", {}, None, None),
        "tse.gatewayservice": (
            "service-parent",
            dict(Name="worker-service"),
            "tse.gateway",
            "HAS_METADATA",
        ),
        "teo.zone": ("zone-one", {}, None, None),
        "cam.user": ("101", {}, None, None),
    }

    def add(k):
        rid, props, pk, rel = definitions[k]
        nid = g.add(
            "100",
            "global" if k in {"teo.zone", "cam.user"} else region,
            k,
            rid,
            "worker" if k == "scf.function" else rid,
            source="fixture",
        )
        g.nodes[nid]["properties"].update(props)
        if pk:
            owner = add(pk)
            g.edge(owner["id"], nid, rel, "fixture")
        return g.nodes[nid]

    return g, add(kind) if kind else None


@pytest.mark.parametrize("read", READS, ids=lambda r: r.action)
def test_provider_response_and_request_scope(read):
    region = (
        "global" if read.service == "teo" else "ap-singapore" if read.service == "ses" else REGION
    )
    g, parent = parent_graph(read.parent, region)
    response = copy.deepcopy(RESPONSES[read.action])
    response.update(RequestId="request-one", UnrequestedSecret="never-retain")
    seen = []
    params = parameters(g, read, parent)

    def call(service, action, selected, **query):
        assert (service, action, selected) == (read.service, read.action, region)
        assert all(query[k] == v for k, v in params.items())
        seen.append(query)
        return response

    checked_read(runner(g, call, [region]), read, region, parent, params)
    assert seen and g.coverage[-1]["status"] == "complete", g.coverage
    actual = [n for n in g.nodes.values() if n["kind"] == read.kind]
    assert len(actual) == 1 and "never-retain" not in g.dump()
    assert actual[0]["account"] == "100" and actual[0]["region"] == region
    validate(g.snapshot())


@pytest.mark.parametrize(
    "action,path,wrong",
    [
        ("DescribeImmutableTagRules", "Rules.0.RegistryId", "tcr-other"),
        ("DescribeTagRetentionExecution", "RetentionExecutionList.0.RetentionId", 999),
        ("DescribeTagRetentionExecutionTask", "RetentionTaskList.0.ExecutionId", 999),
        ("DescribeReplicationExecutions", "ReplicationExecutionList.0.PolicyID", 999),
        ("DescribeCloudNativeAPIGateways", "Result.GatewayList.0.EngineRegion", "ap-guangzhou"),
        (
            "DescribeNativeGatewayServerGroups",
            "Result.GatewayGroupList.0.GatewayId",
            "gateway-other",
        ),
        ("DescribeCloudNativeAPIGatewayPorts", "Result.GatewayId", "gateway-other"),
        ("DescribeAliasDomains", "AliasDomains.0.ZoneId", "zone-other"),
        ("DescribeUserPermissions", "TargetUin", "999"),
        ("DescribeApiEnvironmentStrategy", "Result.ApiEnvironmentStrategySet.0.ApiId", "api-other"),
        ("DescribeClusterRoutes", "RouteSet.0.RouteTableName", "other-routes"),
    ],
)
def test_foreign_scope_rejected_before_mutation(action, path, wrong):
    read = next(r for r in READS if r.action == action)
    region = "global" if read.service == "teo" else REGION
    g, parent = parent_graph(read.parent)
    before = set(g.nodes)
    response = copy.deepcopy(RESPONSES[action])
    cursor = response
    parts = path.split(".")
    for part in parts[:-1]:
        cursor = cursor[int(part)] if isinstance(cursor, list) else cursor[part]
    cursor[parts[-1]] = wrong
    checked_read(
        runner(g, lambda *a, **kw: response), read, region, parent, parameters(g, read, parent)
    )
    assert g.coverage[-1]["status"] == "error" and set(g.nodes) == before


@pytest.mark.parametrize("action", [r.action for r in READS if r.result])
def test_duplicate_resource_is_partial_not_double_counted(action):
    read = next(r for r in READS if r.action == action)
    g, parent = parent_graph(read.parent)
    response = copy.deepcopy(RESPONSES[action])
    cursor = response
    for part in read.result.split("."):
        cursor = cursor[part]
    cursor.append(copy.deepcopy(cursor[0]))
    if read.total:
        obj = response
        parts = read.total.split(".")
        for part in parts[:-1]:
            obj = obj[part]
        obj[parts[-1]] = 2
    checked_read(
        runner(g, lambda *a, **kw: response),
        read,
        "global" if read.service == "teo" else REGION,
        parent,
        parameters(g, read, parent),
    )
    assert g.coverage[-1]["status"] == "error" and g.coverage[-1]["count"] == 0


def test_collector_chains_native_ids_and_rebuilds_exact_links():
    g = Graph()
    for kind in (
        "tcr.instance",
        "tcr.replicationpolicy",
        "tke.cluster",
        "scf.function",
        "apigateway.api",
        "cam.user",
    ):
        source, _ = parent_graph(kind)
        g.nodes.update(source.nodes)
        g.edges.update(source.edges)
    for kind, rid, region in [
        ("vpc.vpc", "vpc-one", REGION),
        ("vpc.subnet", "subnet-one", REGION),
        ("cvm.instance", "ins-one", REGION),
        ("ssl.certificate", "cert-one", "global"),
        ("scf.version", "function-one/1", REGION),
    ]:
        g.add("100", region, kind, rid, source="fixture")
    calls = []

    def call(service, action, region=None, **params):
        calls.append((service, action, region, params))
        return copy.deepcopy(RESPONSES[action])

    collect(runner(g, call), {"tcr", "tke", "scf", "apigateway", "tse", "teo"})
    errors = [r for r in g.coverage if r["status"] == "error"]
    assert not errors, errors
    assert len(calls) == len(READS) - 1
    retention = next(p for _, a, _, p in calls if a == "DescribeTagRetentionExecutionTask")
    assert (
        retention["RegistryId"] == "tcr-one"
        and retention["RetentionId"] == 8
        and retention["ExecutionId"] == 9
    )
    assert next(p for _, a, _, p in calls if a == "DescribeClusterVirtualNode") == dict(
        ClusterId="cls-one", NodePoolId="np-one"
    )
    relations = {e["relationship"] for e in g.edges.values()}
    assert relations >= {
        "CONFIGURED_FUNCTION_BACKEND",
        "CONFIGURED_CVM_BACKEND",
        "CONFIGURED_FUNCTION_QUALIFIER",
        "USES_CERTIFICATE",
        "CONFIGURED_CLUSTER_PERMISSION",
        "USES_SUBNET",
    }
    before = g.snapshot()
    link(g)
    assert g.snapshot()["edges"] == before["edges"]
    validate(g.snapshot())


def test_service_selection_unsupported_region_and_capability_records_do_not_call():
    g = Graph()
    collect(
        runner(g, lambda *a, **kw: pytest.fail("No API call expected")), {"ses", "ciam", "tdmq"}
    )
    assert {r["service"] for r in g.coverage} == {"ses", "ciam", "tdmq"}
    assert all(
        r["status"] == "unsupported" and r["count"] == 0 and not r["request_ids"]
        for r in g.coverage
    )


def test_native_principal_regions_and_official_assets_registered():
    assert ACTIONS <= ALLOWED_ACTIONS and KINDS <= DETAIL_KINDS | {
        "tse.gateway",
        "teo.zone",
        "apigateway.dedicatedinstance",
    }
    assert all(icon_for(k) != "unmapped.svg" for k in KINDS)
    assert service_modes()["tse"] == {"regional"} and service_modes()["teo"] == {"global"}
    plan = RegionPlan.build(None, "100", "default", [REGION], {"tse", "teo"}, [])
    assert plan.by_service["tse"] == [REGION] and "teo" not in plan.by_service


@pytest.mark.parametrize("ports", [[True], [0], [65536], ["443"], "443"])
def test_ports_are_typed_in_range_without_bool_coercion(ports):
    with pytest.raises(Exception):
        project(dict(PortList=ports), schema(integer_arrays="PortList"))


def test_backend_links_do_not_cross_account_region_or_ambiguous_names():
    read = next(r for r in READS if r.action == "ListCustomDomains")
    g = Graph()
    checked_read(runner(g, lambda *a, **kw: RESPONSES[read.action]), read, REGION, None, {})
    for account, region, rid in [
        ("200", REGION, "other-account"),
        ("100", "ap-guangzhou", "other-region"),
    ]:
        nid = g.add(account, region, "scf.function", rid, "worker")
        g.nodes[nid]["properties"]["Namespace"] = "default"
    link(g)
    assert not any(e["relationship"] == "CONFIGURED_FUNCTION_BACKEND" for e in g.edges.values())
    for rid in ("first", "second"):
        nid = g.add("100", REGION, "scf.function", rid, "worker")
        g.nodes[nid]["properties"]["Namespace"] = "default"
    link(g)
    assert not any(e["relationship"] == "CONFIGURED_FUNCTION_BACKEND" for e in g.edges.values())


def test_fifo_encryption_and_confirmation_absence_remains_unknown():
    g = Graph()
    for kind in ("tdmq.cmqqueue", "tdmq.cmqtopic", "tdmq.cmqsubscription"):
        g.add("100", REGION, kind, "native-one")
    link(g)
    assert all(
        n["properties"]["encryption_state"] == "not-exposed-by-collected-api"
        for n in g.nodes.values()
    )
    assert (
        next(n for n in g.nodes.values() if n["kind"] == "tdmq.cmqqueue")["properties"][
            "aws_fifo_equivalence"
        ]
        == "not-established"
    )


def test_scf_invocation_policy_analysis_uses_native_qcs_and_deny_precedence():
    from tencent_cloud_cartography.permissions import RULES, evaluate, identities

    g, fn = parent_graph("scf.function")
    scope = identities(fn)[0]
    assert scope == f"qcs::scf:{REGION}:uin/100:namespace/default/function/worker"
    assert RULES["scf.function"] == (("scf:InvokeFunction", "INVOKE_FUNCTION"),)
    statements = [("allow", dict(effect="allow", action=["scf:InvokeFunction"], resource=[scope]))]
    assert (
        evaluate(statements, "scf:InvokeFunction", scope)[0]
        == "allow_from_collected_identity_policies"
    )
    assert (
        evaluate(statements, "scf:InvokeFunction", scope.replace("uin/100", "uin/200"))[0]
        == "implicit_deny_from_collected_identity_policies"
    )
    statements.append(("deny", dict(effect="deny", action=["scf:*"], resource=["*"])))
    assert evaluate(statements, "scf:InvokeFunction", scope)[0] == "explicit_deny"


def test_tcr_control_pagination_uses_page_numbers_and_keeps_registry_scope():
    read = next(r for r in READS if r.action == "DescribeImmutableTagRules")
    g, parent = parent_graph(read.parent)
    calls = []

    def call(service, action, region, **params):
        assert params["RegistryId"] == "tcr-one" and params["PageSize"] == 100
        calls.append(params["Page"])
        start, end = (0, 100) if params["Page"] == 1 else (100, 101)
        return dict(
            Rules=[dict(RuleId=i, NsName="apps", Disabled=False) for i in range(start, end)],
            Total=101,
        )

    checked_read(runner(g, call), read, REGION, parent, parameters(g, read, parent))
    assert (
        calls == [1, 2]
        and g.coverage[-1]["status"] == "complete"
        and g.coverage[-1]["count"] == 101
    )


def test_ambiguous_registry_ancestry_cannot_form_a_request():
    from tencent_cloud_cartography.transport import CollectionError

    read = next(r for r in READS if r.action == "DescribeReplicationExecutions")
    g, parent = parent_graph(read.parent)
    second = g.add("100", REGION, "tcr.instance", "tcr-two")
    g.edge(second, parent["id"], "HAS_REPLICATION_POLICY", "fixture")
    with pytest.raises(CollectionError) as error:
        parameters(g, read, parent)
    assert error.value.code == "AmbiguousWorkloadMetadataParent"


def test_new_service_roots_run_through_real_orchestration_without_cloud_mutations():
    from tencent_cloud_cartography.collect import collect as sync
    from tencent_cloud_cartography.exclusions import EXCLUSIONS

    calls = []

    class Transport:
        def call(self, service, action, region=None, **params):
            calls.append((service, action, region))
            if service == "sts":
                return dict(AccountId="100", PrincipalId="reader")
            if service == "cloudrc":
                return dict(Resources=[])
            return copy.deepcopy(RESPONSES[action])

    snapshot = sync(
        ["fixture"],
        [REGION],
        services={"tse", "teo"},
        progress=lambda _: None,
        transport_factory=lambda _: Transport(),
    )
    kinds = {n["kind"] for n in snapshot["nodes"]}
    assert kinds >= {r.kind for r in READS if r.service in {"tse", "teo"}}
    assert {"vpc.vpc", "vpc.subnet"} <= kinds
    assert all(
        n["region"] == ("global" if n["kind"].startswith("teo.") else REGION)
        for n in snapshot["nodes"]
    )
    assert not ({(s, a) for s, a, _ in calls} & {(s, a) for s, a, _ in EXCLUSIONS})
    assert all(a.startswith(("Describe", "Get", "List", "Search")) for _, a, _ in calls)
    assert any(r["service"] == "teo" and r["status"] == "unsupported" for r in snapshot["coverage"])


def test_scf_invocation_analysis_integrates_policy_evidence_and_never_invokes():
    import json

    from tencent_cloud_cartography.cam import add_document, parse_document
    from tencent_cloud_cartography.permissions import analyze

    g, _ = parent_graph("scf.function")
    principal = g.add("100", "global", "cam.user", "101")
    policy = g.add("100", "global", "cam.policy", "1")
    add_document(
        g,
        policy,
        parse_document(
            json.dumps(
                dict(
                    version="2.0",
                    statement=[
                        dict(
                            effect="allow",
                            action=["scf:InvokeFunction"],
                            resource=[
                                f"qcs::scf:{REGION}:uin/100:namespace/default/function/worker"
                            ],
                        )
                    ],
                )
            )
        ),
        "fixture",
    )
    g.edge(principal, policy, "HAS_POLICY", "fixture")
    for action in ("ListUsers", "ListGroups", "DescribeRoleList"):
        g.coverage.append(
            dict(account="100", service="cam", action=action, status="complete", count=1)
        )
    g.coverage.append(
        dict(
            account="100",
            service="cam",
            action="ListAttachedUserPolicies",
            status="complete",
            detail=json.dumps(dict(TargetUin=101)),
        )
    )
    analyze(g)
    decisions = [n for n in g.nodes.values() if n["kind"] == "cam.permissiondecision"]
    assert len(decisions) == 1
    p = decisions[0]["properties"]
    assert (
        p["decision"] == "allow_from_collected_identity_policies"
        and not p["effective_access_verified"]
    )
    assert any(e["relationship"] == "BASED_ON_STATEMENT" for e in g.edges.values())
    assert ("scf", "InvokeFunction") not in ALLOWED_ACTIONS


def test_edgeone_global_reconciliation_requires_exact_native_identity_and_owner():
    from tencent_cloud_cartography.inventory import (
        add_resource,
        identity,
        reconcile_global_inventory,
    )

    read = next(r for r in READS if r.action == "DescribeZones")
    g = Graph()
    for account, rid in (("100", "zone-one"), ("200", "zone-one"), ("100", "zone-other")):
        raw = dict(Uin=account, ResourceType="qcs::teo::zone", ResourceId=rid)
        add_resource(g, account, raw, identity(raw, account))
    checked_read(runner(g, lambda *a, **kw: RESPONSES[read.action]), read, "global", None, {})
    reconcile_global_inventory(g)
    actual = [
        n for n in g.nodes.values() if n["account"] == "100" and n["resource_id"] == "zone-one"
    ]
    assert len(actual) == 1 and actual[0]["region"] == "global"
    assert actual[0]["properties"]["inventory_region_resolution"] == "native-global"
    assert len([n for n in g.nodes.values() if n["status"] == "inventory-only"]) == 2
