"""Additional provider families with explicit metadata schemas and independent scopes."""

import json

from .catalog import EXTRA_COLLECTORS, Collector
from .transport import CollectionError, pages
from .vpc import fields

FIELDS = {
    "tcaplusdb.tablegroup": (
        ("TableGroupId", "TableGroupName", "CreatedTime", "MysqlConnIp"),
        (),
        ("TableCount", "TotalSize", "TxhBackupExpireDay", "EnableMysql", "MysqlConnPort"),
    ),
    "tic.stack": (
        ("StackId", "StackName", "Description", "Region", "Status", "CreateTime"),
        (),
        (),
    ),
    "tic.version": (
        ("VersionId", "VersionName", "Description", "StackId", "Status", "CreateTime"),
        (),
        (),
    ),
    "tic.event": (("EventId", "VersionId", "StackId", "Type", "Status", "CreateTime"), (), ()),
    "cvm.reservedinstance": (
        (
            "ReservedInstanceId",
            "ReservedInstancesId",
            "ReservedInstanceName",
            "InstanceType",
            "Zone",
            "StartTime",
            "EndTime",
            "ProductDescription",
            "State",
            "CurrencyCode",
            "OfferingType",
            "InstanceFamily",
        ),
        (),
        ("Duration", "InstanceCount"),
    ),
    "wedata.task": (
        (
            "TaskId",
            "TaskName",
            "WorkflowId",
            "WorkflowName",
            "Status",
            "CreateTime",
            "LastUpdateTime",
            "OwnerUin",
            "TaskDescription",
            "TaskLatestVersionNo",
            "TaskLatestSubmitVersionNo",
        ),
        ("Submit",),
        ("TaskTypeId",),
    ),
    "wedata.workflow": (
        (
            "WorkflowId",
            "WorkflowName",
            "WorkflowType",
            "OwnerUin",
            "CreateTime",
            "ModifyTime",
            "UpdateUserUin",
            "WorkflowDesc",
            "CreateUserUin",
        ),
        (),
        (),
    ),
    "ciam.userstore": (
        ("TenantId", "UserStoreName", "UserStoreDesc", "UserStoreProtocolHost"),
        ("LastStatus", "DefaultStatus"),
        ("UserNum", "AppNum", "CreateDate", "LastStatusTime"),
    ),
    "cam.samlprovider": (("Name", "Description", "CreateTime", "ModifyTime"), (), ()),
    "organization.unit": (
        ("Name", "Remark", "CreateTime", "UpdateTime"),
        (),
        ("NodeId", "ParentNodeId"),
    ),
    "organization.member": (
        (
            "Name",
            "MemberType",
            "OrgPolicyType",
            "OrgPolicyName",
            "NodeName",
            "CreateTime",
            "UpdateTime",
            "IsAllowQuit",
            "BindStatus",
            "PermissionStatus",
        ),
        (),
        ("MemberUin", "NodeId"),
    ),
    "cwp.machine": (
        (
            "MachineName",
            "MachineOs",
            "MachineStatus",
            "AgentStatus",
            "InstanceStatus",
            "Uuid",
            "Quuid",
            "MachineIp",
            "MachineWanIp",
            "SecurityStatus",
            "InstanceState",
            "MachineType",
            "KernelVersion",
            "ProtectType",
            "InstanceId",
            "AgentVersion",
            "CSIPProtectType",
        ),
        ("IsProVersion",),
        (
            "VulNum",
            "MalwareNum",
            "BaselineNum",
            "CyberAttackNum",
            "InvasionNum",
            "LicenseStatus",
            "ProjectId",
            "HasAssetScan",
        ),
    ),
    "tcss.cluster": (
        (
            "ClusterID",
            "ClusterName",
            "Status",
            "BindRuleID",
            "BindRuleName",
            "ClusterType",
            "ClusterVersion",
            "ClusterAuditStatus",
            "AccessedStatus",
        ),
        (),
        ("MemLimit", "CpuLimit"),
    ),
    "tcss.image": (("ImageID", "ImageName", "ScanTime"), (), ("ContainerCnt", "Size")),
    "csip.checkrule": (
        (
            "RuleID",
            "Provider",
            "InstanceType",
            "RiskTitle",
            "CheckType",
            "RiskLevel",
            "DispositionType",
        ),
        (),
        (),
    ),
    "tione.resourcegroup": (
        ("ResourceGroupId", "ResourceGroupName"),
        (),
        ("FreeInstance", "TotalInstance"),
    ),
    "tione.notebook": (
        (
            "Id",
            "Name",
            "ChargeType",
            "ResourceGroupId",
            "CreateTime",
            "StartTime",
            "UpdateTime",
            "ChargeStatus",
            "Status",
            "EndTime",
            "PodName",
            "InstanceTypeAlias",
            "ResourceGroupName",
            "VolumeSourceType",
            "SubUin",
            "Description",
        ),
        ("AutoStopping",),
        ("VolumeSizeInGB", "RuntimeInSeconds", "AutomaticStopTime"),
    ),
    "dlc.engine": (
        (
            "DataEngineName",
            "DataEngineId",
            "EngineType",
            "ClusterType",
            "ExpireTime",
            "IsolatedTime",
            "EngineExecType",
            "ResourceType",
            "ImageVersionId",
            "EngineGeneration",
            "EngineTypeDetail",
            "EngineNetworkId",
            "EngineNetworkName",
        ),
        (
            "AutoResume",
            "AutoSuspend",
            "DefaultDataEngine",
            "StartStandbyCluster",
            "ElasticSwitch",
            "AutoAuthorization",
        ),
        (
            "State",
            "CreateTime",
            "UpdateTime",
            "Size",
            "Mode",
            "MinClusters",
            "MaxClusters",
            "SpendAfter",
            "AutoSuspendTime",
            "ElasticLimit",
            "MaxConcurrency",
            "TolerableQueueTime",
            "NodeNum",
        ),
    ),
    "wedata.project": (
        (
            "ProjectId",
            "ProjectName",
            "DisplayName",
            "Description",
            "CreateTime",
            "CreatorUin",
            "ProjectOwnerUin",
            "ProjectModel",
        ),
        (),
        ("Status",),
    ),
    "tat.agent": (
        ("InstanceId", "Version", "LastHeartbeatTime", "AgentStatus", "Environment"),
        (),
        (),
    ),
}


def collect(runner, spec, region, params=None, parent=None):
    graph, selected = runner.graph, []

    def operation(record):
        seen = set()
        for batch, request in pages(runner.transport, spec, region, params):
            if request:
                record["request_ids"].append(request)
            prepared = []
            for raw in batch:
                props = fields({k: v for k, v in raw.items() if k != "State"}, *FIELDS[spec.kind])
                if "State" in FIELDS[spec.kind][2] and raw.get("State") is not None:
                    if type(raw["State"]) is not int:
                        raise CollectionError("InvalidFamilyState")
                    props["State"] = raw["State"]
                if spec.kind == "cvm.reservedinstance" and props.get("Zone"):
                    if props["Zone"].startswith(region + "-"):
                        props["zone"] = props["Zone"]
                    else:
                        props["zone_placement_unresolved"] = True
                if spec.kind.startswith("tic.") and raw.get("Region") not in (None, region):
                    raise CollectionError("TicRegionMismatch")
                if (
                    parent
                    and spec.kind.startswith("tic.")
                    and raw.get("StackId") != parent["resource_id"]
                ):
                    raise CollectionError("TicStackMismatch")
                value = next((raw[k] for k in spec.ids if raw.get(k) is not None), None)
                if (
                    type(value) not in (str, int)
                    or not str(value)
                    or any(c in str(value) for c in "/\\\n\r")
                ):
                    raise CollectionError("InvalidFamilyIdentity")
                rid = str(value)
                if parent:
                    rid = parent["resource_id"] + "/" + rid
                if rid in seen:
                    raise CollectionError("DuplicateFamilyIdentity")
                seen.add(rid)
                prepared.append((rid, props, raw))
            for rid, props, raw in prepared:
                nid = graph.add(
                    runner.account,
                    region,
                    spec.kind,
                    rid,
                    next((props[k] for k in spec.names if props.get(k)), None),
                    source=spec.service + "." + spec.action,
                )
                graph.nodes[nid]["properties"].update(props)
                if parent:
                    graph.nodes[nid]["properties"]["parent_resource_id"] = parent["resource_id"]
                    graph.edge(parent["id"], nid, "CONTAINS", spec.service + "." + spec.action)
                links(runner, graph.nodes[nid], raw)
                selected.append(nid)
                record["count"] += 1

    runner.scope(
        spec.service,
        spec.action,
        region,
        operation,
        json.dumps(params, sort_keys=True) if params else "",
    )
    return selected


def links(runner, node, raw):
    graph, source = runner.graph, node["sources"][-1]
    if node["kind"] == "wedata.task" and raw.get("WorkflowId"):
        project = node["properties"].get("parent_resource_id")
        if project:
            target = graph.add(
                runner.account,
                node["region"],
                "wedata.workflow",
                project + "/" + raw["WorkflowId"],
                source=source,
                status="reference",
            )
            graph.edge(target, node["id"], "HAS_TASK", source)
    if node["kind"] == "tic.event" and raw.get("VersionId"):
        stack = node["properties"].get("parent_resource_id")
        if stack:
            target = graph.add(
                runner.account,
                node["region"],
                "tic.version",
                stack + "/" + raw["VersionId"],
                source=source,
                status="reference",
            )
            graph.edge(target, node["id"], "HAS_EVENT", source)
    if node["kind"] == "organization.unit" and raw.get("ParentNodeId") not in (None, 0):
        target = graph.add(
            runner.account,
            "global",
            "organization.unit",
            str(raw["ParentNodeId"]),
            source=source,
            status="reference",
        )
        graph.edge(node["id"], target, "CHILD_OF", source)
    if node["kind"] == "organization.member" and raw.get("NodeId") is not None:
        target = graph.add(
            runner.account,
            "global",
            "organization.unit",
            str(raw["NodeId"]),
            source=source,
            status="reference",
        )
        graph.edge(node["id"], target, "MEMBER_OF", source)
        node["properties"]["member_inventory_collected"] = False
    if node["kind"] in ("cwp.machine", "tat.agent"):
        rid = raw.get("InstanceId")
        if isinstance(rid, str) and rid.startswith("ins-"):
            target = graph.add(
                runner.account,
                node["region"],
                "cvm.instance",
                rid,
                source=source,
                status="reference",
            )
            graph.edge(target, node["id"], "HAS_AGENT_INFORMATION", source)
    if node["kind"] == "tat.agent":
        features = raw.get("SupportFeatures")
        if features is not None:
            if not isinstance(features, list) or not all(isinstance(f, str) for f in features):
                raise CollectionError("InvalidAutomationFeatures")
            node["properties"]["SupportFeatures"] = json.dumps(features)
    if node["kind"] == "tione.notebook":
        if raw.get("ResourceGroupId"):
            target = graph.add(
                runner.account,
                node["region"],
                "tione.resourcegroup",
                raw["ResourceGroupId"],
                source=source,
                status="reference",
            )
            graph.edge(node["id"], target, "USES_RESOURCE_GROUP", source)
        if raw.get("ResourceConf"):
            node["properties"]["resources"] = json.dumps(
                fields(
                    raw["ResourceConf"],
                    ("GpuType", "InstanceType"),
                    integers=("Cpu", "Memory", "Gpu"),
                ),
                sort_keys=True,
            )
        if isinstance(raw.get("VolumeSourceCFS"), dict) and raw["VolumeSourceCFS"].get("Id"):
            target = graph.add(
                runner.account,
                node["region"],
                "cfs.filesystem",
                raw["VolumeSourceCFS"]["Id"],
                source=source,
                status="reference",
            )
            graph.edge(node["id"], target, "USES_FILE_SYSTEM", source)
    if node["kind"] == "tione.resourcegroup":
        for key in ("UsedResource", "TotalResource"):
            if raw.get(key) is not None:
                node["properties"][key] = json.dumps(
                    fields(raw[key], integers=("Cpu", "Memory", "Gpu")), sort_keys=True
                )
    if node["kind"] == "dlc.engine":
        networks = raw.get("NetworkConnectionSet") or []
        if not isinstance(networks, list):
            raise CollectionError("InvalidDlcNetworkConnections")
        for net in networks:
            # These are data-source networks, not the engine's own placement.
            for field, kind, prefix in [
                ("DatasourceConnectionVpcId", "vpc.vpc", "vpc-"),
                ("DatasourceConnectionSubnetId", "vpc.subnet", "subnet-"),
            ]:
                value = net.get(field)
                if isinstance(value, str) and value.startswith(prefix):
                    target = graph.add(
                        runner.account,
                        node["region"],
                        kind,
                        value,
                        source=source,
                        status="reference",
                    )
                    graph.edge(node["id"], target, "CONFIGURED_DATASOURCE_NETWORK", source)


def run(runner, services):
    for spec in EXTRA_COLLECTORS:
        if services and spec.service not in services:
            continue
        for region in runner.regions_for(spec.service) if spec.regional else ["global"]:
            if spec.service == "cwp":
                collect(runner, spec, region, dict(MachineType="CVM", MachineRegion=region))
            elif spec.kind == "tione.resourcegroup":
                collect(runner, spec, region, dict(DontShowInstanceSet=True))
            elif spec.kind == "dlc.engine":
                for generation in ("Native", "SuperSQL"):
                    for engine in ("spark", "presto", "kyuubi"):
                        for execution in ("SQL", "BATCH"):
                            collect(
                                runner,
                                spec,
                                region,
                                dict(
                                    EngineGeneration=generation,
                                    EngineType=engine,
                                    EngineExecType=execution,
                                    ExcludePublicEngine=True,
                                ),
                            )
            else:
                collect(runner, spec, region)
    if not services or not {"cwp", "tcss"}.isdisjoint(services):
        from .security_inventory import collect as collect_security_inventory

        collect_security_inventory(runner)
    if not services or "organization" in services:
        from .identity_center import collect as collect_identity_center

        collect_identity_center(runner)
    if not services or "tcaplusdb" in services:
        tcaplus_groups(runner)
    if not services or "lke" in services:
        from .lke import collect as collect_lke

        for region in runner.regions_for("lke"):
            collect_lke(runner, region)
    if not services or "tic" in services:
        tic_details(runner)
    if not services or "csip" in services:
        security_status(runner)
    if not services or "cam" in services:
        federation(runner)
    if not services or "wedata" in services:
        workflows(runner)


def federation(runner):
    def operation(record):
        data = runner.transport.call("cam", "DescribeUserOIDCConfig", "global")
        if data.get("RequestId"):
            record["request_ids"].append(data["RequestId"])
        props = fields(
            data,
            (
                "IdentityUrl",
                "ClientId",
                "AuthorizationEndpoint",
                "ResponseType",
                "ResponseMode",
                "MappingFiled",
                "Description",
            ),
            integers=("ProviderType", "Status", "AutoRotateKey"),
        )
        nid = runner.graph.add(
            runner.account, "global", "cam.useroidc", "account", source="cam.DescribeUserOIDCConfig"
        )
        runner.graph.nodes[nid]["properties"].update(props, effective_access_verified=False)
        record["count"] = 1

    runner.scope("cam", "DescribeUserOIDCConfig", "global", operation)


def workflows(runner):
    spec = Collector(
        "wedata",
        "ListWorkflows",
        "Data.Items",
        "wedata.workflow",
        ("WorkflowId",),
        ("WorkflowName",),
        total="Data.TotalCount",
        paging="number-page",
        require_total=True,
    )
    for parent in list(runner.graph.nodes.values()):
        if (
            parent["kind"] == "wedata.project"
            and parent["account"] == runner.account
            and parent["status"] == "enriched"
        ):
            collect(runner, spec, parent["region"], dict(ProjectId=parent["resource_id"]), parent)
            tasks = Collector(
                "wedata",
                "ListTasks",
                "Data.Items",
                "wedata.task",
                ("TaskId",),
                ("TaskName",),
                total="Data.TotalCount",
                paging="number-page",
                require_total=True,
            )
            collect(runner, tasks, parent["region"], dict(ProjectId=parent["resource_id"]), parent)


def security_status(runner):
    for action, kind, numbers in (
        ("DescribeLicenseStatus", "csip.hub", ("AutoRepurchaseSwitch", "UnbindCountLeft")),
        (
            "DescribeEdrAlertSummary",
            "csip.threatsummary",
            ("CriticalPendingCount", "TotalPendingCount"),
        ),
    ):

        def operation(record, action=action, kind=kind, numbers=numbers):
            data = runner.transport.call("csip", action, "global")
            if data.get("RequestId"):
                record["request_ids"].append(data["RequestId"])
            props = fields(data, integers=numbers)
            if not props:
                raise CollectionError("MissingSecurityStatus")
            licences = []
            if action == "DescribeLicenseStatus":
                if not isinstance(data.get("List"), list):
                    raise CollectionError("InvalidSecurityLicenses")
                licences = [
                    fields(
                        item,
                        ("ResourceId", "LicenseType", "Name", "BeginTime", "EndTime"),
                        integers=("Category", "TotalNum", "UsedNum", "RemainNum"),
                    )
                    for item in data["List"]
                ]
            nid = runner.graph.add(
                runner.account, "global", kind, "account", source="csip." + action
            )
            runner.graph.nodes[nid]["properties"].update(
                props,
                source_reported=True,
                independently_validated=False,
                licences=json.dumps(licences, sort_keys=True),
            )
            record["count"] = 1

        runner.scope("csip", action, "global", operation)


def tic_details(runner):
    for stack in list(runner.graph.nodes.values()):
        if (
            stack["kind"] != "tic.stack"
            or stack["account"] != runner.account
            or stack["status"] != "enriched"
        ):
            continue
        for action, result, kind, key, label in (
            ("DescribeStackVersions", "Versions", "tic.version", "VersionId", "VersionName"),
            ("DescribeStackEvents", "Events", "tic.event", "EventId", "EventId"),
        ):
            spec = Collector("tic", action, result, kind, (key,), (label,), require_total=True)
            collect(
                runner,
                spec,
                stack["region"],
                dict(Filters=[dict(Name="StackId", Values=[stack["resource_id"]])]),
                stack,
            )


def tcaplus_groups(runner):
    """Groups for clusters already identified by CloudRC; never list passwords/IDL bodies."""
    spec = Collector(
        "tcaplusdb",
        "DescribeTableGroups",
        "TableGroups",
        "tcaplusdb.tablegroup",
        ("TableGroupId",),
        ("TableGroupName",),
        require_total=True,
    )
    for cluster in list(runner.graph.nodes.values()):
        if (
            cluster["kind"] == "tcaplusdb.cluster"
            and cluster["account"] == runner.account
            and cluster["region"] in runner.regions_for("tcaplusdb")
            and cluster["resource_id"].isdigit()
        ):
            collect(
                runner, spec, cluster["region"], dict(ClusterId=cluster["resource_id"]), cluster
            )
