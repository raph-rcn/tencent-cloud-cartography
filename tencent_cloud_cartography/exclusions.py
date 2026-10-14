"""Explicit capability gaps imposed by the operator's metadata-only restriction."""

from .catalog import ALLOWED_ACTIONS

# These operations are deliberately never called. Response-field paths were
# audited against the Tencent SDK shipped with TCCLI 3.1.181.1.
EXCLUSIONS = (
    (
        "apigateway",
        "DescribeUpstreams",
        "Result.UpstreamSet.HealthChecker.ActiveRequestHeader.Value can contain credentials",
    ),
    ("mariadb", "DescribeDBEncryptAttributes", "CipherText is a DEK"),
    (
        "cdb",
        "DescribeInstanceParams",
        "Items.CurrentValue can contain init_connect SQL workload configuration",
    ),
    (
        "mariadb",
        "DescribeDBParameters",
        "Params.Value can contain init_connect SQL workload configuration",
    ),
    ("cdb", "DescribeBackups", "Items.IntranetUrl/InternetUrl are backup download capabilities"),
    ("postgres", "DescribeBackupDownloadURL", "backup download capabilities"),
    (
        "sqlserver",
        "DescribeBackups",
        "Backups.ExternalAddr/InternalAddr are backup download capabilities",
    ),
    ("tcss", "DescribeAssetContainerList", "List.Cmd"),
    ("organization", "ListUsers", "Users.Password"),
    ("organization", "GetUser", "UserInfo.Password"),
    ("coding", "DescribeCodingCIJobs", "JobList.JenkinsFileStaticContent/EnvList"),
    ("coding", "DescribeCodingCIJob", "Job.JenkinsFileStaticContent/EnvList"),
    ("lke", "DescribeAppAgentList", "Agents.Instructions/Tools/Plugins"),
    (
        "cvm",
        "DescribeLaunchTemplateVersions",
        "LaunchTemplateVersionSet.LaunchTemplateVersionData.UserData",
    ),
    ("tat", "DescribeCommands", "CommandSet.Content/DefaultParameters"),
    ("tke", "DescribeClusterInstances", "InstanceSet.InstanceAdvancedSettings.UserScript"),
    ("tke", "DescribeEKSContainerInstances", "EksCis.Containers.EnvironmentVars"),
    ("scf", "GetFunction", "Environment.Variables and function source"),
    ("tcr", "DescribeImageManifests", "Config contains image environment/history"),
    ("tcaplusdb", "DescribeClusters", "Clusters.Password"),
    ("tcaplusdb", "DescribeTables", "TableInfos.IdlFiles.FileContent"),
    ("tione", "DescribeModelServiceGroups", "ServiceGroups.Services.ServiceInfo.Env"),
    ("tione", "DescribeTrainingTasks", "TrainingTaskSet.Envs"),
    (
        "tione",
        "DescribeTrainingModelVersions",
        "TrainingModelVersions.ReasoningImageInfo.ImageSecret",
    ),
    ("csip", "DescribeAlertList", "AlertList.ExtraInfo.LeakContent/SecretID/PayloadContent"),
    ("autoscaling", "DescribeLaunchConfigurations", "LaunchConfigurationSet.UserData"),
    (
        "cdn",
        "DescribeDomains",
        "domain origin/authentication configuration can contain credentials",
    ),
)


def record(graph, account, regions, services=None, region_map=None):
    for service, action, field in EXCLUSIONS:
        selected = "autoscaling" if service == "autoscaling" else service
        if services and selected not in services:
            continue
        if (service, action) in ALLOWED_ACTIONS:
            raise ValueError("Excluded workload API is present in metadata allowlist")
        for region in (
            ["global"]
            if service in ("csip", "cdn", "organization", "tcss")
            else (region_map.get(service, []) if region_map is not None else regions)
        ):
            if any(
                r["account"] == account
                and r["service"] == service
                and r["action"] == action
                and r["region"] == region
                for r in graph.coverage
            ):
                continue
            graph.coverage.append(
                dict(
                    account=account,
                    region=region,
                    service=service,
                    action=action,
                    detail="Excluded response field: " + field,
                    status="unsupported",
                    error="UnsupportedMetadataOnlyProjection",
                    count=0,
                    request_ids=[],
                )
            )
