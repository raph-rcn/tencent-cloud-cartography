"""Collect metadata, retain incomplete scopes, and reconcile by canonical resource IDs."""

import json

from .catalog import (
    CHILDREN,
    COLLECTORS,
    DNS_RECORDS,
    EXTRA_COLLECTORS,
    SCF_FUNCTIONS,
    SCF_NAMESPACES,
)
from .model import Graph, first, stable_id
from .transport import CollectionError, TccliTransport, pages


def status_for(code):
    low = code.lower()
    if low.startswith(("unauthorized", "authfailure", "operationdenied", "accessdenied")):
        return "denied"
    if low.startswith(("invalidaction", "unsupported")):
        return "unsupported"
    return "error"


class CollectorRunner:
    def __init__(self, graph, transport, account, regions, progress=print, plan=None):
        self.graph, self.transport, self.account = graph, transport, str(account)
        self.regions, self.progress = regions, progress
        self.plan = plan

    def regions_for(self, service):
        return self.plan.regions_for(service) if self.plan else self.regions

    def scope(self, service, action, region, operation, detail=""):
        record = dict(
            account=self.account,
            region=region or "global",
            service=service,
            action=action,
            detail=detail,
            status="complete",
            count=0,
            request_ids=[],
        )
        self.progress(
            f"{self.account} / {region or 'global'} / {service}.{action} {detail}".rstrip()
        )
        if self.plan and not self.plan.permitted(service, region):
            record.update(status="not-queried", error="OutsideCollectionPlan")
            self.graph.coverage.append(record)
            return record
        try:
            operation(record)
            if record["count"] == 0:
                record["status"] = "empty"
        except CollectionError as exc:
            record.update(status=status_for(exc.code), error=exc.code)
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            # No raw exception text: it might contain an API payload.
            record.update(status="error", error="InvalidResponse", error_type=type(exc).__name__)
        self.graph.coverage.append(record)
        return record

    def baseline(self, region):
        from .inventory import add_resource, identity

        def operation(record):
            token, seen_tokens, seen_resources = None, set(), set()
            record["scanned_count"] = 0
            for _ in range(10000):
                args = dict(MaxResults=100)
                if region != "global":
                    args["Filters"] = [
                        {"Key": "RegionCode", "Values": [region], "MatchType": "Equals"}
                    ]
                if token:
                    args["NextToken"] = token
                response = self.transport.call("cloudrc", "SearchResources", **args)
                if response.get("RequestId"):
                    record["request_ids"].append(response["RequestId"])
                resources = response.get("Resources")
                if not isinstance(resources, list):
                    raise CollectionError("InvalidResponse")
                for item in resources:
                    parsed = identity(item, self.account)
                    kind, rid, actual_region, resolution = parsed
                    key = (kind, rid, actual_region)
                    if key in seen_resources:
                        raise CollectionError("DuplicateInventoryResource")
                    seen_resources.add(key)
                    record["scanned_count"] += 1
                    if actual_region != region:
                        if region == "global":
                            if actual_region != "unknown" and not (
                                self.plan and self.plan.automatic and self.plan.restrictions is None
                            ):
                                continue
                        else:
                            raise CollectionError("RegionMismatch")
                    add_resource(self.graph, self.account, item, parsed)
                    record["count"] += 1
                token = response.get("NextToken")
                if token is not None and not isinstance(token, str):
                    raise CollectionError("InvalidInventoryToken")
                if not token:
                    return
                if token in seen_tokens:
                    raise CollectionError("PaginationStalled")
                seen_tokens.add(token)
            raise CollectionError("PageLimit")

        return self.scope("cloudrc", "SearchResources", region, operation)

    def native(self, spec, region, params=None, parent=None, relation=None):
        collected = []
        if spec.service == "monitor":
            params = {**(params or {}), "Module": "monitor"}
        if spec.service == "dnspod" and spec.action == "DescribeDomainList":
            params = {**(params or {}), "Type": "MINE"}
        if spec.action == "ListPolicies":
            # Preset policies enter through actual attachments; do not collect the
            # entire provider catalog as though every policy belongs to this account.
            params = {**(params or {}), "Scope": "Local"}
        if spec.service == "cvm" and spec.action == "DescribeImages":
            params = {
                **(params or {}),
                "Filters": [{"Name": "image-type", "Values": ["PRIVATE_IMAGE"]}],
            }
        if spec.action == "DescribeLoadBalancersDetail":
            # Tencent returns only the two ID/name fields by default.
            params = {
                **(params or {}),
                "Fields": [
                    "LoadBalancerId",
                    "LoadBalancerName",
                    "VpcId",
                    "ListenerId",
                    "Protocol",
                    "Port",
                    "LocationId",
                    "Domain",
                    "TargetId",
                    "TargetAddress",
                    "TargetPort",
                    "SecurityGroup",
                ],
            }
        source = f"{spec.service}.{spec.action}"

        def operation(record):
            from .catalog import ALLOWED_ACTIONS

            if (spec.service, spec.action) not in ALLOWED_ACTIONS:
                raise CollectionError("UnsupportedMetadataOnlyProjection")
            monitor_ids = set()
            cls_alarm_ids = set()
            scheduled_sql_ids = set()
            cfs_ids = set()
            cmq_ids, cmq_names = set(), set()
            eb_ids = set()
            ses_ids = set()
            config_ids = set()
            kafka_ids, kafka_names = set(), set()
            for items, request_id in pages(self.transport, spec, region, params):
                if request_id:
                    record["request_ids"].append(request_id)
                for item in items:
                    if spec.service == "config":
                        from .cloudconfig import prepare

                        item = prepare(item)
                        if item["ConfigRuleId"] in config_ids:
                            raise CollectionError("DuplicateConfigRule")
                        config_ids.add(item["ConfigRuleId"])
                    if spec.service == "ses":
                        from .ses import prepare

                        item = prepare(item)
                        if item["IdentityName"] in ses_ids:
                            raise CollectionError("DuplicateSesIdentity")
                        ses_ids.add(item["IdentityName"])
                    if spec.service == "eb":
                        from .eventbridge import prepare

                        item = prepare(spec.kind, item, params or {})
                        rid = first(item, spec.ids)
                        if rid in eb_ids:
                            raise CollectionError("DuplicateEventBridgeResource")
                        eb_ids.add(rid)
                    if spec.kind.startswith("tdmq.cmq"):
                        from .cmq import prepare

                        item = prepare(spec.kind, item, params or {}, self.graph.nodes.get(parent))
                        rid, name = first(item, spec.ids), first(item, spec.names)
                        if rid in cmq_ids or name in cmq_names:
                            raise CollectionError("DuplicateCmqResource")
                        cmq_ids.add(rid)
                        cmq_names.add(name)
                    if spec.service == "ckafka":
                        from .ckafka import prepare

                        item = prepare(spec.kind, item, params or {})
                        rid = first(item, spec.ids)
                        name = item.get("TopicName")
                        if rid in kafka_ids or (name is not None and name in kafka_names):
                            raise CollectionError("DuplicateKafkaResource")
                        kafka_ids.add(rid)
                        kafka_names.add(name)
                    if spec.service == "cfs":
                        from .cfs import prepare

                        item = prepare(spec.kind, item, params or {})
                        rid = first(item, spec.ids)
                        if rid in cfs_ids:
                            raise CollectionError("DuplicateCfsResource")
                        cfs_ids.add(rid)
                    if spec.kind == "cls.scheduledsql":
                        from .observability import string

                        rid = string(item.get("TaskId"))
                        if rid in scheduled_sql_ids:
                            raise CollectionError("DuplicateScheduledSqlTask")
                        scheduled_sql_ids.add(rid)
                    if spec.kind in {"cls.alarm", "cls.alarmnotice"}:
                        from .cls_alarms import identity

                        rid = identity(item.get(spec.ids[0]), spec.kind)
                        if rid in cls_alarm_ids:
                            raise CollectionError("DuplicateClsAlarmIdentity")
                        cls_alarm_ids.add(rid)
                    if spec.kind == "monitor.policy":
                        from .monitor import policy_id

                        policy_id(item.get("PolicyId"))
                        if item["PolicyId"] in monitor_ids:
                            raise CollectionError("DuplicateAlarmPolicy")
                        monitor_ids.add(item["PolicyId"])
                    if spec.kind == "cls.topic" and (
                        type(item.get("BizType")) is not int
                        or item["BizType"] != (params or {}).get("BizType", 0)
                    ):
                        raise CollectionError("TopicTypeMismatch")
                    if spec.kind == "cloudaudit.track" and (
                        type(item.get("TrackId")) is not int or item["TrackId"] <= 0
                    ):
                        raise CollectionError("InvalidAuditTrackId")
                    if spec.kind == "ssl.certificate" and str(item.get("OwnerUin")) != self.account:
                        raise CollectionError("AccountMismatch")
                    if spec.kind == "privatedns.zone" and str(item.get("OwnerUin")) != self.account:
                        raise CollectionError("AccountMismatch")
                    if spec.kind == "cvm.launchtemplateversion":
                        version = item.get("LaunchTemplateVersion")
                        template = item.get("LaunchTemplateId") or (params or {}).get(
                            "LaunchTemplateId"
                        )
                        if version is None or not template:
                            raise CollectionError("InvalidResponse")
                        item = {
                            **item,
                            "LaunchTemplateId": template,
                            "VersionResourceId": f"{template}/{version}",
                        }
                    if spec.kind == "vpc.ccnattachment":
                        if not item.get("InstanceId"):
                            raise CollectionError("InvalidResponse")
                        item = {
                            **item,
                            "AttachmentId": stable_id(
                                (params or {}).get("CcnId"),
                                item.get("InstanceUin"),
                                item.get("InstanceRegion"),
                                item["InstanceId"],
                            ),
                        }
                    if spec.kind == "scf.function":
                        namespace = (params or {}).get("Namespace", "default")
                        if item.get("Namespace") not in (None, namespace):
                            raise CollectionError("ScfNamespaceMismatch")
                        item = {
                            **item,
                            "Namespace": namespace,
                            "FunctionId": item.get("FunctionId")
                            or f"{namespace}/{item['FunctionName']}",
                        }
                    nid = self.graph.native(self.account, region, spec, item, source)
                    collected.append((nid, item))
                    if parent:
                        self.graph.edge(parent, nid, relation or "CONTAINS", source)
                    record["count"] += 1

        self.scope(
            spec.service, spec.action, region, operation, json.dumps(params) if params else ""
        )
        return collected

    def security_rules(self, region, groups):
        from .security_groups import collect_rules

        collect_rules(self, region, groups)

    def buckets(self):
        from .cos import collect_bucket

        selected = []

        def operation(record):
            for bucket in self.transport.buckets():
                if bucket["region"] not in self.regions_for("cos"):
                    continue
                nid = self.graph.add(
                    self.account,
                    bucket["region"],
                    "cos.bucket",
                    bucket["name"],
                    source="cos.list_buckets",
                )
                selected.append(nid)
                record["count"] += 1

        self.scope("cos", "list_buckets", "global", operation)
        for nid in selected:
            collect_bucket(self, nid)

    def run(self, services=None):
        # Baseline is always retained, including unresolved supported product types.
        for region in [*self.regions, "global"]:
            self.baseline(region)
        for spec in COLLECTORS:
            if services and spec.service not in services:
                continue
            for region in self.regions_for(spec.service) if spec.regional else ["global"]:
                if spec.service in {
                    "cdb",
                    "postgres",
                    "redis",
                    "mongodb",
                    "mariadb",
                    "sqlserver",
                    "cdwpg",
                }:
                    from dataclasses import replace

                    from .databases import collect as collect_database

                    collect_database(
                        self,
                        replace(spec, require_total=True),
                        region,
                        {"PaginationType": "offset"} if spec.service == "sqlserver" else None,
                    )
                    continue
                if spec.kind == "tke.cluster":
                    from .tke import collect as collect_tke

                    collect_tke(self, spec, region)
                    continue
                if spec.kind == "es.instance":
                    from .elasticsearch import collect as collect_elasticsearch

                    collect_elasticsearch(self, spec, region)
                    continue
                if spec.kind == "vpc.peeringconnection":
                    from .peering import collect as collect_peering

                    collect_peering(self, spec, region)
                    continue
                if spec.kind == "vpc.networkacl":
                    from .network_acls import collect as collect_acls

                    collect_acls(self, spec, region)
                    continue
                if spec.kind == "vpc.routetable":
                    from .routes import collect as collect_routes

                    collect_routes(self, spec, region)
                    continue
                if spec.kind in {
                    "vpc.securitygroup",
                    "vpc.addresstemplate",
                    "vpc.addresstemplategroup",
                    "vpc.servicetemplate",
                    "vpc.servicetemplategroup",
                }:
                    from .security_groups import collect as collect_security_groups

                    collect_security_groups(self, spec, region)
                    continue
                if spec.kind in {"vpc.vpc", "vpc.subnet"}:
                    from .vpc import collect as collect_vpc

                    collect_vpc(self, spec, region)
                    continue
                if spec.kind in {"vpc.endpoint", "vpc.endpointservice"}:
                    from .privatelink import collect as collect_privatelink

                    collect_privatelink(self, spec, region)
                    continue
                if spec.kind == "vpc.ccn":
                    from .ccn import collect as collect_ccn

                    collect_ccn(self, spec)
                    continue
                if spec.kind in {"vpc.networkinterface", "vpc.eip"}:
                    from .network_addresses import collect as collect_network_addresses

                    collect_network_addresses(self, spec, region)
                    continue
                if spec.kind in {"cvm.image", "cbs.snapshot"}:
                    from .image_snapshots import collect_owned

                    collect_owned(self, spec, region)
                    continue
                if spec.service == "autoscaling":
                    from .autoscaling import collect as collect_autoscaling

                    collect_autoscaling(self, spec, region)
                    continue
                if spec.kind == "cdn.domain":
                    from .cdn import collect_domains

                    collect_domains(self)
                    continue
                if spec.kind == "ssm.secret":
                    from .secrets import collect_secrets

                    collect_secrets(self, spec, region)
                    continue
                if spec.kind == "emr.cluster":
                    from .emr import collect_clusters

                    collect_clusters(self, spec, region)
                    continue
                if spec.kind == "config.rule":
                    from .cloudconfig import collect_rule_details, collect_settings

                    collect_settings(self)
                    collect_rule_details(self, self.native(spec, region))
                    continue
                if spec.kind == "ses.domain":
                    from .ses import collect_domains

                    collect_domains(self, spec, region)
                    continue
                if spec.kind == "cls.topic":
                    for biz_type in (0, 1):
                        self.native(spec, region, {"BizType": biz_type})
                    continue
                if spec.action == "ListKeys" and spec.service == "kms":
                    from .kms import collect_keys

                    collect_keys(self, spec, region)
                    continue
                collected = self.native(spec, region)
                if spec.kind == "eb.bus":
                    from .eventbridge import collect_bus

                    for nid, item in collected:
                        collect_bus(self, nid)
                if spec.kind in {"tdmq.cmqqueue", "tdmq.cmqtopic"}:
                    from .cmq import collect_resource

                    for nid, item in collected:
                        collect_resource(self, nid)
                if spec.kind == "ckafka.instance":
                    from .ckafka import collect_instance

                    for nid, item in collected:
                        collect_instance(self, nid)
                if spec.kind == "monitor.policy":
                    from .monitor import collect_bindings

                    collect_bindings(self, collected)
                if spec.kind == "cloudaudit.track":
                    from .observability import collect_track_details

                    collect_track_details(self, collected)
                if spec.kind == "apigateway.service":
                    from .gateway import collect_service

                    for nid, item in collected:
                        collect_service(self, nid)
                if spec.kind == "tcr.instance":
                    from .tcr import collect_registry

                    for nid, item in collected:
                        collect_registry(self, nid, item)
                if spec.kind in DNS_RECORDS:
                    from .dns import collect_records

                    for nid, item in collected:
                        collect_records(self, nid, item)
                if spec.kind == "vpc.securitygroup":
                    self.security_rules(region, collected)
                child = CHILDREN.get(spec.kind)
                if child:
                    key = {
                        "cfs.filesystem": "FileSystemId",
                        "cfs.permissiongroup": "PGroupId",
                        "tke.cluster": "ClusterId",
                        "cam.role": "RoleId",
                        "cam.user": "TargetUin",
                        "cam.group": "TargetGroupId",
                        "cvm.launchtemplate": "LaunchTemplateId",
                        "vpc.ccn": "CcnId",
                    }[spec.kind]
                    for nid, item in collected:
                        self.native(
                            child,
                            region,
                            {key: first(item, spec.ids)},
                            nid,
                            {
                                "cfs.filesystem": "HAS_MOUNT_TARGET",
                                "cfs.permissiongroup": "HAS_ACCESS_RULE",
                                "tke.cluster": "HAS_NODE",
                                "cvm.launchtemplate": "HAS_VERSION",
                                "vpc.ccn": "HAS_ATTACHMENT",
                            }.get(spec.kind, "HAS_POLICY"),
                        )
        if not services or "clb" in services:
            from .clb import collect_listeners

            collect_listeners(self)
            from .clb_depth import collect as collect_clb_depth

            for region in self.regions_for("clb"):
                collect_clb_depth(self, region)
        if not services or "cam" in services:
            from .cam import collect_details

            collect_details(self)
            from .cam_security import collect as collect_cam_security

            collect_cam_security(self)
        if not services or "scf" in services:
            from .scf import collect_function, collect_layers

            for region in self.regions_for("scf"):
                namespaces = self.native(SCF_NAMESPACES, region)
                for nid, ns in namespaces:
                    functions = self.native(
                        SCF_FUNCTIONS, region, {"Namespace": ns["Name"]}, nid, "CONTAINS"
                    )
                    for fid, item in functions:
                        collect_function(self, fid, item)
                collect_layers(self, region)
        if not services or "cos" in services:
            self.buckets()
        from .image_snapshots import collect_in_use

        collect_in_use(self, services)
        if not services or "tag" in services:
            from .tags import collect_tags

            collect_tags(self)
        from .families import run as collect_families

        collect_families(self, services)
        if not services or "tcr" in services:
            from .tcr_personal import collect as personal_repositories

            for region in self.regions_for("tcr"):
                personal_repositories(self, region)
        from .exclusions import record as record_exclusions

        record_exclusions(
            self.graph,
            self.account,
            self.regions,
            services,
            self.plan.by_service if self.plan else None,
        )
        # Explicit exclusions remain visible, rather than being represented as zero resources.
        for service in sorted(
            {s.service for s in (*COLLECTORS, *EXTRA_COLLECTORS)}
            | {"scf", "cos", "tag", "lke", "tcaplusdb", "coding", "hunyuan"}
        ):
            if services and service not in services:
                self.graph.coverage.append(
                    dict(
                        account=self.account,
                        region="all",
                        service=service,
                        action="*",
                        status="not-queried",
                        count=0,
                        request_ids=[],
                    )
                )


def collect(
    profiles,
    regions=None,
    services=None,
    tccli="tccli",
    progress=print,
    transport_factory=None,
    kube_contexts=None,
    kube_transport_factory=None,
    analysis_limit=25000,
    discover_regions=False,
):
    from .authorization import analysis_limit as validate_analysis_limit

    analysis_limit = validate_analysis_limit(analysis_limit)
    from .collection_plan import RegionPlan, blank_scopes, region_restrictions
    from .fleet_coverage import reconcile_organization

    restrictions = region_restrictions(regions)
    if type(discover_regions) is not bool:
        raise ValueError("Invalid region discovery setting")
    if not profiles or len(profiles) != len(set(profiles)):
        raise ValueError("Provide distinct profile names")
    import re

    if not all(
        isinstance(p, str) and p not in {".", ".."} and re.fullmatch(r"[A-Za-z0-9_.-]+", p)
        for p in profiles
    ):
        raise ValueError("Invalid TCCLI profile name")
    graph = Graph()
    graph.collection = dict(
        version=1,
        region_mode="automatic" if discover_regions or restrictions is None else "explicit",
        requested_profiles=list(profiles),
        requested_regions=restrictions,
        requested_services=sorted(services) if services else None,
        profiles=[],
        scopes=[],
        organization=[],
        organization_discovery=[],
    )
    accepted = set()
    for profile in profiles:
        outcome = dict(
            profile=profile,
            account=None,
            status="failed",
            committed=False,
            identity_verified=False,
            error="",
        )
        graph.collection["profiles"].append(outcome)
        temp = Graph()
        progress(f"Profile {profile}: checking account identity")
        try:
            transport = (
                transport_factory(profile) if transport_factory else TccliTransport(profile, tccli)
            )
            identity = transport.call("sts", "GetCallerIdentity")
            account = str(identity.get("AccountId") or "")
            if not re.fullmatch(r"[1-9][0-9]*", account):
                raise CollectionError("InvalidIdentity")
        except Exception as exc:
            code = exc.code if isinstance(exc, CollectionError) else "ProfileIdentityFailed"
            outcome["error"] = code
            graph.coverage.append(
                dict(
                    account="unknown",
                    profile=profile,
                    region="global",
                    service="sts",
                    action="GetCallerIdentity",
                    status="error",
                    error=code,
                    count=0,
                    request_ids=[],
                )
            )
            graph.collection["scopes"].extend(blank_scopes(profile, regions, services, code))
            progress(f"Profile {profile}: identity unavailable ({code}); continuing")
            continue
        outcome.update(account=account, identity_verified=True)
        if account in accepted:
            outcome.update(
                status="duplicate",
                error="DuplicateAccount",
                alias_of=graph.accounts[account]["name"],
            )
            progress(f"Profile {profile}: account {account} already collected; duplicate skipped")
            continue
        temp.accounts[account] = dict(
            id=account,
            name=profile,
            display=f"{profile} · {account}",
            principal_type=identity.get("Type", "unknown"),
        )
        try:
            plan = RegionPlan.build(
                transport,
                account,
                profile,
                regions,
                services,
                temp.coverage,
                discover_regions,
                progress,
            )
        except Exception as exc:
            code = exc.code if isinstance(exc, CollectionError) else "RegionPlanningFailed"
            outcome.update(error=code)
            graph.coverage.append(
                dict(
                    account=account,
                    profile=profile,
                    region="global",
                    service="collection",
                    action="PlanRegions",
                    status="error",
                    error=code,
                    count=0,
                    request_ids=[],
                )
            )
            graph.collection["scopes"].extend(
                {**s, "account": account} for s in blank_scopes(profile, regions, services, code)
            )
            continue
        runner = CollectorRunner(temp, transport, account, plan.regions, progress, plan)
        interrupted = None
        try:
            runner.run(services)
            if not services or "tke" in services:
                from .tke import collect_access_mappings

                collect_access_mappings(runner)
        except Exception as exc:
            interrupted = (
                exc.code if isinstance(exc, CollectionError) else "AccountCollectionInterrupted"
            )
            temp.coverage.append(
                dict(
                    account=account,
                    region="global",
                    service="collection",
                    action="CollectAccount",
                    status="error",
                    error=interrupted,
                    count=0,
                    request_ids=[],
                )
            )
        try:
            final = transport.call("sts", "GetCallerIdentity")
            if str(final.get("AccountId")) != account or any(
                final.get(k) != identity.get(k) for k in ("PrincipalId", "Arn", "Type")
            ):
                raise CollectionError("IdentityChanged")
        except Exception as exc:
            code = exc.code if isinstance(exc, CollectionError) else "ProfileReverificationFailed"
            outcome.update(status="discarded", error=code)
            graph.collection["scopes"].extend(plan.finish(temp, discarded=True))
            # Preserve query evidence but never publish resources from an unverified account attempt.
            for row in temp.coverage:
                graph.coverage.append({**row, "profile": profile, "inventory_discarded": True})
            graph.coverage.append(
                dict(
                    account=account,
                    profile=profile,
                    region="global",
                    service="sts",
                    action="VerifyCallerIdentity",
                    status="error",
                    error=code,
                    count=0,
                    request_ids=[],
                )
            )
            progress(f"Profile {profile}: account inventory discarded ({code}); continuing")
            continue
        accepted.add(account)
        graph.nodes.update(temp.nodes)
        graph.edges.update(temp.edges)
        graph.accounts.update(temp.accounts)
        graph.coverage.extend({**r, "profile": profile} for r in temp.coverage)
        scopes = plan.finish(temp)
        graph.collection["scopes"].extend(scopes)
        partial = (
            interrupted
            or temp.snapshot()["status"] == "partial"
            or any(r["state"] in {"failed", "unscanned"} or r["partial"] for r in scopes)
        )
        outcome.update(
            status="partial" if partial else "scanned", committed=True, error=interrupted or ""
        )
    reconcile_organization(graph)
    from .inventory import reconcile_global_inventory

    reconcile_global_inventory(graph)
    from .tags import link_tags

    link_tags(graph)
    from .secrets import link_resources

    link_resources(graph)
    from .kms import link_policy_resources

    link_policy_resources(graph)
    from .network_addresses import link as link_network_addresses

    link_network_addresses(graph)
    from .peering import link as link_peering

    link_peering(graph)
    from .routes import link_next_hops

    link_next_hops(graph)
    from .privatelink import link as link_privatelink

    link_privatelink(graph)
    from .dns import link_dns

    link_dns(graph)
    from .ses import link_dns_checks

    link_dns_checks(graph)
    from .scf import link_trigger_sources

    link_trigger_sources(graph)
    from .gateway import link_backends

    link_backends(graph)
    from .cam import link_compute_roles

    link_compute_roles(graph)
    from .observability import link_destinations

    link_destinations(graph)
    from .cmq import link_destinations as link_cmq_destinations

    link_cmq_destinations(graph)
    from .eventbridge import link_targets

    link_targets(graph)
    from .cloudconfig import link_delivery

    link_delivery(graph)
    from .monitor import link_bindings

    link_bindings(graph)
    from .kubernetes_metadata import collect_contexts

    collect_contexts(graph, kube_contexts, kube_transport_factory)
    from .exposure import analyze as analyze_exposure

    analyze_exposure(graph)
    from .permissions import analyze as analyze_permissions

    analyze_permissions(graph, analysis_limit)
    from .public_access import analyze as analyze_public_access

    analyze_public_access(graph)
    from .cos_authorization import analyze as analyze_cos_authorization
    from .role_assumption import analyze as analyze_role_assumption

    analyze_cos_authorization(graph, max_decisions=analysis_limit)
    analyze_role_assumption(graph, max_decisions=analysis_limit)
    return graph.snapshot()
