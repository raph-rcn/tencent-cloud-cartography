"""Collect metadata, retain incomplete scopes, and reconcile by canonical resource IDs."""

import json

from .catalog import CHILDREN, COLLECTORS, DNS_RECORDS, SCF_FUNCTIONS, SCF_NAMESPACES
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
    def __init__(self, graph, transport, account, regions, progress=print):
        self.graph, self.transport, self.account = graph, transport, str(account)
        self.regions, self.progress = regions, progress

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
                            if actual_region != "unknown":
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
                if bucket["region"] not in self.regions:
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
            for region in self.regions if spec.regional else ["global"]:
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
        if not services or "cam" in services:
            from .cam import collect_details

            collect_details(self)
        if not services or "scf" in services:
            from .scf import collect_function, collect_layers

            for region in self.regions:
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
        # Explicit exclusions remain visible, rather than being represented as zero resources.
        for service in sorted({s.service for s in COLLECTORS} | {"scf", "cos", "tag"}):
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
    profiles, regions, services=None, tccli="tccli", progress=print, transport_factory=None
):
    graph = Graph()
    seen_accounts = set()
    for profile in profiles:
        transport = (
            transport_factory(profile) if transport_factory else TccliTransport(profile, tccli)
        )
        identity = transport.call("sts", "GetCallerIdentity")
        account = str(identity.get("AccountId") or "")
        if not account or not account.isdigit():
            raise CollectionError("InvalidIdentity")
        if account in seen_accounts:
            raise CollectionError(
                "DuplicateAccount", "Profiles resolve to the same account; select one"
            )
        seen_accounts.add(account)
        graph.accounts[account] = dict(
            id=account,
            name=profile,
            display=f"{profile} · {account}",
            principal_type=identity.get("Type", "unknown"),
        )
        runner = CollectorRunner(graph, transport, account, regions, progress)
        runner.run(services)
        final_identity = transport.call("sts", "GetCallerIdentity")
        if any(
            final_identity.get(k) != identity.get(k) for k in ("AccountId", "PrincipalId", "Arn")
        ):
            raise CollectionError(
                "IdentityChanged",
                "Authentication changed during collection; snapshot not published",
            )
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
    return graph.snapshot()
