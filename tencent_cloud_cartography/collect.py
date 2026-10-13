"""Collect metadata, retain incomplete scopes, and reconcile by canonical resource IDs."""

import json

from .catalog import CHILDREN, COLLECTORS, DNS_RECORDS, SCF_FUNCTIONS, SCF_NAMESPACES
from .model import Graph, first, resource_kind, stable_id
from .transport import CollectionError, TccliTransport, pages


def status_for(code):
    low = code.lower()
    if low.startswith(("unauthorized", "authfailure", "operationdenied")):
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
        def operation(record):
            token, seen = None, set()
            for _ in range(10000):
                args = dict(MaxResults=100)
                if region != "global":
                    args["Filters"] = [
                        {"Key": "RegionCode", "Values": [region], "MatchType": "Equals"}
                    ]
                # An account-wide pass retains only globals, so regional scope never leaks.
                if token:
                    args["NextToken"] = token
                response = self.transport.call("cloudrc", "SearchResources", **args)
                if response.get("RequestId"):
                    record["request_ids"].append(response["RequestId"])
                resources = response.get("Resources")
                if not isinstance(resources, list):
                    raise CollectionError("InvalidResponse")
                for item in resources:
                    owner = item.get("Uin")
                    if owner is not None and str(owner) != self.account:
                        raise CollectionError("AccountMismatch")
                    actual_region = item.get("RegionCode") or "global"
                    if actual_region != region:
                        if region == "global":
                            continue
                        raise CollectionError("RegionMismatch")
                    kind = resource_kind(item["ResourceType"])
                    self.graph.add(
                        self.account,
                        actual_region,
                        kind,
                        item["ResourceId"],
                        item.get("ResourceAlias"),
                        item,
                        "cloudrc.SearchResources",
                        "inventory-only",
                    )
                    record["count"] += 1
                token = response.get("NextToken")
                if not token:
                    return
                if token in seen:
                    raise CollectionError("PaginationStalled")
                seen.add(token)
            raise CollectionError("PageLimit")

        return self.scope("cloudrc", "SearchResources", region, operation)

    def native(self, spec, region, params=None, parent=None, relation=None):
        collected = []
        if spec.service == "dnspod" and spec.action == "DescribeDomainList":
            params = {**(params or {}), "Type": "MINE"}
        if spec.action == "ListPolicies":
            # Preset policies enter through actual attachments; do not collect the
            # entire provider catalog as though every policy belongs to this account.
            params = {**(params or {}), "Scope": "Local"}
        if spec.action == "DescribeImages":
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
            for items, request_id in pages(self.transport, spec, region, params):
                if request_id:
                    record["request_ids"].append(request_id)
                for item in items:
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
                    # ListFunctions IDs are namespace scoped when FunctionId is unavailable.
                    if spec.kind == "scf.function" and not item.get("FunctionId"):
                        item = {
                            **item,
                            "FunctionId": f"{(params or {}).get('Namespace', 'default')}/{item['FunctionName']}",
                        }
                    nid = self.graph.native(self.account, region, spec, item, source)
                    collected.append((nid, item))
                    if parent:
                        self.graph.edge(parent, nid, relation or "CONTAINS", source)
                record["count"] += len(items)

        self.scope(
            spec.service, spec.action, region, operation, json.dumps(params) if params else ""
        )
        return collected

    def security_rules(self, region, groups):
        for nid, group in groups:

            def operation(record, nid=nid, group=group):
                response = self.transport.call(
                    "vpc",
                    "DescribeSecurityGroupPolicies",
                    region,
                    SecurityGroupId=group["SecurityGroupId"],
                )
                if response.get("RequestId"):
                    record["request_ids"].append(response["RequestId"])
                policy_set = response.get("SecurityGroupPolicySet")
                if not isinstance(policy_set, dict):
                    raise CollectionError("InvalidResponse")
                for direction in ("Ingress", "Egress"):
                    rules = policy_set.get(direction)
                    if rules is None:
                        rules = []
                    if not isinstance(rules, list):
                        raise CollectionError("InvalidResponse")
                    for idx, rule in enumerate(rules):
                        rid = (
                            group["SecurityGroupId"]
                            + "/"
                            + direction
                            + "/"
                            + str(rule.get("PolicyIndex", idx))
                        )
                        target = self.graph.add(
                            self.account,
                            region,
                            "vpc.securitygrouprule",
                            rid,
                            f"{direction} {rule.get('Action', '')} {rule.get('Protocol', '')}:{rule.get('Port', '')}",
                            rule,
                            "vpc.DescribeSecurityGroupPolicies",
                        )
                        self.graph.edge(
                            nid, target, "HAS_RULE", "vpc.DescribeSecurityGroupPolicies"
                        )
                        record["count"] += 1

            self.scope(
                "vpc", "DescribeSecurityGroupPolicies", region, operation, group["SecurityGroupId"]
            )

    def buckets(self):
        def operation(record):
            for bucket in self.transport.buckets():
                if bucket["region"] not in self.regions:
                    continue
                self.graph.add(
                    self.account,
                    bucket["region"],
                    "cos.bucket",
                    bucket["name"],
                    source="cos.list_buckets",
                )
                record["count"] += 1

        self.scope("cos", "list_buckets", "global", operation)

    def run(self, services=None):
        # Baseline is always retained, including unresolved supported product types.
        for region in [*self.regions, "global"]:
            self.baseline(region)
        for spec in COLLECTORS:
            if services and spec.service not in services:
                continue
            for region in self.regions if spec.regional else ["global"]:
                if spec.action == "ListKeys" and spec.service == "kms":
                    from .kms import collect_keys

                    collect_keys(self, spec, region)
                    continue
                collected = self.native(spec, region)
                if spec.kind in DNS_RECORDS:
                    from .dns import collect_records

                    for nid, item in collected:
                        collect_records(self, nid, item)
                if spec.kind == "vpc.securitygroup":
                    self.security_rules(region, collected)
                child = CHILDREN.get(spec.kind)
                if child:
                    key = {
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
                                "tke.cluster": "HAS_NODE",
                                "cvm.launchtemplate": "HAS_VERSION",
                                "vpc.ccn": "HAS_ATTACHMENT",
                            }.get(spec.kind, "HAS_POLICY"),
                        )
        if not services or "cam" in services:
            from .cam import collect_details

            collect_details(self)
        if not services or "scf" in services:
            for region in self.regions:
                namespaces = self.native(SCF_NAMESPACES, region)
                for nid, ns in namespaces:
                    self.native(SCF_FUNCTIONS, region, {"Namespace": ns["Name"]}, nid, "CONTAINS")
        if not services or "cos" in services:
            self.buckets()
        # Explicit exclusions remain visible, rather than being represented as zero resources.
        for service in sorted({s.service for s in COLLECTORS} | {"scf", "cos"}):
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
    from .kms import link_policy_resources

    link_policy_resources(graph)
    from .dns import link_dns

    link_dns(graph)
    return graph.snapshot()
