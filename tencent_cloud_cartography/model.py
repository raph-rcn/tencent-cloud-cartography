"""A small, provider-specific graph with explicit provenance and no raw payloads."""

import hashlib
import json
from datetime import UTC, datetime

from .transport import path_value


def stable_id(*parts):
    return hashlib.sha256("\0".join(str(p) for p in parts).encode()).hexdigest()[:32]


def resource_kind(value):
    from .inventory import type_identity

    return type_identity(value)[0]


def first(data, keys, default=""):
    return next(
        (path_value(data, k) for k in keys if path_value(data, k) not in (None, "")), default
    )


def walk_values(data, keys):
    if isinstance(data, dict):
        for k, v in data.items():
            if k in keys and isinstance(v, (str, int)) and str(v) not in ("", "0", "-1"):
                yield str(v)
            elif k in keys and isinstance(v, list):
                yield from (str(x) for x in v if isinstance(x, (str, int)) and x)
            if isinstance(v, (dict, list)):
                yield from walk_values(v, keys)
    elif isinstance(data, list):
        for v in data:
            yield from walk_values(v, keys)


SAFE_FIELDS = {
    "Forward",
    "CamRoleName",
    "RoleName",
    "KmsKeyId",
    "KmsKeyType",
    "EncryptType",
    "EncryptSwitching",
    "RotationStatus",
    "RotationFrequency",
    "NextRotationTime",
    "SecretType",
    "DiskEncryption",
    "ConsoleLogin",
    "RoleType",
    "SessionDuration",
    "RoleArn",
    "AddTime",
    "UpdateTime",
    "PolicyType",
    "Deactived",
    "IsServiceLinkedRolePolicy",
    "DestinationIpv6CidrBlock",
    "GatewayType",
    "GatewayId",
    "Enabled",
    "RouteType",
    "Priority",
    "ImageType",
    "OsName",
    "Architecture",
    "ImageSize",
    "SnapshotType",
    "Encrypt",
    "MinSize",
    "MaxSize",
    "DesiredCapacity",
    "InstanceCount",
    "LifeCycleState",
    "HealthStatus",
    "LaunchTemplateVersion",
    "DefaultVersionNumber",
    "LatestVersionNumber",
    "IsDefaultVersion",
    "SourceVpcId",
    "PeerVpcId",
    "DestinationVpcId",
    "SourceRegion",
    "DestinationRegion",
    "SourceUin",
    "DestinationUin",
    "InstanceUin",
    "InstanceRegion",
    "ServiceType",
    "SubnetId",
    "EndPointServiceId",
    "CidrBlock",
    "InstanceType",
    "EngineVersion",
    "Engine",
    "ClusterVersion",
    "DiskSize",
    "DiskType",
    "Runtime",
    "Protocol",
    "Port",
    "TargetPort",
    "DestinationCidrBlock",
    "Action",
    "PolicyIndex",
    "PolicyDescription",
    "CidrBlock",
    "Ipv6CidrBlock",
    "SecurityGroupId",
    "LoadBalancerType",
    "Domain",
    "CreatedTime",
    "CreateTime",
    "Namespace",
}
REFERENCES = (
    ({"VpcId", "UniqVpcId", "UnVpcId"}, "vpc.vpc", "IN_VPC", "vpc-"),
    (
        {"SubnetId", "UniqSubnetId", "SubnetIds", "SubnetIdSet"},
        "vpc.subnet",
        "IN_SUBNET",
        "subnet-",
    ),
    (
        {"SecurityGroupId", "SecurityGroupIds", "GroupSet", "SecurityGroupSet"},
        "vpc.securitygroup",
        "USES_SECURITY_GROUP",
        "sg-",
    ),
    ({"RouteTableId"}, "vpc.routetable", "USES_ROUTE_TABLE", "rtb-"),
    ({"NatGatewayId"}, "vpc.nat", "USES_NAT", "nat-"),
    ({"DiskId"}, "cbs.disk", "USES_DISK", "disk-"),
    ({"InstanceId"}, "cvm.instance", "ATTACHED_TO", "ins-"),
    ({"NetworkInterfaceId"}, "vpc.networkinterface", "USES_INTERFACE", "eni-"),
)


class Graph:
    def __init__(self, mode="live"):
        self.nodes, self.edges, self.accounts, self.coverage = {}, {}, {}, []
        self.created_at = datetime.now(UTC).isoformat()
        self.mode = mode

    def add(self, account, region, kind, rid, name=None, raw=None, source="", status="enriched"):
        if not rid:
            raise ValueError(f"Missing resource ID for {kind}")
        account, region, rid = str(account), region or "global", str(rid)
        nid = stable_id(account, region, kind, rid)
        raw = raw or {}
        existing = self.nodes.get(nid)
        props = {
            k: v
            for k, v in raw.items()
            if k in SAFE_FIELDS and isinstance(v, (str, int, float, bool))
        }
        props["zone"] = str(first(raw, ("ZoneCode", "Zone", "Placement.Zone", "ZoneName")))
        props["state"] = str(
            first(
                raw,
                (
                    "InstanceState",
                    "State",
                    "Status",
                    "ClusterStatus",
                    "DiskState",
                    "AddressStatus",
                    "SnapshotState",
                    "ImageState",
                    "AutoScalingGroupStatus",
                    "LaunchConfigurationStatus",
                ),
            )
        )
        ips = list(
            walk_values(
                raw,
                {
                    "PrivateIpAddresses",
                    "PrivateIpAddress",
                    "PublicIpAddresses",
                    "PublicIpAddress",
                    "AddressIp",
                    "Vip",
                },
            )
        )
        if ips:
            props["ip_addresses"] = ", ".join(sorted(set(ips)))
        if existing:
            if status == "reference" or (
                status == "inventory-only" and existing["status"] == "enriched"
            ):
                return nid
            existing["properties"].update({k: v for k, v in props.items() if v != ""})
            if name:
                existing["name"] = str(name)
            existing["status"] = status
            existing["sources"] = sorted(set(existing["sources"] + [source]))
        else:
            self.nodes[nid] = dict(
                id=nid,
                account=account,
                region=region,
                kind=kind,
                resource_id=rid,
                name=str(name or rid),
                status=status,
                properties=props,
                sources=[source] if source else [],
            )
        return nid

    def edge(self, source, target, relation, provenance=""):
        if source == target:
            return
        eid = stable_id(source, target, relation)
        self.edges[eid] = dict(
            id=eid, source=source, target=target, relationship=relation, provenance=provenance
        )

    def native(self, account, region, spec, raw, source):
        rid = first(raw, spec.ids)
        # Dedicated selectors own persisted configuration and links for these kinds;
        # nested configuration must not feed recursive network inference.
        explicit_configuration = spec.kind.startswith(
            ("ckafka.", "tdmq.", "eb.", "ses.", "config.", "emr.")
        ) or spec.kind in {
            "cls.alarm",
            "cls.alarmnotice",
            "cls.scheduledsql",
        }
        nid = self.add(
            account,
            region,
            spec.kind,
            rid,
            first(raw, spec.names),
            {} if explicit_configuration else raw,
            source,
        )
        for keys, kind, relation, prefix in REFERENCES:
            # Associations in these responses describe peers/children, not where
            # the resource itself lives. Handle them with typed relationship code.
            if (
                explicit_configuration
                or spec.kind.startswith("cfs.")
                or spec.kind in {"vpc.ccnattachment", "privatedns.zone", "monitor.policy"}
                or (spec.kind == "cbs.snapshot" and relation == "USES_DISK")
            ):
                continue
            reference_data = raw
            if spec.kind in {"vpc.networkacl", "vpc.routetable", "vpc.endpointservice"}:
                reference_data = {
                    key: value for key, value in raw.items() if not isinstance(value, (list, dict))
                }
            for value in set(walk_values(reference_data, keys)):
                if not value.startswith(prefix):
                    continue
                other = self.add(account, region, kind, value, status="reference")
                self.edge(nid, other, relation, source)
        if spec.kind == "clb.clb" and raw.get("ListenerId"):
            from .clb import flat_listener

            lid = flat_listener(self, self.nodes[nid], raw, source)
            if raw.get("TargetId") or raw.get("TargetAddress"):
                target = raw.get("TargetId")
                if target and target.startswith("ins-"):
                    tid = self.add(account, region, "cvm.instance", target, status="reference")
                else:
                    target = f"{rid}/{raw.get('TargetAddress', target)}:{raw.get('TargetPort', '')}"
                    tid = self.add(
                        account,
                        region,
                        "clb.target",
                        target,
                        raw.get("TargetAddress") or target,
                        raw,
                        source,
                    )
                self.edge(lid, tid, "FORWARDS_TO", source)
        if (spec.service, spec.action) in {("cvm", "DescribeInstances"), ("cbs", "DescribeDisks")}:
            from .compute_metadata import enrich as enrich_compute

            enrich_compute(self, nid, raw, source)
        from .relationships import enrich

        enrich(self, account, region, spec.kind, nid, raw, source)
        return nid

    def snapshot(self):
        coverage_bad = any(c["status"] not in {"complete", "empty"} for c in self.coverage)
        unresolved = sum(n["status"] != "enriched" for n in self.nodes.values())
        return dict(
            schema_version=1,
            created_at=self.created_at,
            mode=self.mode,
            status="partial" if coverage_bad or unresolved else "complete",
            accounts=list(self.accounts.values()),
            nodes=list(self.nodes.values()),
            edges=list(self.edges.values()),
            coverage=self.coverage,
            unresolved=unresolved,
        )

    def dump(self):
        return json.dumps(self.snapshot(), ensure_ascii=False, indent=2) + "\n"
