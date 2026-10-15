"""Gateway identities needed by route and EIP targets, without tunnel secrets."""

from .network_addresses import ip
from .network_parity import read_rows
from .transport import CollectionError
from .vpc import fields, identity

SPECS = (
    ("DescribeHaVips", "HaVipSet", "vpc.havip", "HaVipId", "HaVipName", "havip"),
    (
        "DescribeVpnGateways",
        "VpnGatewaySet",
        "vpc.vpngateway",
        "VpnGatewayId",
        "VpnGatewayName",
        "vpngw",
    ),
    (
        "DescribeDirectConnectGateways",
        "DirectConnectGatewaySet",
        "vpc.directconnectgateway",
        "DirectConnectGatewayId",
        "DirectConnectGatewayName",
        "dcg",
    ),
)


def collect(runner, region):
    for action, result, kind, id_key, name_key, prefix in SPECS:

        def prepare(raw, id_key=id_key, name_key=name_key, prefix=prefix):
            props = fields(
                raw,
                (
                    name_key,
                    "State",
                    "CreatedTime",
                    "CreateTime",
                    "ExpiredTime",
                    "FlushedTime",
                    "Business",
                    "CdcId",
                    "Type",
                    "RenewFlag",
                    "InstanceChargeType",
                    "RestrictState",
                    "Zone",
                    "Version",
                    "NetworkType",
                    "NetworkInstanceId",
                    "GatewayType",
                    "CcnRouteType",
                    "ModeType",
                    "AccessNetworkType",
                ),
                (
                    "CheckAssociate",
                    "IsAddressBlocked",
                    "IsPrivate",
                    "EnableBGP",
                    "EnableBGPCommunity",
                    "LocalZone",
                ),
                (
                    "InternetMaxBandwidthOut",
                    "MaxConnection",
                    "BgpAsn",
                    "GatewayAsn",
                    "EnableFlowDetails",
                ),
            )
            rid = identity(raw.get(id_key), prefix)
            refs = []
            for key, target_kind, target_prefix, relation in (
                ("VpcId", "vpc.vpc", "vpc", "IN_VPC"),
                ("SubnetId", "vpc.subnet", "subnet", "IN_SUBNET"),
                ("NetworkInterfaceId", "vpc.networkinterface", "eni", "USES_INTERFACE"),
                ("NatGatewayId", "vpc.nat", "nat", "USES_NAT"),
            ):
                if raw.get(key):
                    props[key] = identity(raw[key], target_prefix)
                    refs.append((target_kind, props[key], relation))
            if raw.get("CcnId"):
                props["CcnId"] = identity(raw["CcnId"], "ccn")
            if raw.get("InstanceId"):
                if not isinstance(raw["InstanceId"], str):
                    raise CollectionError("InvalidGatewayAttachment")
                props["InstanceId"] = raw["InstanceId"]
            for key in ("Vip", "AddressIp", "PublicIpAddress", "DirectConnectGatewayIp"):
                if raw.get(key):
                    props[key] = ip(raw[key])
            props.update(
                state=props.get("State", ""),
                ip_addresses=", ".join(
                    props[key]
                    for key in ("Vip", "AddressIp", "PublicIpAddress", "DirectConnectGatewayIp")
                    if key in props
                ),
                reachability_verified=False,
            )
            return rid, props, refs

        def save(row, kind=kind, action=action, name_key=name_key):
            rid, props, refs = row
            nid = runner.graph.add(
                runner.account, region, kind, rid, props.get(name_key), source="vpc." + action
            )
            runner.graph.nodes[nid]["properties"].update(props)
            for target_kind, target_id, relation in refs:
                target = runner.graph.add(
                    runner.account, region, target_kind, target_id, status="reference"
                )
                runner.graph.edge(nid, target, relation, "vpc." + action)

        read_rows(runner, "vpc", action, result, region, {}, prepare, save)
