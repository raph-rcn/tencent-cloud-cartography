from __future__ import annotations

import hashlib
from collections import Counter
from collections import defaultdict
from typing import Any

CONTAINMENT_RELATIONSHIPS = {
    "MEMBER_OF_AWS_VPC",
    "PART_OF_SUBNET",
    "RESOURCE",
}

PROPERTY_ALLOWLIST = (
    "name",
    "id",
    "arn",
    "region",
    "state",
    "status",
    "vpc_id",
    "vpcid",
    "subnet_id",
    "subnetid",
    "availability_zone",
    "availabilityzone",
    "cidr_block",
    "primary_cidr_block",
    "instancetype",
    "engine",
    "dnsname",
)

LABEL_DISPLAY_NAMES = {
    "AWSVpc": "VPC",
    "AWSEC2Subnet": "Subnet",
    "AWSEC2Instance": "EC2 instance",
    "AWSS3Bucket": "S3 bucket",
    "AWSLambda": "Lambda function",
    "AWSRDSInstance": "RDS instance",
    "AWSRDSCluster": "RDS cluster",
    "AWSDynamoDBTable": "DynamoDB table",
    "AWSEKSCluster": "EKS cluster",
    "AWSECSCluster": "ECS cluster",
    "AWSCloudFrontDistribution": "CloudFront distribution",
    "AWSInternetGateway": "Internet gateway",
    "AWSNatGateway": "NAT gateway",
    "AWSVpcEndpoint": "VPC endpoint",
    "AWSEC2SecurityGroup": "Security group",
    "AWSNetworkInterface": "Network interface",
    "AWSKMSKey": "AWS KMS key",
    "AWSEC2RouteTable": "Route table",
    "AWSEC2NetworkAcl": "Network ACL",
    "AWSElasticIPAddress": "Elastic IP address",
    "AWSRouteTable": "Route table",
    "AWSRDSSnapshot": "RDS snapshot",
    "AWSEC2KeyPair": "EC2 key pair",
    "AWSEBSVolume": "EBS volume",
    "AWSECRRepository": "ECR repository",
    "AWSCloudFormationStack": "CloudFormation stack",
    "AWSSNSTopic": "SNS topic",
    "AWSEventBridgeRule": "EventBridge rule",
}

SERVICE_ICON_NAMES = {
    "AWSEC2Instance": "ec2",
    "AWSS3Bucket": "s3",
    "AWSLambda": "lambda",
    "AWSRDSInstance": "rds",
    "AWSRDSCluster": "rds",
    "AWSDynamoDBTable": "dynamodb",
    "AWSEKSCluster": "eks",
    "AWSECSCluster": "ecs",
    "AWSCloudFrontDistribution": "cloudfront",
    "AWSInternetGateway": "internet-gateway",
    "AWSNatGateway": "nat-gateway",
    "AWSVpcEndpoint": "vpc-endpoint",
    "AWSEC2SecurityGroup": "security-group",
    "AWSNetworkInterface": "network-interface",
    "AWSKMSKey": "kms",
    "AWSEC2RouteTable": "route-table",
    "AWSEC2NetworkAcl": "network-acl",
    "AWSElasticIPAddress": "elastic-ip",
    "AWSRouteTable": "route-table",
    "AWSRDSSnapshot": "rds",
    "AWSEC2KeyPair": "key-pair",
    "AWSEBSVolume": "ebs",
    "AWSECRRepository": "ecr",
    "AWSCloudFormationStack": "cloudformation",
    "AWSSNSTopic": "sns",
    "AWSEventBridgeRule": "eventbridge",
}

ARCHITECTURE_DETAIL_MARKERS = (
    "AccessKey",
    "BillingMode",
    "ECRImage",
    "FederatedPrincipal",
    "InlinePolicy",
    "IpPermission",
    "IpRange",
    "IpRule",
    "KMSAlias",
    "KMSGrant",
    "MfaDevice",
    "NetworkAclRule",
    "PolicyStatement",
    "PrivateIp",
    "RepositoryImage",
    "RootPrincipal",
    "RouteTableAssociation",
    "S3Acl",
    "ServicePrincipal",
)
ARCHITECTURE_DETAIL_LABELS = {
    "AWSAccountAccessKey",
    "AWSEC2Reservation",
    "AWSEC2Route",
    "AWSEventBridgeTarget",
    "AWSGroup",
    "AWSInstanceProfile",
    "AWSRole",
    "AWSSNSTopicSubscription",
    "AWSUser",
    # Operational and security-control objects remain available in the full
    # relationship graph but are intentionally omitted from the presentation
    # diagram so service flows stay readable at architecture scale.
    "AWSEC2KeyPair",
    "AWSEC2NetworkAcl",
    "AWSEC2RouteTable",
    "AWSEC2SecurityGroup",
    "AWSElasticIPAddress",
    "AWSKMSKey",
    "AWSNetworkInterface",
    "AWSRDSSnapshot",
    "AWSRouteTable",
}

COMPONENT_BY_LABEL = {
    "AWSS3Bucket": "Storage component",
    "AWSDynamoDBTable": "Data component",
    "AWSRDSInstance": "Data component",
    "AWSRDSCluster": "Data component",
    "AWSLambda": "Compute component",
    "AWSEC2Instance": "Compute component",
    "AWSECSCluster": "Container component",
    "AWSEKSCluster": "Container component",
    "AWSECRRepository": "Image deployment component",
    "AWSCloudFormationStack": "Deployment component",
    "AWSCloudFrontDistribution": "Web component",
    "AWSSNSTopic": "Integration component",
    "AWSSQSQueue": "Integration component",
    "AWSEventBridgeRule": "Integration component",
    "AWSInternetGateway": "Network component",
    "AWSNatGateway": "Network component",
    "AWSVpcEndpoint": "Network component",
    "AWSEBSVolume": "Storage component",
}


def _stable_id(prefix: str, *parts: str) -> str:
    digest = hashlib.sha256("\x00".join(parts).encode()).hexdigest()[:16]
    return f"{prefix}:{digest}"


def _primary_label(labels: list[str]) -> str:
    aws_labels = [
        label
        for label in labels
        if label.startswith("AWS") and label not in {"AWSAccount", "AWSPrincipal"}
    ]
    return aws_labels[0] if aws_labels else labels[0]


def _display_type(primary_label: str) -> str:
    if primary_label in LABEL_DISPLAY_NAMES:
        return LABEL_DISPLAY_NAMES[primary_label]
    value = primary_label.removeprefix("AWS")
    for token in ("EC2", "RDS", "ECS", "EKS", "S3"):
        value = value.replace(token, f"{token} ")
    return value.strip() or primary_label


def _display_name(primary_label: str, props: dict[str, Any]) -> str:
    for key in (
        "name",
        "display_name",
        "id",
        "arn",
        "dnsname",
        "vpcid",
        "subnetid",
    ):
        value = props.get(key)
        if value not in (None, ""):
            text = str(value)
            return text if len(text) <= 42 else f"{text[:18]}…{text[-12:]}"
    return _display_type(primary_label)


def _diagram_label(primary_label: str, props: dict[str, Any]) -> str:
    display_type = _display_type(primary_label)
    display_name = _display_name(primary_label, props)
    if display_name.lower() == display_type.lower():
        return display_type
    return f"{display_type}\n{display_name}"


def _component_name(primary_label: str) -> str:
    return COMPONENT_BY_LABEL.get(primary_label, "Supporting services component")


def _safe_properties(props: dict[str, Any]) -> dict[str, Any]:
    safe: dict[str, Any] = {}
    for key in PROPERTY_ALLOWLIST:
        value = props.get(key)
        if isinstance(value, (str, int, float, bool)) or value is None:
            safe[key] = value
    return safe


def _property(props: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = props.get(key)
        if value not in (None, ""):
            return str(value)
    return None


def _is_architecture_detail(labels: list[str]) -> bool:
    primary_label = _primary_label(labels)
    return primary_label in ARCHITECTURE_DETAIL_LABELS or any(
        marker in primary_label for marker in ARCHITECTURE_DETAIL_MARKERS
    )


def _compound_node(
    node_id: str,
    label: str,
    node_type: str,
    *,
    parent: str | None = None,
    color: str | None = None,
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": node_id,
        "label": label,
        "type": node_type,
        "kind": "container",
    }
    if parent:
        data["parent"] = parent
    if color:
        data["color"] = color
    return {"data": data, "classes": node_type}


def build_topology(
    raw_nodes: list[dict[str, Any]],
    raw_edges: list[dict[str, Any]],
    *,
    include_details: bool = False,
) -> dict[str, Any]:
    if not include_details:
        raw_nodes = [
            node
            for node in raw_nodes
            if "AWSVpc" in node["labels"]
            or "AWSEC2Subnet" in node["labels"]
            or not _is_architecture_detail(node["labels"])
        ]
        included_element_ids = {node["element_id"] for node in raw_nodes}
        raw_edges = [
            edge
            for edge in raw_edges
            if edge["source"] in included_element_ids
            and edge["target"] in included_element_ids
        ]

    nodes_by_element_id = {node["element_id"]: node for node in raw_nodes}
    related_subnet: dict[str, str] = {}
    related_vpc: dict[str, str] = {}

    for edge in raw_edges:
        source = nodes_by_element_id.get(edge["source"])
        target = nodes_by_element_id.get(edge["target"])
        if not source or not target:
            continue
        source_labels = set(source["labels"])
        target_labels = set(target["labels"])
        if edge["type"] == "PART_OF_SUBNET":
            if "AWSEC2Subnet" in source_labels:
                related_subnet[target["element_id"]] = str(source["properties"]["id"])
            elif "AWSEC2Subnet" in target_labels:
                related_subnet[source["element_id"]] = str(target["properties"]["id"])
        if edge["type"] == "MEMBER_OF_AWS_VPC":
            if "AWSVpc" in source_labels:
                related_vpc[target["element_id"]] = str(source["properties"]["id"])
            elif "AWSVpc" in target_labels:
                related_vpc[source["element_id"]] = str(target["properties"]["id"])

    subnets: dict[str, dict[str, Any]] = {}
    vpcs: dict[str, dict[str, Any]] = {}
    for raw_node in raw_nodes:
        labels = set(raw_node["labels"])
        props = raw_node["properties"]
        if "AWSVpc" in labels:
            vpcs[str(props["id"])] = raw_node
        if "AWSEC2Subnet" in labels:
            subnets[str(props["id"])] = raw_node

    elements: list[dict[str, Any]] = []
    created: set[str] = set()

    def add(element: dict[str, Any]) -> None:
        element_id = element["data"]["id"]
        if element_id not in created:
            created.add(element_id)
            elements.append(element)

    # Materialize networking containers even when they are empty. This keeps
    # the architecture view an inventory of the landscape rather than only a
    # view of locations that currently contain another synced resource.
    for raw_node in raw_nodes:
        labels = set(raw_node["labels"])
        if "AWSVpc" not in labels and "AWSEC2Subnet" not in labels:
            continue
        props = raw_node["properties"]
        account_id = str(raw_node["account_id"])
        account_node_id = _stable_id("account", account_id)
        add(
            _compound_node(
                account_node_id,
                "AWS Cloud",
                "account",
                color="#232f3e",
            )
        )
        region = _property(props, "region") or "global"
        region_node_id = _stable_id("region", account_id, region)
        add(
            _compound_node(
                region_node_id,
                (
                    "Global services component"
                    if region == "global"
                    else f"{region} component"
                ),
                "region",
                parent=account_node_id,
                color="#147eba",
            )
        )

        vpc_id = _property(props, "vpc_id", "vpcid")
        if "AWSVpc" in labels:
            vpc_id = _property(props, "id", "vpcid")
        vpc = vpcs.get(vpc_id or "")
        if not vpc_id:
            continue
        vpc_node_id = _stable_id("vpc", account_id, region, vpc_id)
        vpc_label = vpc_id
        cidr = _property(
            (vpc or raw_node)["properties"],
            "primary_cidr_block",
        )
        if cidr:
            vpc_label = f"{vpc_label} · {cidr}"
        add(
            _compound_node(
                vpc_node_id,
                vpc_label,
                "vpc",
                parent=region_node_id,
                color="#248814",
            )
        )

        if "AWSEC2Subnet" in labels:
            subnet_id = _property(props, "id", "subnet_id", "subnetid")
            az = (
                _property(props, "availability_zone", "availabilityzone")
                or "unassigned"
            )
            az_node_id = _stable_id("az", account_id, vpc_id, az)
            add(
                _compound_node(
                    az_node_id,
                    az,
                    "availabilityZone",
                    parent=vpc_node_id,
                    color="#f59e0b",
                )
            )
            subnet_node_id = _stable_id("subnet", account_id, subnet_id or "")
            subnet_kind = (
                "Public subnet"
                if props.get("map_public_ip_on_launch")
                else "Private subnet"
            )
            subnet_label = subnet_kind
            subnet_cidr = _property(props, "cidr_block", "name")
            if subnet_cidr:
                subnet_label = f"{subnet_label} · {subnet_cidr}"
            add(
                _compound_node(
                    subnet_node_id,
                    subnet_label,
                    "subnet",
                    parent=az_node_id,
                    color="#22c55e",
                )
            )

    resource_ids: dict[str, str] = {}
    service_counts: Counter[str] = Counter()

    for raw_node in raw_nodes:
        labels = raw_node["labels"]
        if "AWSAccount" in labels or "AWSVpc" in labels or "AWSEC2Subnet" in labels:
            continue

        props = raw_node["properties"]
        primary_label = _primary_label(labels)
        account_id = str(raw_node["account_id"])
        account_node_id = _stable_id("account", account_id)
        add(
            _compound_node(
                account_node_id,
                "AWS Cloud",
                "account",
                color="#232f3e",
            )
        )

        region = _property(props, "region") or "global"
        region_node_id = _stable_id("region", account_id, region)
        add(
            _compound_node(
                region_node_id,
                (
                    "Global services component"
                    if region == "global"
                    else f"{region} component"
                ),
                "region",
                parent=account_node_id,
                color="#147eba",
            )
        )
        location_parent = region_node_id

        subnet_id = _property(props, "subnet_id", "subnetid") or related_subnet.get(
            raw_node["element_id"]
        )
        subnet = subnets.get(subnet_id or "")
        vpc_id = (
            _property(props, "vpc_id", "vpcid")
            or related_vpc.get(raw_node["element_id"])
            or (_property(subnet["properties"], "vpc_id", "vpcid") if subnet else None)
        )
        vpc = vpcs.get(vpc_id or "")

        if vpc_id:
            vpc_region = (
                _property(vpc["properties"], "region") if vpc else None
            ) or region
            if vpc_region != region:
                region = vpc_region
                region_node_id = _stable_id("region", account_id, region)
                add(
                    _compound_node(
                        region_node_id,
                        f"{region} component",
                        "region",
                        parent=account_node_id,
                        color="#147eba",
                    )
                )
            vpc_node_id = _stable_id("vpc", account_id, region, vpc_id)
            vpc_label = vpc_id
            if vpc:
                cidr = _property(vpc["properties"], "primary_cidr_block")
                if cidr:
                    vpc_label = f"{vpc_id} · {cidr}"
            add(
                _compound_node(
                    vpc_node_id,
                    vpc_label,
                    "vpc",
                    parent=region_node_id,
                    color="#248814",
                )
            )
            location_parent = vpc_node_id

            if subnet:
                az = (
                    _property(
                        subnet["properties"],
                        "availability_zone",
                        "availabilityzone",
                    )
                    or "unassigned"
                )
                az_node_id = _stable_id("az", account_id, vpc_id, az)
                add(
                    _compound_node(
                        az_node_id,
                        az,
                        "availabilityZone",
                        parent=vpc_node_id,
                        color="#f59e0b",
                    )
                )
                subnet_node_id = _stable_id("subnet", account_id, subnet_id or "")
                subnet_kind = (
                    "Public subnet"
                    if subnet["properties"].get("map_public_ip_on_launch")
                    else "Private subnet"
                )
                subnet_label = subnet_kind
                cidr = _property(subnet["properties"], "cidr_block", "name")
                if cidr:
                    subnet_label = f"{subnet_label} · {cidr}"
                add(
                    _compound_node(
                        subnet_node_id,
                        subnet_label,
                        "subnet",
                        parent=az_node_id,
                        color="#22c55e",
                    )
                )
                location_parent = subnet_node_id

        display_type = _display_type(primary_label)
        component_name = _component_name(primary_label)
        type_node_id = _stable_id("component", location_parent, component_name)
        add(
            _compound_node(
                type_node_id,
                component_name,
                "component",
                parent=location_parent,
                color="#5a6c86",
            )
        )

        resource_node_id = f"resource:{raw_node['element_id']}"
        resource_ids[raw_node["element_id"]] = resource_node_id
        service_counts[display_type] += 1
        safe_props = _safe_properties(props)
        add(
            {
                "data": {
                    "id": resource_node_id,
                    "label": _diagram_label(primary_label, props),
                    "title": display_type,
                    "type": "resource",
                    "kind": "resource",
                    "parent": type_node_id,
                    "primaryLabel": primary_label,
                    "labels": labels,
                    "icon": SERVICE_ICON_NAMES.get(primary_label, "default"),
                    "properties": safe_props,
                },
                "classes": "resource",
            }
        )

    relationship_counts: Counter[str] = Counter()
    for index, edge in enumerate(raw_edges):
        if edge["type"] in CONTAINMENT_RELATIONSHIPS:
            continue
        source = resource_ids.get(edge["source"])
        target = resource_ids.get(edge["target"])
        if not source or not target:
            continue
        relationship_counts[edge["type"]] += 1
        elements.append(
            {
                "data": {
                    "id": f"edge:{index}:{source}:{target}",
                    "source": source,
                    "target": target,
                    "label": edge["type"].replace("_", " ").title(),
                    "relationship": edge["type"],
                }
            }
        )

    return {
        "elements": elements,
        "stats": {
            "resources": len(resource_ids),
            "relationships": sum(relationship_counts.values()),
            "containers": len(created) - len(resource_ids),
            "services": dict(service_counts.most_common()),
            "relationshipTypes": dict(relationship_counts.most_common()),
        },
    }
