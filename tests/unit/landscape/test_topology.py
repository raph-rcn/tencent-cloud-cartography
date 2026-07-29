from cartography.landscape.topology import build_topology


def test_build_topology_projects_vpc_az_subnet_and_relationships() -> None:
    # Arrange
    raw_nodes = [
        {
            "account_id": "111122223333",
            "account_name": "Example",
            "element_id": "vpc-element",
            "labels": ["AWSVpc", "VirtualNetwork"],
            "properties": {
                "id": "vpc-example",
                "region": "eu-west-1",
                "primary_cidr_block": "10.0.0.0/16",
            },
        },
        {
            "account_id": "111122223333",
            "account_name": "Example",
            "element_id": "subnet-element",
            "labels": ["AWSEC2Subnet", "Subnet"],
            "properties": {
                "id": "subnet-example",
                "region": "eu-west-1",
                "vpc_id": "vpc-example",
                "availability_zone": "eu-west-1a",
                "cidr_block": "10.0.1.0/24",
            },
        },
        {
            "account_id": "111122223333",
            "account_name": "Example",
            "element_id": "instance-element",
            "labels": ["AWSEC2Instance", "ComputeInstance"],
            "properties": {
                "id": "i-example",
                "region": "eu-west-1",
                "state": "running",
            },
        },
        {
            "account_id": "111122223333",
            "account_name": "Example",
            "element_id": "role-element",
            "labels": ["AWSRole", "AWSPrincipal"],
            "properties": {
                "id": "arn:aws:iam::111122223333:role/example",
                "name": "example-role",
            },
        },
    ]
    raw_edges = [
        {
            "source": "instance-element",
            "target": "subnet-element",
            "type": "PART_OF_SUBNET",
        },
        {
            "source": "instance-element",
            "target": "role-element",
            "type": "ASSUMES",
        },
    ]

    # Act
    result = build_topology(raw_nodes, raw_edges, include_details=True)

    # Assert
    node_data = [
        element["data"]
        for element in result["elements"]
        if "source" not in element["data"]
    ]
    node_types = {node["type"] for node in node_data}
    instance = next(
        node for node in node_data if node.get("label") == "EC2 instance\ni-example"
    )
    subnet = next(node for node in node_data if node["type"] == "subnet")
    edges = [
        element["data"] for element in result["elements"] if "source" in element["data"]
    ]
    assert {
        "account",
        "region",
        "vpc",
        "availabilityZone",
        "subnet",
        "component",
        "resource",
    } <= node_types
    assert instance["parent"].startswith("component:")
    assert subnet["label"] == "Private subnet · 10.0.1.0/24"
    assert len(edges) == 1
    assert edges[0]["relationship"] == "ASSUMES"
    assert result["stats"]["resources"] == 2


def test_architecture_view_hides_low_level_security_detail() -> None:
    # Arrange
    raw_nodes = [
        {
            "account_id": "111122223333",
            "account_name": "Example",
            "element_id": "bucket-element",
            "labels": ["AWSS3Bucket"],
            "properties": {"id": "example-bucket", "region": "eu-west-1"},
        },
        {
            "account_id": "111122223333",
            "account_name": "Example",
            "element_id": "statement-element",
            "labels": ["AWSS3PolicyStatement"],
            "properties": {"id": "statement-1", "region": "eu-west-1"},
        },
    ]

    # Act
    result = build_topology(raw_nodes, [])

    # Assert
    resources = [
        element["data"]
        for element in result["elements"]
        if element["data"].get("kind") == "resource"
    ]
    assert [resource["primaryLabel"] for resource in resources] == ["AWSS3Bucket"]


def test_architecture_hides_service_implementation_nodes() -> None:
    raw_nodes = [
        {
            "account_id": "111122223333",
            "account_name": "Example",
            "element_id": label,
            "labels": [label],
            "properties": {"id": label, "region": "eu-west-1"},
        }
        for label in (
            "AWSAPIGatewayRestAPI",
            "AWSAPIGatewayResource",
            "AWSAPIGatewayMethod",
            "AWSAPIGatewayIntegration",
            "AWSAPIGatewayDeployment",
            "AWSAPIGatewayStage",
            "AWSLambda",
            "AWSLambdaLayer",
            "AWSSecretsManagerSecret",
            "AWSSecretsManagerSecretVersion",
            "AWSManagedPolicy",
            "AWSDBSubnetGroup",
        )
    ]

    architecture = build_topology(raw_nodes, [])
    full = build_topology(raw_nodes, [], include_details=True)

    architecture_labels = {
        element["data"]["primaryLabel"]
        for element in architecture["elements"]
        if element["data"].get("kind") == "resource"
    }
    full_labels = {
        element["data"]["primaryLabel"]
        for element in full["elements"]
        if element["data"].get("kind") == "resource"
    }

    assert architecture_labels == {
        "AWSAPIGatewayRestAPI",
        "AWSAPIGatewayStage",
        "AWSLambda",
        "AWSSecretsManagerSecret",
    }
    assert full_labels == {next(iter(node["labels"])) for node in raw_nodes}


def test_full_graph_keeps_non_account_resource_relationships() -> None:
    raw_nodes = [
        {
            "account_id": "111122223333",
            "account_name": "Example",
            "element_id": "api",
            "labels": ["AWSAPIGatewayRestAPI"],
            "properties": {"id": "api", "region": "eu-west-1"},
        },
        {
            "account_id": "111122223333",
            "account_name": "Example",
            "element_id": "resource",
            "labels": ["AWSAPIGatewayResource"],
            "properties": {"id": "resource", "region": "eu-west-1"},
        },
    ]
    raw_edges = [{"source": "api", "target": "resource", "type": "RESOURCE"}]

    result = build_topology(raw_nodes, raw_edges, include_details=True)
    relationships = [
        element for element in result["elements"] if "source" in element["data"]
    ]

    assert len(relationships) == 1
    assert relationships[0]["data"]["relationship"] == "RESOURCE"
    assert relationships[0]["classes"] == "membership"


def test_architecture_projects_api_gateway_lambda_invocation() -> None:
    raw_nodes = [
        {
            "account_id": "111122223333",
            "account_name": "Example",
            "element_id": element_id,
            "labels": [label],
            "properties": {"id": element_id, "region": "eu-west-1"},
        }
        for element_id, label in (
            ("api", "AWSAPIGatewayRestAPI"),
            ("api-resource", "AWSAPIGatewayResource"),
            ("integration", "AWSAPIGatewayIntegration"),
            ("lambda", "AWSLambda"),
        )
    ]
    raw_edges = [
        {"source": "api", "target": "api-resource", "type": "RESOURCE"},
        {
            "source": "api-resource",
            "target": "integration",
            "type": "HAS_INTEGRATION",
        },
        {"source": "integration", "target": "lambda", "type": "INVOKES"},
    ]

    result = build_topology(raw_nodes, raw_edges)
    resources = [
        element["data"]
        for element in result["elements"]
        if element["data"].get("kind") == "resource"
    ]
    relationships = [
        element["data"] for element in result["elements"] if "source" in element["data"]
    ]

    assert {resource["primaryLabel"] for resource in resources} == {
        "AWSAPIGatewayRestAPI",
        "AWSLambda",
    }
    assert [relationship["relationship"] for relationship in relationships] == [
        "INVOKES"
    ]


def test_architecture_places_rds_in_vpc_via_hidden_db_subnet_group() -> None:
    raw_nodes = [
        {
            "account_id": "111122223333",
            "account_name": "Example",
            "element_id": "vpc",
            "labels": ["AWSVpc"],
            "properties": {
                "id": "vpc-example",
                "region": "eu-west-1",
                "primary_cidr_block": "10.0.0.0/16",
            },
        },
        {
            "account_id": "111122223333",
            "account_name": "Example",
            "element_id": "subnet-group",
            "labels": ["AWSDBSubnetGroup"],
            "properties": {
                "id": "subnet-group",
                "region": "eu-west-1",
                "vpc_id": "vpc-example",
            },
        },
        {
            "account_id": "111122223333",
            "account_name": "Example",
            "element_id": "database",
            "labels": ["AWSRDSInstance"],
            "properties": {
                "id": "database",
                "region": "eu-west-1",
                "engine": "postgres",
            },
        },
    ]
    raw_edges = [
        {
            "source": "database",
            "target": "subnet-group",
            "type": "MEMBER_OF_DB_SUBNET_GROUP",
        }
    ]

    result = build_topology(raw_nodes, raw_edges)
    nodes = {
        element["data"]["id"]: element["data"]
        for element in result["elements"]
        if "source" not in element["data"]
    }
    database = next(
        node for node in nodes.values() if node.get("primaryLabel") == "AWSRDSInstance"
    )
    component = nodes[database["parent"]]

    assert component["parent"].startswith("vpc:")


def test_multi_subnet_load_balancer_stays_in_vpc_and_keeps_memberships() -> None:
    # Arrange
    account_id = "111122223333"
    raw_nodes = [
        {
            "account_id": account_id,
            "account_name": "Example",
            "element_id": "vpc-element",
            "labels": ["AWSVpc"],
            "properties": {
                "id": "vpc-example",
                "region": "eu-west-1",
                "primary_cidr_block": "10.0.0.0/16",
            },
        },
        {
            "account_id": account_id,
            "account_name": "Example",
            "element_id": "subnet-a",
            "labels": ["AWSEC2Subnet"],
            "properties": {
                "id": "subnet-a",
                "region": "eu-west-1",
                "vpc_id": "vpc-example",
                "availability_zone": "eu-west-1a",
                "cidr_block": "10.0.1.0/24",
            },
        },
        {
            "account_id": account_id,
            "account_name": "Example",
            "element_id": "subnet-b",
            "labels": ["AWSEC2Subnet"],
            "properties": {
                "id": "subnet-b",
                "region": "eu-west-1",
                "vpc_id": "vpc-example",
                "availability_zone": "eu-west-1b",
                "cidr_block": "10.0.2.0/24",
            },
        },
        {
            "account_id": account_id,
            "account_name": "Example",
            "element_id": "load-balancer",
            "labels": ["AWSLoadBalancerV2", "LoadBalancer"],
            "properties": {
                "id": "example.eu-west-1.elb.amazonaws.com",
                "name": "example-alb",
                "region": "eu-west-1",
            },
        },
        {
            "account_id": account_id,
            "account_name": "Example",
            "element_id": "instance",
            "labels": ["AWSEC2Instance"],
            "properties": {
                "id": "i-example",
                "region": "eu-west-1",
                "subnet_id": "subnet-a",
            },
        },
    ]
    raw_edges = [
        {
            "source": "load-balancer",
            "target": "subnet-a",
            "type": "SUBNET",
        },
        {
            "source": "load-balancer",
            "target": "subnet-b",
            "type": "SUBNET",
        },
        {
            "source": "load-balancer",
            "target": "instance",
            "type": "EXPOSE",
        },
    ]

    # Act
    result = build_topology(raw_nodes, raw_edges)

    # Assert
    nodes = [
        element["data"]
        for element in result["elements"]
        if "source" not in element["data"]
    ]
    load_balancer = next(
        node for node in nodes if node.get("primaryLabel") == "AWSLoadBalancerV2"
    )
    parent = next(node for node in nodes if node["id"] == load_balancer["parent"])
    relationships = [
        element for element in result["elements"] if "source" in element["data"]
    ]

    assert load_balancer["icon"] == "elastic-load-balancing"
    assert load_balancer["title"] == "Application/network load balancer"
    assert parent["type"] == "component"
    assert parent["parent"].startswith("vpc:")
    assert sorted(edge["data"]["relationship"] for edge in relationships) == [
        "EXPOSE",
        "SUBNET",
        "SUBNET",
    ]
    assert sum(edge["classes"] == "membership" for edge in relationships) == 2


def test_architecture_places_internet_gateway_at_vpc_boundary() -> None:
    # Arrange
    raw_nodes = [
        {
            "account_id": "111122223333",
            "account_name": "Example",
            "element_id": "vpc-element",
            "labels": ["AWSVpc"],
            "properties": {
                "id": "vpc-example",
                "region": "eu-west-1",
                "primary_cidr_block": "10.0.0.0/16",
            },
        },
        {
            "account_id": "111122223333",
            "account_name": "Example",
            "element_id": "gateway-element",
            "labels": ["AWSInternetGateway"],
            "properties": {
                "id": "igw-example",
                "region": "eu-west-1",
            },
        },
    ]
    raw_edges = [
        {
            "source": "gateway-element",
            "target": "vpc-element",
            "type": "ATTACHED_TO",
        },
    ]

    # Act
    architecture = build_topology(raw_nodes, raw_edges)
    relationships = build_topology(
        raw_nodes,
        raw_edges,
        include_details=True,
    )

    # Assert
    architecture_nodes = [
        element["data"]
        for element in architecture["elements"]
        if "source" not in element["data"]
    ]
    gateway = next(
        node
        for node in architecture_nodes
        if node.get("primaryLabel") == "AWSInternetGateway"
    )
    component = next(
        node for node in architecture_nodes if node["id"] == gateway["parent"]
    )
    assert component["parent"].startswith("vpc:")
    assert architecture["stats"]["relationships"] == 0
    assert relationships["stats"]["relationships"] == 1
