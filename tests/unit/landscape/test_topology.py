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
