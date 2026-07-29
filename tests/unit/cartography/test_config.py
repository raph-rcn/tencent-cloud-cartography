from cartography.config import Config


def test_config_defaults_to_aws_only_values() -> None:
    # Arrange / Act
    config = Config(neo4j_uri="bolt://127.0.0.1:7687")

    # Assert
    assert config.neo4j_uri == "bolt://127.0.0.1:7687"
    assert config.aws_sync_all_profiles is False
    assert config.aws_requested_syncs is None
    assert config.aws_best_effort_mode is False
    assert config.permission_relationships_file is None


def test_config_accepts_landscape_sync_options() -> None:
    # Arrange / Act
    config = Config(
        neo4j_uri="bolt://127.0.0.1:7687",
        aws_regions="eu-central-1,eu-west-1",
        aws_requested_syncs="ec2:vpc,ec2:subnet",
        aws_organization_account_ids="111122223333",
        aws_guardduty_severity_threshold="HIGH",
    )

    # Assert
    assert config.aws_regions == "eu-central-1,eu-west-1"
    assert config.aws_requested_syncs == "ec2:vpc,ec2:subnet"
    assert config.aws_organization_account_ids == "111122223333"
    assert config.aws_guardduty_severity_threshold == "HIGH"
