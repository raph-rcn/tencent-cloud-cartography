import json
import re
from pathlib import Path

import cartography
from cartography.intel.aws.resources import RESOURCE_FUNCTIONS
from cartography.landscape.catalog import SERVICE_FAMILIES
from cartography.landscape.catalog import service_family_for_label
from cartography.landscape.drawio import ICON_DIRECTORY
from cartography.landscape.syncs import EXCLUDED_LANDSCAPE_SYNCS
from cartography.landscape.syncs import landscape_sync_names

AWS_MODELS = Path(cartography.__file__).parent / "models" / "aws"
AWS_ICONS = ICON_DIRECTORY / "aws"


def _aws_model_labels() -> set[str]:
    labels: set[str] = set()
    for model_file in AWS_MODELS.rglob("*.py"):
        labels.update(
            re.findall(
                r"""["'](AWS[A-Za-z0-9]+)["']""",
                model_file.read_text(),
            ),
        )
    return labels


def test_every_cartography_aws_model_has_an_intentional_service_family() -> None:
    # Arrange
    labels = _aws_model_labels() - {"AWSAccount"}

    # Act
    unresolved = sorted(
        label for label in labels if service_family_for_label(label).key == "resource"
    )

    # Assert
    assert len(labels) >= 170
    assert unresolved == []


def test_every_service_family_uses_an_installed_official_icon() -> None:
    # Act
    missing_icons = sorted(
        family.icon
        for family in SERVICE_FAMILIES.values()
        if not (AWS_ICONS / f"{family.icon}.svg").is_file()
    )

    # Assert
    assert missing_icons == []


def test_official_icon_package_is_complete_and_pinned() -> None:
    # Act
    manifest = json.loads((AWS_ICONS / "manifest.json").read_text())

    # Assert
    assert manifest["release"] == "04302026"
    assert manifest["icon_count"] >= 300
    assert len(manifest["archive_sha256"]) == 64


def test_absent_account_services_resolve_to_their_real_icon_families() -> None:
    # Arrange
    expected = {
        "AWSLoadBalancer": "elastic-load-balancing",
        "AWSLoadBalancerV2": "elastic-load-balancing",
        "AWSELBV2Listener": "elastic-load-balancing",
        "AWSAPIGatewayRestAPI": "amazon-api-gateway",
        "AWSSQSQueue": "amazon-simple-queue-service",
        "AWSEfsFileSystem": "amazon-efs",
        "AWSElasticacheCluster": "amazon-elasticache",
        "AWSRedshiftCluster": "amazon-redshift",
        "AWSESDomain": "amazon-opensearch-service",
        "AWSSecretsManagerSecret": "aws-secrets-manager",
    }

    # Act
    actual = {label: service_family_for_label(label).icon for label in expected}

    # Assert
    assert actual == expected


def test_landscape_enables_every_non_payload_aws_sync() -> None:
    # Act
    actual = set(landscape_sync_names())

    # Assert
    assert EXCLUDED_LANDSCAPE_SYNCS == {"ssm"}
    assert actual == (set(RESOURCE_FUNCTIONS) - EXCLUDED_LANDSCAPE_SYNCS)
