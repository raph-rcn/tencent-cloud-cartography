import pytest

from cartography.config import Config
from cartography.sync import build_default_sync
from cartography.sync import build_sync
from cartography.sync import parse_and_validate_selected_modules
from cartography.sync import run_with_config
from cartography.sync import Sync
from cartography.sync import TOP_LEVEL_MODULES


def test_available_modules_are_aws_only() -> None:
    # Arrange / Act
    available = Sync.list_intel_modules()

    # Assert
    assert list(available) == ["create-indexes", "aws"]
    assert list(available) == list(TOP_LEVEL_MODULES)


def test_build_default_sync() -> None:
    # Arrange / Act
    sync = build_default_sync()

    # Assert
    assert list(sync._stages) == ["create-indexes", "aws"]


def test_build_sync_accepts_only_aws_stages() -> None:
    # Arrange / Act
    sync = build_sync("create-indexes, aws")

    # Assert
    assert list(sync._stages) == ["create-indexes", "aws"]


def test_parse_rejects_removed_provider() -> None:
    # Arrange / Act / Assert
    with pytest.raises(ValueError, match="Unsupported sync stage"):
        parse_and_validate_selected_modules("aws,gcp")


def test_run_with_config_forwards_optional_driver_kwargs(mocker) -> None:
    # Arrange
    sync = mocker.Mock()
    driver = object()
    driver_mock = mocker.patch(
        "cartography.sync.GraphDatabase.driver",
        return_value=driver,
    )
    mocker.patch("cartography.sync.time.time", return_value=123)
    config = Config(
        neo4j_uri="bolt://localhost:7687",
        neo4j_user="neo4j",
        neo4j_password="password",
        neo4j_max_connection_lifetime=300,
        neo4j_liveness_check_timeout=30,
        neo4j_connection_timeout=15.0,
        neo4j_keep_alive=True,
        neo4j_max_transaction_retry_time=30.0,
        neo4j_max_connection_pool_size=64,
        neo4j_connection_acquisition_timeout=60.0,
    )

    # Act
    run_with_config(sync, config)

    # Assert
    driver_mock.assert_called_once_with(
        "bolt://localhost:7687",
        auth=("neo4j", "password"),
        max_connection_lifetime=300,
        liveness_check_timeout=30,
        connection_timeout=15.0,
        keep_alive=True,
        max_transaction_retry_time=30.0,
        max_connection_pool_size=64,
        connection_acquisition_timeout=60.0,
    )
    sync.run.assert_called_once_with(driver, config)
    assert config.update_tag == 123
