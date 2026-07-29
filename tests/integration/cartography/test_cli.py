import os
from unittest import mock

from cartography.cli import CLI
from cartography.landscape.syncs import landscape_sync_names


def test_cli_builds_aws_only_read_only_config(monkeypatch) -> None:
    monkeypatch.setenv("CARTOGRAPHY_AWS_READ_ONLY", "false")
    captured_config = None

    def capture_run_with_config(sync, config):
        nonlocal captured_config
        captured_config = config
        return 0

    with mock.patch(
        "cartography.cli.run_with_config",
        side_effect=capture_run_with_config,
    ):
        CLI("test").main(
            [
                "--neo4j-uri",
                "bolt://127.0.0.1:7687",
                "--aws-regions",
                "eu-central-1,eu-west-1",
                "--aws-requested-syncs",
                "s3,ec2:vpc",
                "--aws-best-effort-mode",
            ],
        )

    assert os.environ["CARTOGRAPHY_AWS_READ_ONLY"] == "true"
    assert captured_config is not None
    assert captured_config.neo4j_uri == "bolt://127.0.0.1:7687"
    assert captured_config.aws_regions == "eu-central-1,eu-west-1"
    assert captured_config.aws_requested_syncs == "s3,ec2:vpc"
    assert captured_config.aws_best_effort_mode is True


def test_cli_defaults_to_safe_landscape_collectors(monkeypatch) -> None:
    monkeypatch.setenv("CARTOGRAPHY_AWS_READ_ONLY", "false")
    captured_config = None

    def capture_run_with_config(sync, config):
        nonlocal captured_config
        captured_config = config
        return 0

    with mock.patch(
        "cartography.cli.run_with_config",
        side_effect=capture_run_with_config,
    ):
        CLI("test").main([])

    assert captured_config is not None
    assert captured_config.aws_requested_syncs == ",".join(landscape_sync_names())
    assert "ssm" not in captured_config.aws_requested_syncs.split(",")


def test_cli_help_is_aws_specific(capsys, monkeypatch) -> None:
    monkeypatch.setenv("CARTOGRAPHY_AWS_READ_ONLY", "false")
    CLI("test").main(["--help"])

    help_text = capsys.readouterr().out
    assert "AWS-only, read-only metadata sync" in help_text
    assert "--aws-regions" in help_text
    assert "Cartography AWS" in help_text
    assert "--microsoft" not in help_text
    assert "--gcp" not in help_text
    assert "--azure" not in help_text
    assert "--trivy" not in help_text
