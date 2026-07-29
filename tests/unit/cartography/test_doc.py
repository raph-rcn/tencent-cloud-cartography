from pathlib import Path

from cartography.sync import Sync


def test_readme_identifies_the_aws_only_fork() -> None:
    # Arrange
    readme = Path("README.md").read_text()

    # Act
    modules = list(Sync.list_intel_modules())

    # Assert
    assert readme.startswith("# AWS Cartography Landscape")
    assert "AWS-only" in readme
    assert modules == ["create-indexes", "aws"]
