from types import SimpleNamespace

import pytest

from cartography.intel.aws.util.botocore_config import _enforce_read_only_operation
from cartography.intel.aws.util.botocore_config import _is_read_only_operation
from cartography.intel.aws.util.botocore_config import aws_read_only_enabled
from cartography.intel.aws.util.botocore_config import AWSReadOnlyViolation


@pytest.mark.parametrize(  # type: ignore[misc]
    "operation_name",
    [
        "DescribeInstances",
        "GetCallerIdentity",
        "ListBuckets",
        "BatchGetItem",
        "LookupEvents",
        "SearchResources",
        "AssumeRole",
    ],
)
def test_read_only_operations_are_allowed(operation_name: str) -> None:
    # Act and assert
    assert _is_read_only_operation(operation_name)


@pytest.mark.parametrize(  # type: ignore[misc]
    "operation_name",
    [
        "CreateBucket",
        "DeleteObject",
        "PutBucketPolicy",
        "RunInstances",
        "StartInstances",
        "TagResources",
        "UpdateFunctionConfiguration",
    ],
)
def test_mutating_operations_are_rejected(operation_name: str) -> None:
    # Act and assert
    assert not _is_read_only_operation(operation_name)


def test_guard_raises_before_a_mutating_operation_is_sent() -> None:
    # Arrange
    model = SimpleNamespace(name="CreateBucket")

    # Act and assert
    with pytest.raises(AWSReadOnlyViolation, match="CreateBucket"):
        _enforce_read_only_operation(model)


@pytest.mark.parametrize(  # type: ignore[misc]
    "value",
    ["1", "true", "YES", "on"],
)
def test_read_only_environment_flag(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    # Arrange
    monkeypatch.setenv("CARTOGRAPHY_AWS_READ_ONLY", value)

    # Act and assert
    assert aws_read_only_enabled()
