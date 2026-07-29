import os
from functools import lru_cache
from typing import Any

import botocore.config
from botocore.exceptions import BotoCoreError

DEFAULT_READ_TIMEOUT = 120
DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_RETRY_MODE = "standard"
VALID_RETRY_MODES = frozenset({"adaptive", "legacy", "standard"})

RETRY_MODE_ENV_VAR = "CARTOGRAPHY_AWS_RETRY_MODE"
MAX_ATTEMPTS_ENV_VAR = "CARTOGRAPHY_AWS_MAX_ATTEMPTS"
READ_TIMEOUT_ENV_VAR = "CARTOGRAPHY_AWS_READ_TIMEOUT"
LAMBDA_READ_TIMEOUT = 30
LAMBDA_MAX_ATTEMPTS = 2
READ_ONLY_ENV_VAR = "CARTOGRAPHY_AWS_READ_ONLY"

_READ_ONLY_OPERATION_PREFIXES = (
    "BatchGet",
    "BatchList",
    "Describe",
    "Get",
    "Head",
    "List",
    "Lookup",
    "Query",
    "Scan",
    "Search",
    "Select",
)
_READ_ONLY_OPERATION_ALLOWLIST = frozenset(
    {
        # Assuming a role creates temporary session credentials but does not
        # mutate an AWS resource. Cartography needs it for cross-account syncs.
        "AssumeRole",
    }
)


class AWSReadOnlyViolation(BotoCoreError):
    fmt = (
        "Blocked AWS operation {operation_name!r} because " f"{READ_ONLY_ENV_VAR}=true"
    )


def _env_flag_enabled(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def aws_read_only_enabled() -> bool:
    return _env_flag_enabled(READ_ONLY_ENV_VAR)


def _is_read_only_operation(operation_name: str) -> bool:
    return (
        operation_name in _READ_ONLY_OPERATION_ALLOWLIST
        or operation_name.startswith(_READ_ONLY_OPERATION_PREFIXES)
    )


def _enforce_read_only_operation(model: Any, **_: Any) -> None:
    if not _is_read_only_operation(model.name):
        raise AWSReadOnlyViolation(operation_name=model.name)


def _install_read_only_guard(client: Any) -> Any:
    if aws_read_only_enabled():
        client.meta.events.register(
            "before-call.*.*",
            _enforce_read_only_operation,
            unique_id="cartography-aws-read-only-guard",
        )
    return client


def _get_int_env(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None or raw_value == "":
        return default
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ValueError(
            f"{name} must be a positive integer, got {raw_value!r}."
        ) from exc
    if value < 1:
        raise ValueError(f"{name} must be a positive integer, got {raw_value!r}.")
    return value


def _get_retry_mode_env(default: str) -> str:
    raw_value = os.getenv(RETRY_MODE_ENV_VAR)
    if raw_value is None or raw_value == "":
        return default
    retry_mode = raw_value.strip().lower()
    if retry_mode not in VALID_RETRY_MODES:
        supported_modes = ", ".join(sorted(VALID_RETRY_MODES))
        raise ValueError(
            f"{RETRY_MODE_ENV_VAR} must be one of {supported_modes}, got {raw_value!r}."
        )
    return retry_mode


def _normalize_retries(
    config: botocore.config.Config,
    *,
    max_attempts: int,
    retry_mode: str,
) -> botocore.config.Config:
    # Botocore mutates Config.retries during client creation by replacing
    # max_attempts with total_max_attempts. Reset the shared config object so
    # callers always see the contract Cartography expects.
    config.retries = {
        "max_attempts": max_attempts,
        "mode": retry_mode,
    }
    return config


@lru_cache(maxsize=None)
def _get_botocore_config(
    *,
    read_timeout: int = DEFAULT_READ_TIMEOUT,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    retry_mode: str = DEFAULT_RETRY_MODE,
    max_pool_connections: int | None = None,
) -> botocore.config.Config:
    kwargs: dict[str, object] = {
        "read_timeout": read_timeout,
        "retries": {
            "max_attempts": max_attempts,
            "mode": retry_mode,
        },
    }
    if max_pool_connections is not None:
        kwargs["max_pool_connections"] = max_pool_connections
    return botocore.config.Config(**kwargs)


def get_botocore_config(
    *,
    read_timeout: int | None = None,
    max_attempts: int | None = None,
    retry_mode: str | None = None,
    max_pool_connections: int | None = None,
) -> botocore.config.Config:
    resolved_read_timeout = (
        read_timeout
        if read_timeout is not None
        else _get_int_env(READ_TIMEOUT_ENV_VAR, DEFAULT_READ_TIMEOUT)
    )
    resolved_max_attempts = (
        max_attempts
        if max_attempts is not None
        else _get_int_env(MAX_ATTEMPTS_ENV_VAR, DEFAULT_MAX_ATTEMPTS)
    )
    resolved_retry_mode = (
        retry_mode
        if retry_mode is not None
        else _get_retry_mode_env(DEFAULT_RETRY_MODE)
    )
    return _normalize_retries(
        _get_botocore_config(
            read_timeout=resolved_read_timeout,
            max_attempts=resolved_max_attempts,
            retry_mode=resolved_retry_mode,
            max_pool_connections=max_pool_connections,
        ),
        max_attempts=resolved_max_attempts,
        retry_mode=resolved_retry_mode,
    )


def get_lambda_botocore_config(
    *,
    read_timeout: int | None = None,
    max_attempts: int | None = None,
    retry_mode: str | None = None,
    max_pool_connections: int | None = None,
) -> botocore.config.Config:
    return get_botocore_config(
        read_timeout=(
            read_timeout if read_timeout is not None else LAMBDA_READ_TIMEOUT
        ),
        max_attempts=(
            max_attempts if max_attempts is not None else LAMBDA_MAX_ATTEMPTS
        ),
        retry_mode=retry_mode,
        max_pool_connections=max_pool_connections,
    )


def _create_client(
    session: Any,
    service_name: str,
    *args: Any,
    config: botocore.config.Config | None = None,
    **kwargs: Any,
) -> Any:
    return _install_read_only_guard(
        session.client(
            service_name,
            *args,
            config=config or get_botocore_config(),
            **kwargs,
        )
    )


def create_boto3_client(
    session: Any,
    service_name: str,
    *args: Any,
    config: botocore.config.Config | None = None,
    **kwargs: Any,
) -> Any:
    return _create_client(
        session,
        service_name,
        *args,
        config=config,
        **kwargs,
    )


def create_boto3_resource(
    session: Any,
    service_name: str,
    *args: Any,
    config: botocore.config.Config | None = None,
    **kwargs: Any,
) -> Any:
    resource = session.resource(
        service_name,
        *args,
        config=config or get_botocore_config(),
        **kwargs,
    )
    resource_client = getattr(getattr(resource, "meta", None), "client", None)
    if resource_client is not None:
        _install_read_only_guard(resource_client)
    return resource


def create_aioboto3_client(
    session: Any,
    service_name: str,
    *args: Any,
    config: botocore.config.Config | None = None,
    **kwargs: Any,
) -> Any:
    return _create_client(
        session,
        service_name,
        *args,
        config=config,
        **kwargs,
    )
