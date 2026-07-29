from __future__ import annotations

import logging
import time
from collections import OrderedDict
from typing import Callable

import neo4j
import neo4j.exceptions
from neo4j import GraphDatabase
from statsd import StatsClient

from cartography.config import Config
from cartography.intel.aws import start_aws_ingestion
from cartography.intel.create_indexes import run as create_indexes
from cartography.stats import set_stats_client
from cartography.util import STATUS_FAILURE
from cartography.util import STATUS_SUCCESS

logger = logging.getLogger(__name__)

TOP_LEVEL_MODULES: OrderedDict[str, Callable[..., None]] = OrderedDict(
    (
        ("create-indexes", create_indexes),
        ("aws", start_aws_ingestion),
    )
)


class Sync:
    """Run the Neo4j bootstrap and AWS inventory stages in a stable order."""

    def __init__(self) -> None:
        self._stages: OrderedDict[str, Callable[..., None]] = OrderedDict()

    def add_stage(self, name: str, func: Callable[..., None]) -> None:
        self._stages[name] = func

    def add_stages(self, stages: list[tuple[str, Callable[..., None]]]) -> None:
        for name, func in stages:
            self.add_stage(name, func)

    def run(self, neo4j_driver: neo4j.Driver, config: Config) -> int:
        logger.info("Starting AWS sync with update tag '%d'", config.update_tag)
        with neo4j_driver.session(database=config.neo4j_database) as neo4j_session:
            for stage_name, stage_func in self._stages.items():
                logger.info("Starting sync stage '%s'", stage_name)
                stage_func(neo4j_session, config)
                logger.info("Finished sync stage '%s'", stage_name)
        return STATUS_SUCCESS

    @classmethod
    def list_intel_modules(cls) -> OrderedDict[str, Callable[..., None]]:
        return TOP_LEVEL_MODULES.copy()


def run_with_config(sync: Sync, config: Config) -> int:
    if config.statsd_enabled:
        set_stats_client(
            StatsClient(
                host=config.statsd_host,
                port=config.statsd_port,
                prefix=config.statsd_prefix,
            ),
        )

    neo4j_auth = None
    if config.neo4j_user or config.neo4j_password:
        neo4j_auth = (config.neo4j_user, config.neo4j_password)
    driver_kwargs = {
        key: value
        for key, value in {
            "max_connection_lifetime": config.neo4j_max_connection_lifetime,
            "liveness_check_timeout": config.neo4j_liveness_check_timeout,
            "connection_timeout": config.neo4j_connection_timeout,
            "keep_alive": config.neo4j_keep_alive,
            "max_transaction_retry_time": config.neo4j_max_transaction_retry_time,
            "max_connection_pool_size": config.neo4j_max_connection_pool_size,
            "connection_acquisition_timeout": (
                config.neo4j_connection_acquisition_timeout
            ),
        }.items()
        if value is not None
    }
    try:
        driver = GraphDatabase.driver(
            config.neo4j_uri,
            auth=neo4j_auth,
            **driver_kwargs,
        )
    except (neo4j.exceptions.ServiceUnavailable, neo4j.exceptions.AuthError):
        logger.exception("Unable to connect or authenticate to Neo4j")
        return STATUS_FAILURE

    if not config.update_tag:
        config.update_tag = int(time.time())
    return sync.run(driver, config)


def build_default_sync() -> Sync:
    sync = Sync()
    sync.add_stages(list(TOP_LEVEL_MODULES.items()))
    return sync


def parse_and_validate_selected_modules(selected_modules: str) -> list[str]:
    modules = [
        module.strip() for module in selected_modules.split(",") if module.strip()
    ]
    invalid = set(modules) - set(TOP_LEVEL_MODULES)
    if invalid:
        raise ValueError(
            f"Unsupported sync stage(s): {', '.join(sorted(invalid))}. "
            f"Valid stages: {', '.join(TOP_LEVEL_MODULES)}",
        )
    return modules


def build_sync(selected_modules: str) -> Sync:
    names = parse_and_validate_selected_modules(selected_modules)
    sync = Sync()
    sync.add_stages([(name, TOP_LEVEL_MODULES[name]) for name in names])
    return sync
