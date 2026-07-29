from __future__ import annotations


class Config:
    """Configuration required by the AWS-only sync and local Neo4j graph."""

    def __init__(
        self,
        neo4j_uri: str,
        neo4j_user: str | None = None,
        neo4j_password: str | None = None,
        neo4j_max_connection_lifetime: int | None = None,
        neo4j_liveness_check_timeout: int | None = None,
        neo4j_database: str | None = None,
        update_tag: int | None = None,
        aws_sync_all_profiles: bool = False,
        aws_regions: str | None = None,
        aws_best_effort_mode: bool = False,
        experimental_aws_inspector_batch: int = 1000,
        aws_tagging_api_cleanup_batch: int = 1000,
        aws_ssm_public_parameter_prefix_allowlist: str | None = None,
        aws_requested_syncs: str | None = None,
        aws_guardduty_severity_threshold: str | None = None,
        permission_relationships_file: str | None = None,
        statsd_enabled: bool = False,
        statsd_prefix: str | None = None,
        statsd_host: str | None = None,
        statsd_port: int | None = None,
        neo4j_connection_timeout: float | None = None,
        neo4j_keep_alive: bool | None = None,
        neo4j_max_transaction_retry_time: float | None = None,
        neo4j_max_connection_pool_size: int | None = None,
        neo4j_connection_acquisition_timeout: float | None = None,
        aws_organization_account_ids: str | None = None,
    ) -> None:
        self.neo4j_uri = neo4j_uri
        self.neo4j_user = neo4j_user
        self.neo4j_password = neo4j_password
        self.neo4j_max_connection_lifetime = neo4j_max_connection_lifetime
        self.neo4j_liveness_check_timeout = neo4j_liveness_check_timeout
        self.neo4j_database = neo4j_database
        self.neo4j_connection_timeout = neo4j_connection_timeout
        self.neo4j_keep_alive = neo4j_keep_alive
        self.neo4j_max_transaction_retry_time = neo4j_max_transaction_retry_time
        self.neo4j_max_connection_pool_size = neo4j_max_connection_pool_size
        self.neo4j_connection_acquisition_timeout = neo4j_connection_acquisition_timeout
        self.update_tag = update_tag

        self.aws_sync_all_profiles = aws_sync_all_profiles
        self.aws_regions = aws_regions
        self.aws_organization_account_ids = aws_organization_account_ids
        self.aws_best_effort_mode = aws_best_effort_mode
        self.experimental_aws_inspector_batch = experimental_aws_inspector_batch
        self.aws_tagging_api_cleanup_batch = aws_tagging_api_cleanup_batch
        self.aws_ssm_public_parameter_prefix_allowlist = (
            aws_ssm_public_parameter_prefix_allowlist
        )
        self.aws_requested_syncs = aws_requested_syncs
        self.aws_guardduty_severity_threshold = aws_guardduty_severity_threshold
        self.permission_relationships_file = permission_relationships_file

        self.statsd_enabled = statsd_enabled
        self.statsd_prefix = statsd_prefix
        self.statsd_host = statsd_host
        self.statsd_port = statsd_port
