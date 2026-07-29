from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

import typer
from typing_extensions import Annotated

from cartography.config import Config
from cartography.landscape.syncs import landscape_sync_names
from cartography.sync import build_default_sync
from cartography.sync import run_with_config
from cartography.version import get_release_version_and_commit_revision

DEFAULT_PERMISSION_RELATIONSHIPS = str(
    Path(__file__).with_name("data") / "permission_relationships.yaml"
)

app = typer.Typer(
    add_completion=False,
    help=(
        "Collect AWS resource metadata and relationships into the local "
        "Cartography Landscape graph."
    ),
)


def _version_callback(value: bool) -> None:
    if value:
        release, revision = get_release_version_and_commit_revision()
        typer.echo(f"AWS Cartography Landscape {release} ({revision})")
        raise typer.Exit()


@app.command()  # type: ignore[misc]
def sync(
    neo4j_uri: Annotated[
        str,
        typer.Option(help="Neo4j Bolt URI."),
    ] = "bolt://127.0.0.1:7687",
    aws_regions: Annotated[
        str | None,
        typer.Option(help="Comma-separated AWS regions; omit for auto-discovery."),
    ] = None,
    aws_requested_syncs: Annotated[
        str | None,
        typer.Option(help="Comma-separated Cartography AWS collectors."),
    ] = None,
    aws_sync_all_profiles: Annotated[
        bool,
        typer.Option(help="Sync every configured AWS profile."),
    ] = False,
    aws_organization_account_ids: Annotated[
        str | None,
        typer.Option(help="Optional AWS Organizations account IDs."),
    ] = None,
    aws_best_effort_mode: Annotated[
        bool,
        typer.Option(help="Continue collecting other accounts after an account error."),
    ] = False,
    permission_relationships_file: Annotated[
        str | None,
        typer.Option(help="AWS permission-relationship mapping file."),
    ] = None,
    aws_guardduty_severity_threshold: Annotated[
        str | None,
        typer.Option(help="Minimum GuardDuty severity."),
    ] = None,
    neo4j_user: Annotated[str | None, typer.Option()] = None,
    neo4j_password_env_var: Annotated[
        str | None,
        typer.Option(help="Environment variable containing the Neo4j password."),
    ] = None,
    quiet: Annotated[bool, typer.Option("--quiet", "-q")] = False,
    verbose: Annotated[int, typer.Option("--verbose", "-v", count=True)] = 0,
    version: Annotated[
        bool,
        typer.Option("--version", callback=_version_callback, is_eager=True),
    ] = False,
) -> None:
    """Run the AWS-only, read-only metadata sync."""
    del version
    logging.basicConfig(
        level=(
            logging.ERROR if quiet else logging.DEBUG if verbose > 0 else logging.INFO
        ),
        format="%(levelname)s %(name)s: %(message)s",
    )

    # This fork intentionally has no mode that permits mutating AWS API calls.
    os.environ["CARTOGRAPHY_AWS_READ_ONLY"] = "true"
    requested_syncs = aws_requested_syncs or ",".join(landscape_sync_names())
    password = (
        os.environ.get(neo4j_password_env_var) if neo4j_password_env_var else None
    )
    config = Config(
        neo4j_uri=neo4j_uri,
        neo4j_user=neo4j_user,
        neo4j_password=password,
        aws_regions=aws_regions,
        aws_requested_syncs=requested_syncs,
        aws_sync_all_profiles=aws_sync_all_profiles,
        aws_organization_account_ids=aws_organization_account_ids,
        aws_best_effort_mode=aws_best_effort_mode,
        permission_relationships_file=(
            permission_relationships_file or DEFAULT_PERMISSION_RELATIONSHIPS
        ),
        aws_guardduty_severity_threshold=aws_guardduty_severity_threshold,
    )
    raise typer.Exit(run_with_config(build_default_sync(), config))


class CLI:
    """Compatibility wrapper for programmatic invocation in tests and scripts."""

    def __init__(self, prog: str = "aws-cartography-landscape") -> None:
        self.prog = prog

    def main(self, args: list[str] | None = None) -> None:
        app(
            args=args,
            prog_name=self.prog,
            standalone_mode=False,
        )


def main() -> None:
    CLI().main(sys.argv[1:])


if __name__ == "__main__":
    main()
