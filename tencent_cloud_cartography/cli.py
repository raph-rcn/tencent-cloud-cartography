import argparse
import os
import sys
from pathlib import Path

from .catalog import SERVICE_ICONS
from .collect import collect
from .demo import demo
from .neo4j import Neo4jRepository
from .repository import FileRepository, SourceError
from .server import serve
from .storage import load, mirror, save
from .transport import CollectionError


def database_options(parser):
    parser.add_argument("--neo4j-user", default=os.environ.get("NEO4J_USER"))
    parser.add_argument(
        "--neo4j-password-env",
        default="NEO4J_PASSWORD",
        help="Name of the environment variable containing the database password",
    )
    parser.add_argument(
        "--neo4j-database",
        default=os.environ.get("NEO4J_DATABASE"),
        help="Named database; defaults to the server default",
    )


def database_credentials(args):
    return dict(
        user=args.neo4j_user,
        password=os.environ.get(args.neo4j_password_env),
        database=args.neo4j_database,
    )


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Tencent Cloud metadata inventory and local architecture diagrams"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sync = sub.add_parser(
        "sync", help="Collect read-only metadata through authenticated TCCLI profiles"
    )
    sync.add_argument(
        "--profile", action="append", help="Repeat for multiple accounts; defaults to default"
    )
    sync.add_argument("--regions", help="auto (default) or comma-separated region restrictions")
    sync.add_argument(
        "--services", help="Comma-separated native services; CloudRC baseline is always queried"
    )
    sync.add_argument(
        "--discover-regions",
        action="store_true",
        help="Discover per-service regions within any explicit region restrictions",
    )
    sync.add_argument("--tccli", default="tccli")
    sync.add_argument(
        "--tccli-python",
        help="TCCLI interpreter for custom wrappers; normally detected from the tccli launcher",
    )
    sync.add_argument(
        "--kube-context",
        action="append",
        help="Explicit ACCOUNT/REGION/CLUSTER=CONTEXT; reads only Kubernetes Tables without objects",
    )
    sync.add_argument("--output", type=Path)
    sync.add_argument("--project", help="Use saved environment settings and isolated snapshot")
    sync.add_argument("--projects-dir", type=Path, default=Path(".local/projects"))
    sync.add_argument(
        "--analysis-limit",
        type=int,
        default=25000,
        help="Generated decisions per analysis phase; limit breaches remain partial",
    )
    sync.add_argument(
        "--neo4j-uri", help="Optional loopback Neo4j mirror, e.g. bolt://127.0.0.1:7688"
    )
    database_options(sync)
    sample = sub.add_parser("demo", help="Write an explicitly synthetic Frankfurt snapshot")
    sample.add_argument("--output", type=Path, default=Path(".local/demo.json"))
    publish = sub.add_parser(
        "import", help="Publish a saved snapshot into local Neo4j without cloud access"
    )
    publish.add_argument("--input", type=Path, required=True)
    publish.add_argument("--neo4j-uri", default="bolt://127.0.0.1:7688")
    database_options(publish)
    analysis = sub.add_parser(
        "analyze", help="Analyze saved authorization and exposure configuration without cloud calls"
    )
    analysis.add_argument("--input", type=Path, required=True)
    analysis.add_argument("--output", type=Path, required=True)
    analysis.add_argument(
        "--context",
        type=Path,
        help="Optional JSON of allowlisted nonsecret request attributes; offline evaluation only",
    )
    analysis.add_argument(
        "--analysis-limit", type=int, default=25000, help="Generated decisions per analysis phase"
    )
    ui = sub.add_parser("serve", help="View local snapshots or read directly from Neo4j")
    source = ui.add_mutually_exclusive_group()
    source.add_argument("--input", type=Path, help="Snapshot file, default .local/inventory.json")
    source.add_argument(
        "--neo4j-uri", help="Read the latest published graph directly from local Neo4j"
    )
    database_options(ui)
    ui.add_argument("--port", type=int, default=8787)
    ui.add_argument("--project", help="Open a configured project")
    ui.add_argument("--projects-dir", type=Path, default=Path(".local/projects"))
    projects = sub.add_parser(
        "projects", help="Manage environment configurations without storing credentials"
    )
    projects.add_argument("--projects-dir", type=Path, default=Path(".local/projects"))
    commands = projects.add_subparsers(dest="project_command", required=True)
    init = commands.add_parser(
        "init", help="Create an isolated project using existing TCCLI profiles"
    )
    init.add_argument("name")
    init.add_argument("--profile", action="append")
    init.add_argument("--regions", default="auto")
    init.add_argument("--discover-regions", action="store_true")
    init.add_argument("--services")
    commands.add_parser("list", help="List configured projects")
    args = parser.parse_args(argv)
    try:
        if args.command == "sync":
            from .projects import ProjectStore

            store = ProjectStore(args.projects_dir)
            project = store.read(args.project) if args.project else None
            region_text = (
                args.regions
                if args.regions is not None
                else (",".join(project["regions"]) if project else "auto")
            )
            regions = list(dict.fromkeys(r.strip() for r in region_text.split(",") if r.strip()))
            args.output = args.output or (
                store.snapshot_path(args.project) if project else Path(".local/inventory.json")
            )
            from .collection_plan import region_restrictions

            region_restrictions(regions)
            services = (
                set(s.strip() for s in args.services.split(","))
                if args.services is not None
                else set(project["services"])
                if project and project["services"]
                else None
            )
            if services and "as" in services:
                services = (services - {"as"}) | {"autoscaling"}
            if services and not services <= SERVICE_ICONS.keys():
                parser.error(
                    "Unknown service; supported native services: "
                    + ", ".join(sorted(SERVICE_ICONS))
                )
            from .kubernetes_metadata import parse_contexts

            snapshot = collect(
                args.profile or (project["profiles"] if project else ["default"]),
                regions,
                services,
                args.tccli,
                tccli_python=args.tccli_python,
                kube_contexts=parse_contexts(args.kube_context),
                analysis_limit=args.analysis_limit,
                discover_regions=args.discover_regions
                or bool(project and project.get("discover_regions")),
            )
            collection = snapshot.get("collection")
            if collection and (
                not any(p["committed"] for p in collection["profiles"])
                or not (
                    any(s["successful_queries"] for s in collection["scopes"])
                    or any(n["status"] != "reference" for n in snapshot["nodes"])
                )
            ):
                report = args.output.with_name(args.output.name + ".attempt.json")
                save(snapshot, report)
                print(
                    f"No usable account inventory was collected; existing snapshot preserved. Coverage report: {report}",
                    file=sys.stderr,
                )
                return 1
            save(snapshot, args.output)
            print(
                f"Saved {len(snapshot['nodes'])} resources, {len(snapshot['edges'])} relationships; coverage={snapshot['status']}: {args.output}"
            )
            if args.neo4j_uri:
                mirror(snapshot, args.neo4j_uri, **database_credentials(args))
                print("Neo4j mirror updated")
            return 2 if snapshot["status"] == "partial" else 0
        if args.command == "demo":
            save(demo(), args.output)
            print(f"Synthetic demo written to {args.output}")
        elif args.command == "import":
            mirror(load(args.input), args.neo4j_uri, **database_credentials(args))
            print("Saved snapshot published to Neo4j")
        elif args.command == "analyze":
            from .authorization import load_context
            from .permissions import analyze_snapshot

            snapshot = analyze_snapshot(
                load(args.input),
                load_context(args.context) if args.context else None,
                args.analysis_limit,
            )
            save(snapshot, args.output)
            print(
                f"Analyzed authorization and exposure configuration; coverage={snapshot['status']}: {args.output}"
            )
            return 2 if snapshot["status"] == "partial" else 0
        elif args.command == "serve":
            from .projects import ProjectRepository, ProjectStore

            if args.project and (args.input or args.neo4j_uri):
                parser.error(
                    "--project selects its own snapshot; use it without --input or --neo4j-uri"
                )
            repository = (
                Neo4jRepository(args.neo4j_uri, **database_credentials(args))
                if args.neo4j_uri
                else FileRepository(args.input)
                if args.input
                else ProjectRepository(ProjectStore(args.projects_dir), args.project)
            )
            try:
                serve(port=args.port, repository=repository)
            finally:
                repository.close()
        elif args.command == "projects":
            import json

            from .projects import ProjectStore

            store = ProjectStore(args.projects_dir)
            if args.project_command == "init":
                services = args.services.split(",") if args.services else None
                store.create(
                    args.name,
                    args.profile or ["default"],
                    [r.strip() for r in args.regions.split(",") if r.strip()],
                    services,
                    args.discover_regions,
                )
                print("Project configured: " + args.name)
            else:
                print(json.dumps(store.list(), indent=2))
        return 0
    except CollectionError as exc:
        print("Collection stopped: " + exc.code, file=sys.stderr)
        return 1
    except (ValueError, OSError, SourceError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
