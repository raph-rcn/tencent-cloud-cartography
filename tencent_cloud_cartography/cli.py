import argparse
import sys
from pathlib import Path

from .catalog import SERVICE_ICONS
from .collect import collect
from .demo import demo
from .server import serve
from .storage import load, mirror, save
from .transport import CollectionError


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
    sync.add_argument("--regions", default="eu-frankfurt", help="Comma-separated regions")
    sync.add_argument(
        "--services", help="Comma-separated native services; CloudRC baseline is always queried"
    )
    sync.add_argument("--tccli", default="tccli")
    sync.add_argument("--output", type=Path, default=Path(".local/inventory.json"))
    sync.add_argument(
        "--neo4j-uri", help="Optional loopback Neo4j mirror, e.g. bolt://127.0.0.1:7688"
    )
    sample = sub.add_parser("demo", help="Write an explicitly synthetic Frankfurt snapshot")
    sample.add_argument("--output", type=Path, default=Path(".local/demo.json"))
    ui = sub.add_parser("serve", help="Serve a saved snapshot on loopback")
    ui.add_argument("--input", type=Path, default=Path(".local/inventory.json"))
    ui.add_argument("--port", type=int, default=8787)
    args = parser.parse_args(argv)
    try:
        if args.command == "sync":
            regions = list(dict.fromkeys(r.strip() for r in args.regions.split(",") if r.strip()))
            if not regions or any(
                not r.replace("-", "").isalnum() or r == "global" for r in regions
            ):
                parser.error("Provide one or more region codes, e.g. eu-frankfurt")
            services = set(args.services.split(",")) if args.services else None
            if services and not services <= SERVICE_ICONS.keys():
                parser.error(
                    "Unknown service; supported native services: "
                    + ", ".join(sorted(SERVICE_ICONS))
                )
            snapshot = collect(args.profile or ["default"], regions, services, args.tccli)
            save(snapshot, args.output)
            print(
                f"Saved {len(snapshot['nodes'])} resources, {len(snapshot['edges'])} relationships; coverage={snapshot['status']}: {args.output}"
            )
            if args.neo4j_uri:
                mirror(snapshot, args.neo4j_uri)
                print("Neo4j mirror updated")
            return 2 if snapshot["status"] == "partial" else 0
        if args.command == "demo":
            save(demo(), args.output)
            print(f"Synthetic demo written to {args.output}")
        elif args.command == "serve":
            serve(load(args.input), args.port)
        return 0
    except CollectionError as exc:
        print("Collection stopped: " + exc.code, file=sys.stderr)
        return 1
    except (ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
