# Local landscape

Run `./landscape/local.sh install`, then `./landscape/local.sh demo` from the repository root. The viewer is at http://127.0.0.1:8787 and the full icon gallery at /icons.html.

For live data, authenticate with `tccli auth login`, run `./landscape/local.sh sync --regions eu-frankfurt`, then `./landscape/local.sh serve`. A partial collection returns exit code 2 and still saves its snapshot. See the root README for supported services, coverage limitations, and optional Neo4j.
