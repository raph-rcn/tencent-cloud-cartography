# Local landscape

Run `./landscape/local.sh install`, then `./landscape/local.sh demo` from the repository root. The viewer is at http://127.0.0.1:8787 and the full icon gallery at /icons.html.

For live data, authenticate with `tccli auth login`, run `./landscape/local.sh sync --regions eu-frankfurt`, then `./landscape/local.sh serve`. A partial collection returns exit code 2 and still saves its snapshot. See the root README for supported services, coverage limitations, and optional Neo4j.

To read directly from Neo4j, run `./landscape/local.sh serve --neo4j-uri bolt://127.0.0.1:7688`. Use `import --input .local/demo.json --neo4j-uri bolt://127.0.0.1:7688` to publish an existing snapshot without cloud calls. Press **Refresh** after a sync or import; either backend reloads without restarting the viewer. Database credentials can be supplied via `NEO4J_USER` / `NEO4J_PASSWORD`, with `--neo4j-database` selecting a named database.
