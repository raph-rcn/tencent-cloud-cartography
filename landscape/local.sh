#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
case "${1:-help}" in
  install)
    uv sync --frozen
    (cd landscape/web && npm ci && npm run build)
    ;;
  demo)
    uv run tencent-cloud-cartography demo
    exec uv run tencent-cloud-cartography serve --input .local/demo.json
    ;;
  sync|import|analyze|projects)
    command="$1"
    shift
    exec uv run tencent-cloud-cartography "$command" "$@"
    ;;
  serve)
    shift
    exec uv run tencent-cloud-cartography serve "$@"
    ;;
  start)
    docker compose -f landscape/compose.yaml up -d --wait
    ;;
  stop)
    docker compose -f landscape/compose.yaml stop
    ;;
  status)
    docker compose -f landscape/compose.yaml ps
    ;;
  *)
    echo 'Usage: ./landscape/local.sh install|serve [options]|projects init NAME|projects list|sync [options]|analyze [options]|import [options]|demo|start|stop|status'
    echo 'The diagram runs from a private JSON snapshot. Neo4j is optional.'
    ;;
esac
