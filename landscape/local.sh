#!/usr/bin/env bash
set -euo pipefail

LANDSCAPE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${LANDSCAPE_DIR}/.." && pwd)"
COMPOSE_FILE="${LANDSCAPE_DIR}/compose.yaml"

usage() {
  echo "Usage: landscape/local.sh {install|start|sync|serve|stop|status}"
}

case "${1:-}" in
  install)
    cd "${REPO_DIR}"
    uv sync
    cd "${LANDSCAPE_DIR}/web"
    npm ci
    npm run build
    ;;
  start)
    docker compose -f "${COMPOSE_FILE}" up -d
    ;;
  sync)
    cd "${REPO_DIR}"
    export CARTOGRAPHY_AWS_READ_ONLY=true
    landscape_syncs="$(
      uv run python -c \
        "from cartography.landscape.syncs import landscape_sync_names; print(','.join(landscape_sync_names()))"
    )"
    syncs="${CARTOGRAPHY_AWS_REQUESTED_SYNCS:-${landscape_syncs}}"
    args=(
      --quiet
      --neo4j-uri bolt://127.0.0.1:7687
      --aws-requested-syncs "${syncs}"
    )
    if [[ -n "${CARTOGRAPHY_AWS_REGIONS:-}" ]]; then
      args+=(--aws-regions "${CARTOGRAPHY_AWS_REGIONS}")
    fi
    uv run cartography "${args[@]}"
    ;;
  serve)
    cd "${REPO_DIR}"
    uv run python -m cartography.landscape.server
    ;;
  stop)
    docker compose -f "${COMPOSE_FILE}" down
    ;;
  status)
    docker compose -f "${COMPOSE_FILE}" ps
    ;;
  *)
    usage
    exit 2
    ;;
esac
