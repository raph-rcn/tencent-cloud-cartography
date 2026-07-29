#!/usr/bin/env bash
set -euo pipefail

LANDSCAPE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${LANDSCAPE_DIR}/.." && pwd)"
COMPOSE_FILE="${LANDSCAPE_DIR}/compose.yaml"

ARCHITECTURE_SYNCS="iam,iaminstanceprofiles,kms,s3,dynamodb,ec2:launch_templates,ec2:autoscalinggroup,ec2:instance,ec2:security_group,ec2:subnet,ec2:load_balancer,ec2:load_balancer_v2,ec2:network_acls,ec2:network_interface,ec2:tgw,ec2:vpc,ec2:vpc_endpoint,ec2:route_table,ec2:vpc_peering,ec2:internet_gateway,ec2:volumes,ecr,ecs,eks,elasticache,elastic_ip_addresses,lambda_function,rds,redshift,route53,elasticsearch,cloudformation,permission_relationships,resourcegroupstaggingapi,apigateway,apigatewayv2,cloudfront,s3accountpublicaccessblock,sns,sqs,acm:certificate,efs,cognito,eventbridge"

usage() {
  echo "Usage: landscape/local.sh {install|start|sync|serve|stop|status}"
}

case "${1:-}" in
  install)
    cd "${REPO_DIR}"
    uv sync
    cd "${LANDSCAPE_DIR}/web"
    npm install
    npm run build
    ;;
  start)
    docker compose -f "${COMPOSE_FILE}" up -d
    ;;
  sync)
    cd "${REPO_DIR}"
    export CARTOGRAPHY_AWS_READ_ONLY=true
    syncs="${CARTOGRAPHY_AWS_REQUESTED_SYNCS:-${ARCHITECTURE_SYNCS}}"
    args=(
      --quiet
      --neo4j-uri bolt://127.0.0.1:7687
      --selected-modules aws
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
