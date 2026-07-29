from __future__ import annotations

from cartography.intel.aws.resources import RESOURCE_FUNCTIONS

# SSM reads parameter values. The landscape still inventories Systems Manager
# relationships through other AWS metadata, but does not ingest parameter
# payloads.
EXCLUDED_LANDSCAPE_SYNCS = {
    "ssm",
}


def landscape_sync_names() -> list[str]:
    return [name for name in RESOURCE_FUNCTIONS if name not in EXCLUDED_LANDSCAPE_SYNCS]
