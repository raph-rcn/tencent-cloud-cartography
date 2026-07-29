from __future__ import annotations

from cartography.intel.aws.resources import RESOURCE_FUNCTIONS


# SSM reads parameter values and CloudTrail management-event collection reads
# event payloads. The landscape inventories the SSM/CloudTrail services through
# related metadata where available, but intentionally does not ingest those two
# payload-bearing streams.
EXCLUDED_LANDSCAPE_SYNCS = {
    "cloudtrail_management_events",
    "ssm",
}


def landscape_sync_names() -> list[str]:
    return [
        name
        for name in RESOURCE_FUNCTIONS
        if name not in EXCLUDED_LANDSCAPE_SYNCS
    ]

