"""Structured COS XML metadata using the official SDK and the selected TCCLI profile."""

import re

from .authentication import quiet_sdk
from .transport import CollectionError

COS_ACTIONS = frozenset(
    "get_bucket_" + suffix
    for suffix in ("acl", "policy", "encryption", "versioning", "logging", "notification")
)
BUCKET = re.compile(r"[a-z0-9][a-z0-9-]*-\d+")


def credentials(profile):
    from .authentication import VerifiedSession
    from .tccli_runtime import TccliRuntime

    return VerifiedSession(profile, TccliRuntime()).material().sdk()


def validate_scope(action, region, params):
    # Restrict both method and parameters: no object operations, custom hosts or headers.
    if action == "list_buckets":
        if (
            not set(params) <= {"Marker", "MaxKeys"}
            or region is not None
            or (
                "Marker" in params
                and (
                    not isinstance(params["Marker"], str)
                    or len(params["Marker"]) > 1024
                    or any(ord(c) < 32 for c in params["Marker"])
                )
            )
            or (
                "MaxKeys" in params
                and (type(params["MaxKeys"]) is not int or not 1 <= params["MaxKeys"] <= 2000)
            )
        ):
            raise CollectionError("InvalidCosScope")
        return
    if action not in COS_ACTIONS:
        raise CollectionError("BlockedAction", "COS action is outside the metadata allowlist")
    if (
        set(params) != {"Bucket"}
        or not isinstance(params["Bucket"], str)
        or not BUCKET.fullmatch(params["Bucket"])
        or not isinstance(region, str)
        or not re.fullmatch(r"[a-z]+-[a-z0-9-]+", region)
    ):
        raise CollectionError("InvalidCosScope")


@quiet_sdk()
def call(profile, action, region, params, timeout, material=None):
    validate_scope(action, region, params)
    from qcloud_cos import CosConfig, CosS3Client, CosServiceError
    from qcloud_cos.cos_exception import CosClientError

    config = CosConfig(
        Region=region or "ap-guangzhou",
        Scheme="https",
        Timeout=timeout,
        AllowRedirects=False,
        VerifySSL=True,
        **(material.sdk() if material else credentials(profile)),
    )
    try:
        client = CosS3Client(config, retry=0)
        if action == "get_bucket_notification":
            # The Python SDK has no notification helper. Use its signing/HTTPS
            # transport with the fixed V2 query, never an arbitrary URL or method.
            from qcloud_cos.cos_auth import CosS3Auth

            from .cos_notifications import parse_xml

            query = {"notification": "", "notify-type": "2"}
            response = client.send_request(
                method="GET",
                url=config.uri(bucket=params["Bucket"]),
                bucket=params["Bucket"],
                auth=CosS3Auth(config, params=query),
                headers={},
                params=query,
            )
            result = parse_xml(response.content)
        else:
            result = getattr(client, action)(**params)
    except CosServiceError as exc:
        code = exc.get_error_code()
        raise CollectionError(
            code
            if isinstance(code, str) and re.fullmatch(r"[A-Za-z0-9.]+", code)
            else "CosApiError"
        ) from None
    except CosClientError:
        raise CollectionError("CosClientError") from None
    if not isinstance(result, dict):
        raise CollectionError("InvalidResponse")
    return result
