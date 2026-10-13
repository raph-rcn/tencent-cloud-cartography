"""Structured COS XML metadata using the official SDK and the selected TCCLI profile."""

import json
import os
import re
from pathlib import Path

from .transport import CollectionError

COS_ACTIONS = frozenset(
    "get_bucket_" + suffix for suffix in ("acl", "policy", "encryption", "versioning", "logging")
)
BUCKET = re.compile(r"[a-z0-9][a-z0-9-]*-\d+")


def credentials(profile):
    path = Path.home() / ".tccli" / (profile + ".credential")
    env = {
        k: os.environ.get(v)
        for k, v in (
            ("secretId", "TENCENTCLOUD_SECRET_ID"),
            ("secretKey", "TENCENTCLOUD_SECRET_KEY"),
            ("token", "TENCENTCLOUD_TOKEN"),
        )
    }
    if any(env.values()):
        if path.exists():
            raise CollectionError("CredentialSourceConflict")
        raw = env
    else:
        try:
            raw = json.loads(path.read_text())
        except (OSError, ValueError):
            raise CollectionError("MissingCredentials") from None
    if not isinstance(raw, dict):
        raise CollectionError("InvalidCredentialConfiguration")
    # Never silently consume cached SSO/OAuth/role credentials without refreshing.
    if raw.get("type", "default") != "default":
        raise CollectionError("UnsupportedCosCredentialType")
    if not all(isinstance(raw.get(k), str) and raw[k] for k in ("secretId", "secretKey")):
        raise CollectionError("MissingCredentials")
    if raw.get("token") is not None and not isinstance(raw["token"], str):
        raise CollectionError("InvalidCredentialConfiguration")
    return dict(SecretId=raw["secretId"], SecretKey=raw["secretKey"], Token=raw.get("token"))


def call(profile, action, region, params, timeout):
    # Restrict both method and parameters: no object operations, custom hosts or headers.
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
    from qcloud_cos import CosConfig, CosS3Client, CosServiceError
    from qcloud_cos.cos_exception import CosClientError

    config = CosConfig(
        Region=region,
        Scheme="https",
        Timeout=timeout,
        AllowRedirects=False,
        VerifySSL=True,
        **credentials(profile),
    )
    try:
        result = getattr(CosS3Client(config, retry=0), action)(**params)
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
