"""One explicit profile policy shared with the isolated TCCLI runtime.

This module uses only Python's standard library and also runs in TCCLI's Python.
No implicit instance-role fallback, credential-source merging or default-profile
fallback for missing named profiles is permitted.
"""

import hashlib
import json
import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .errors import AuthenticationError

PROFILE = re.compile(r"[A-Za-z0-9_.-]+")
ROLE = re.compile(r"qcs::cam::uin/([1-9][0-9]*):role(?:Name)?/([^/\s:]+)")
PROVIDERS = frozenset(("profile", "environment", "oauth", "sso", "role", "cvm-role", "tke-oidc"))
ENV_KEYS = ("TENCENTCLOUD_SECRET_ID", "TENCENTCLOUD_SECRET_KEY", "TENCENTCLOUD_TOKEN")
TKE_KEYS = ("TKE_REGION", "TKE_PROVIDER_ID", "TKE_WEB_IDENTITY_TOKEN_FILE", "TKE_ROLE_ARN")


def unique_object(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise ValueError("Duplicate field")
        result[k] = v
    return result


def read_json(path, optional=False):
    try:
        with path.open("rb") as stream:
            data = stream.read(1_000_001)
        if len(data) > 1_000_000:
            raise ValueError
        value = json.loads(data, object_pairs_hook=unique_object)
        if not isinstance(value, dict):
            raise ValueError
        return value
    except FileNotFoundError:
        if optional:
            return None
        raise AuthenticationError("MissingProfile") from None
    except (OSError, ValueError, TypeError):
        raise AuthenticationError("InvalidCredentialConfiguration") from None


def expiration(value):
    if value is None:
        return None
    if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
        raise AuthenticationError("InvalidCredentialConfiguration")
    return float(value)


def secret(value, optional=False):
    if optional and value in (None, ""):
        return None
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 65536
        or any(ord(c) < 32 for c in value)
    ):
        raise AuthenticationError("InvalidCredentialConfiguration")
    return value


@dataclass(repr=False, frozen=True)
class Material:
    secret_id: str = field(repr=False)
    secret_key: str = field(repr=False)
    token: str | None = field(default=None, repr=False)
    expires_at: float | None = None
    provider: str = "profile"
    target_account: str | None = None

    def __repr__(self):
        return "<CredentialMaterial redacted>"

    @classmethod
    def parse(cls, data):
        if not isinstance(data, dict) or data.get("provider", "profile") not in PROVIDERS:
            raise AuthenticationError("InvalidCredentialConfiguration")
        target = data.get("target_account")
        if target is not None and (
            not isinstance(target, str) or not re.fullmatch(r"[1-9][0-9]*", target)
        ):
            raise AuthenticationError("InvalidCredentialConfiguration")
        return cls(
            secret(data.get("secretId")),
            secret(data.get("secretKey")),
            secret(data.get("token"), True),
            expiration(data.get("expiresAt")),
            data.get("provider", "profile"),
            target,
        )

    def sdk(self):
        return dict(SecretId=self.secret_id, SecretKey=self.secret_key, Token=self.token)

    def wire(self):
        return dict(
            secretId=self.secret_id,
            secretKey=self.secret_key,
            token=self.token,
            expiresAt=self.expires_at,
            provider=self.provider,
            target_account=self.target_account,
        )


@dataclass(repr=False)
class Source:
    profile: str
    provider: str
    base_kind: str
    raw: dict = field(repr=False)
    path: Path | None = None
    role_arn: str | None = None
    role_session: str | None = None

    def __repr__(self):
        return "<CredentialSource redacted>"

    def stamp(self):
        # An in-memory change detector, never serialized into reports or logs.
        try:
            body = json.dumps(
                [self.provider, self.base_kind, self.raw, self.role_arn, self.role_session],
                sort_keys=True,
                allow_nan=False,
            )
        except (ValueError, TypeError):
            raise AuthenticationError("InvalidCredentialConfiguration") from None
        return hashlib.sha256(body.encode()).digest()

    def material(self):
        if (
            self.base_kind == "sso"
            and not any(self.raw.get(k) for k in ("secretId", "secretKey", "token"))
            and isinstance(self.raw.get("sso"), dict)
            and self.raw["sso"].get("authUrl")
        ):
            raise AuthenticationError("SsoLoginRequired", "sso")
        target = ROLE.fullmatch(self.role_arn)[1] if self.role_arn else None
        if target is None and self.base_kind == "sso" and isinstance(self.raw.get("sso"), dict):
            value = self.raw["sso"].get("uin")
            target = str(value) if type(value) in (str, int) else None
        material = Material.parse(dict(self.raw, provider=self.provider, target_account=target))
        if self.base_kind in {"oauth", "sso"}:
            login = self.raw.get(self.base_kind)
            if not material.token or not material.expires_at or not isinstance(login, dict):
                raise AuthenticationError("InvalidCredentialConfiguration")
            expiration(login.get("expiresAt"))
            required = (
                ("accessToken", "refreshToken", "openId", "site")
                if self.base_kind == "oauth"
                else (
                    "token",
                    "roleConfigurationId",
                    "roleConfigurationName",
                    "zoneId",
                    "site",
                    "authUrl",
                )
            )
            for key in required:
                secret(login.get(key))
            if self.base_kind == "sso" and (
                type(login.get("uin")) not in (str, int)
                or not re.fullmatch(r"[1-9][0-9]*", str(login["uin"]))
            ):
                raise AuthenticationError("InvalidCredentialConfiguration")
            if login.get("expiresAt") is None:
                raise AuthenticationError("InvalidCredentialConfiguration")
        return material


def load_source(profile, environ=None, home=None):
    if not isinstance(profile, str) or not PROFILE.fullmatch(profile) or profile in (".", ".."):
        raise AuthenticationError("InvalidProfile")
    environ = os.environ if environ is None else environ
    home = Path.home() if home is None else Path(home)
    path = home / ".tccli" / (profile + ".credential")
    raw = read_json(path, optional=True)
    if raw is not None:
        kind = raw.get("type", "default")
        if kind not in ("default", "oauth", "sso", "role", "cvm-role"):
            raise AuthenticationError("UnsupportedCredentialType")
        base = "profile" if kind in ("default", "role") else kind
    else:
        if profile != "default":
            raise AuthenticationError("MissingProfile")
        path = None
        raw = dict(zip(("secretId", "secretKey", "token"), (environ.get(k) for k in ENV_KEYS)))
        raw.update({k: environ.get(k) for k in TKE_KEYS if environ.get(k)})
        raw["role-arn"] = environ.get("TENCENTCLOUD_ROLE_ARN")
        raw["role-session-name"] = environ.get("TENCENTCLOUD_ROLE_SESSION_NAME")
        base = "environment"
        if not raw["role-arn"] and any(k in raw for k in TKE_KEYS):
            if not all(raw.get(k) for k in TKE_KEYS):
                raise AuthenticationError("InvalidCredentialConfiguration")
            if (
                not re.fullmatch(r"[a-z]+-[a-z0-9-]+", raw["TKE_REGION"])
                or not ROLE.fullmatch(raw["TKE_ROLE_ARN"])
                or not re.fullmatch(r"[A-Za-z0-9_-]+", raw["TKE_PROVIDER_ID"])
            ):
                raise AuthenticationError("InvalidCredentialConfiguration")
            base = "tke-oidc"
        elif not any(
            raw.get(k) for k in ("secretId", "secretKey", "token", "role-arn", "role-session-name")
        ):
            raise AuthenticationError("MissingCredentials")
    arn, session = raw.get("role-arn"), raw.get("role-session-name")
    if arn or session or raw.get("type") == "role":
        if (
            not isinstance(arn, str)
            or not ROLE.fullmatch(arn)
            or not isinstance(session, str)
            or not re.fullmatch(r"[A-Za-z0-9+=,.@_-]{2,128}", session)
        ):
            raise AuthenticationError("InvalidConfiguredRole")
        provider = "role"
    else:
        provider = base
    result = Source(profile, provider, base, raw, path, arn, session)
    if base not in ("cvm-role", "tke-oidc"):
        result.material()
    return result
