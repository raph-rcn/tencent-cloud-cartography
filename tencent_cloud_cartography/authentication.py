"""Shared explicit credential resolution and identity-bound scan sessions."""

import hashlib
import io
import json
import logging
import re
import threading
import time
from contextlib import contextmanager, redirect_stderr, redirect_stdout

from .auth_source import PROVIDERS, Material, load_source
from .errors import AuthenticationError, CollectionError

EXPIRED_CODES = frozenset(
    (
        "AuthFailure.TokenFailure",
        "AuthFailure.TokenExpire",
        "AuthFailure.TokenExpired",
        "AuthFailure.ExpiredToken",
        "ExpiredToken",
        "ExpiredTokenException",
        "InvalidSecurity",
        "InvalidToken",
        "AuthSessionExpired",
    )
)
LOGIN_CODES = frozenset(
    (
        "OAuthLoginRequired",
        "SsoSessionExpired",
        "SsoLoginRequired",
        "AuthSessionExpired",
        "MissingCredentials",
        "MissingProfile",
    )
)


@contextmanager
def quiet_sdk():
    previous = logging.root.manager.disable
    try:
        logging.disable(max(previous, logging.CRITICAL))
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            yield
    finally:
        logging.disable(previous)


def stable_identity(value, strict=True):
    if not isinstance(value, dict):
        raise AuthenticationError("InvalidIdentity")
    account = str(value.get("AccountId") or "")
    if not re.fullmatch(r"[1-9][0-9]*", account):
        raise AuthenticationError("InvalidIdentity")
    fields = [value.get(k) for k in ("PrincipalId", "Arn", "Type", "UserId")]
    if any(v is not None and (not isinstance(v, str) or len(v) > 4096) for v in fields):
        raise AuthenticationError("InvalidIdentity")
    principal, arn, kind, user = fields
    if strict and not all((principal, arn, kind, user)):
        raise AuthenticationError("InvalidIdentity")
    if kind == "CAMRole" and isinstance(user, str) and isinstance(arn, str):
        match = re.fullmatch(r"qcs::sts:" + account + r":assumed-role/([0-9]+)", arn)
        if match and user.startswith(match[1] + ":") and user.split(":", 1)[1]:
            # Documented role session names rotate on SSO refresh. Keep role ID,
            # source principal, account and complete ARN bound to the session.
            user = match[1]
    return account, principal, arn, kind, user


def fingerprint(material):
    return hashlib.sha256(json.dumps(material.wire(), sort_keys=True).encode()).digest()


class ProfileResolver:
    def __init__(self, profile, runtime, clock=time.time):
        self.profile, self.runtime, self.clock = profile, runtime, clock
        self.provider = "unknown"
        self.login_provider = "unknown"
        self.material = None
        self.stamp = None
        self.refreshes = 0

    def resolve(self, force=False):
        try:
            source = load_source(self.profile)
        except AuthenticationError as exc:
            if exc.provider in PROVIDERS:
                self.provider = exc.provider
                self.login_provider = exc.provider
            raise
        self.provider = source.provider
        self.login_provider = source.base_kind
        stamp = source.stamp()
        cached = self.material
        if (
            not force
            and stamp == self.stamp
            and cached
            and (cached.expires_at is None or cached.expires_at > self.clock() + 300)
        ):
            return cached
        if source.provider in {"profile", "environment"}:
            material = source.material()
            if material.expires_at is not None and material.expires_at <= self.clock() + 30:
                raise AuthenticationError("AuthSessionExpired")
            if force and cached and fingerprint(material) == fingerprint(cached):
                raise AuthenticationError("AuthSessionExpired")
        elif (
            source.provider in {"oauth", "sso"}
            and not force
            and source.raw["expiresAt"] > self.clock() + 300
        ):
            material = source.material()
        else:
            material = Material.parse(
                self.runtime.invoke("resolve", profile=self.profile, force=force)
            )
            if material.provider != source.provider:
                raise AuthenticationError("CredentialSourceChanged")
            if material.expires_at is None or material.expires_at <= self.clock() + 30:
                raise AuthenticationError("AuthSessionExpired")
        if cached and fingerprint(material) != fingerprint(cached):
            self.refreshes += 1
        self.material, self.stamp = material, load_source(self.profile).stamp()
        return material


class VerifiedSession:
    def __init__(self, profile, runtime, resolver=None):
        self.profile, self.runtime = profile, runtime
        self.resolver = resolver or ProfileResolver(profile, runtime)
        self._identity = self._fingerprint = self._failure = None
        self.generations = 0
        self._lock = threading.RLock()

    def _probe(self, material):
        return self.runtime.invoke(
            "metadata",
            service="sts",
            action="GetCallerIdentity",
            region=None,
            params={},
            material=material.wire(),
        )

    def material(self, force=False):
        with self._lock:
            if self._failure:
                raise AuthenticationError(self._failure)
            try:
                material = self.resolver.resolve(force)
                candidate = fingerprint(material)
                if candidate != self._fingerprint or force:
                    try:
                        identity = stable_identity(self._probe(material))
                    except CollectionError as exc:
                        if exc.code in EXPIRED_CODES and not force:
                            return self.material(force=True)
                        raise
                    if material.target_account and identity[0] != material.target_account:
                        raise AuthenticationError("IdentityChanged")
                    if self._identity is not None and identity != self._identity:
                        raise AuthenticationError("IdentityChanged")
                    if (
                        material.expires_at is not None
                        and material.expires_at <= self.resolver.clock() + 5
                    ):
                        if not force:
                            return self.material(force=True)
                        raise AuthenticationError("AuthSessionExpired")
                    self._identity = identity
                    self.generations += int(candidate != self._fingerprint)
                    self._fingerprint = candidate
                return material
            except CollectionError as exc:
                self._failure = exc.code
                raise

    def execute(self, operation):
        material = self.material()
        try:
            return operation(material)
        except CollectionError as exc:
            if exc.code not in EXPIRED_CODES:
                raise
        # One forced refresh and one replay; no fallback or permission-driven
        # credential switching. All collection operations are allowlisted reads.
        material = self.material(force=True)
        try:
            return operation(material)
        except CollectionError as exc:
            if exc.code in EXPIRED_CODES:
                self._failure = "AuthSessionExpired"
                raise AuthenticationError(self._failure) from None
            raise

    def report(self):
        code = self._failure or ""
        provider = self.resolver.provider
        status = "ready" if self.generations else "unverified"
        if code:
            status = "login-required" if code in LOGIN_CODES else "failed"
        login = (
            "sso"
            if code in {"SsoLoginRequired", "SsoSessionExpired"}
            or self.resolver.login_provider == "sso"
            else "auth"
            if code == "OAuthLoginRequired" or self.resolver.login_provider == "oauth"
            else "configure"
        )
        # Safe structured data only; neither identity documents nor material are
        # serialized. Profiles are independently validated before interpolation.
        return dict(
            provider=provider,
            status=status,
            code=code,
            generations=self.generations,
            refreshes=self.resolver.refreshes,
            remediation=(
                f"tccli {login} login --profile {self.profile}"
                if login != "configure"
                else f"tccli configure --profile {self.profile}"
            )
            if code in LOGIN_CODES
            else "",
        )


def validate_report(report):
    if not isinstance(report, dict) or set(report) != {
        "provider",
        "status",
        "code",
        "generations",
        "refreshes",
        "remediation",
    }:
        raise ValueError("Invalid authentication report")
    if report["provider"] not in PROVIDERS | {"unknown"} or report["status"] not in {
        "ready",
        "unverified",
        "failed",
        "login-required",
    }:
        raise ValueError("Invalid authentication status")
    if any(
        type(report[k]) is not int or not 0 <= report[k] <= 1_000_000
        for k in ("generations", "refreshes")
    ):
        raise ValueError("Invalid authentication counts")
    if not isinstance(report["code"], str) or not re.fullmatch(
        r"[A-Za-z0-9.]{0,101}", report["code"]
    ):
        raise ValueError("Invalid authentication code")
    if not isinstance(report["remediation"], str) or (
        report["remediation"]
        and not re.fullmatch(
            r"tccli (?:auth login|sso login|configure) --profile [A-Za-z0-9_.-]+",
            report["remediation"],
        )
    ):
        raise ValueError("Invalid authentication remediation")
