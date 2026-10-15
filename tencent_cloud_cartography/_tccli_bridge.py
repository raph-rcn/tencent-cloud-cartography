"""Isolated native TCCLI authentication and API runtime (private pipe protocol).

Run by absolute filename under TCCLI's Python, not the inventory virtualenv. Only
stdlib imports occur before output is suppressed. Never import tccli.main.
"""

import contextlib
import importlib
import io
import json
import logging
import os
import re
import sys
import tempfile
import time
import types
import uuid
from pathlib import Path

# -I omits the script directory. Register only this package's search path: adding
# its parent site-packages would expose the application's conflicting SDK when
# the bridge runs from an installed wheel rather than a source checkout.
if __name__ == "__main__":
    package = types.ModuleType("tencent_cloud_cartography")
    package.__path__ = [str(Path(__file__).resolve().parent)]
    sys.modules[package.__name__] = package

from tencent_cloud_cartography.auth_source import (  # noqa: E402
    ROLE,
    Material,
    load_source,
)
from tencent_cloud_cartography.errors import AuthenticationError, CollectionError  # noqa: E402


def atomic_cache(path, value):
    fd, temporary = tempfile.mkstemp(prefix=".cartography-auth-", dir=path.parent)
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextlib.contextmanager
def cache_lock(path):
    # Serializes concurrent cartography refreshes. TCCLI remains the cache owner;
    # independently running tccli login/logout should be done between scans.
    lock = path.with_suffix(".cartography-auth.lock")
    fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        os.chmod(lock, 0o600)
        with os.fdopen(fd, "r+b") as stream:
            if os.name == "nt":
                import msvcrt

                stream.write(b"0")
                stream.flush()
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            yield
    finally:
        # Closing the handle releases the lock, including on exceptions.
        pass


def secure_native_http(module, timeout):
    """Harden the native OAuth helpers' verify=False and unbounded requests."""
    import requests

    post = requests.post

    def verified_post(url, **kwargs):
        if not isinstance(url, str) or not url.startswith("https://cli.cloud.tencent.com/"):
            raise AuthenticationError("InvalidAuthenticationEndpoint")
        kwargs.update(verify=True, allow_redirects=False, timeout=timeout)
        try:
            response = post(url, **kwargs)
            if response.status_code in {401, 403}:
                raise AuthenticationError(
                    "SsoLoginRequired" if module.__name__ == "tccli.sso" else "OAuthLoginRequired"
                )
            response.raise_for_status()
            if response.json().get("Error"):
                raise AuthenticationError(
                    "SsoLoginRequired" if module.__name__ == "tccli.sso" else "OAuthLoginRequired"
                )
        except AuthenticationError:
            raise
        except Exception:
            raise AuthenticationError("AuthRefreshFailed") from None
        return response

    # A private facade, not a global requests monkey patch.
    from types import SimpleNamespace

    module.requests = SimpleNamespace(post=verified_post)


def refresh_login(source, timeout, force):
    with cache_lock(source.path):
        source = load_source(source.profile)
        if source.base_kind not in {"oauth", "sso"}:
            raise AuthenticationError("CredentialSourceChanged")
        raw = source.raw
        if not force and raw["expiresAt"] > time.time() + 300:
            return source
        module = importlib.import_module("tccli." + source.base_kind)
        secure_native_http(module, timeout)
        saved = []

        def save(_path, value):
            if load_source(source.profile).stamp() != source.stamp():
                raise AuthenticationError("CredentialSourceChanged")
            # Preserve explicit role configuration when refreshing its source.
            for key in ("role-arn", "role-session-name"):
                if key in raw:
                    value[key] = raw[key]
            Material.parse(dict(value, provider=source.base_kind))
            if value["expiresAt"] <= time.time() + 30:
                raise AuthenticationError("AuthSessionExpired")
            atomic_cache(source.path, value)
            saved.append(True)

        # The native helpers construct their own supported cache schema.
        module.Utils.dump_json_msg = save
        if source.base_kind == "oauth":
            token = dict(raw["oauth"])
            if token["expiresAt"] <= time.time() + 300:
                token.update(
                    module.refresh_user_token(token["refreshToken"], token["openId"], token["site"])
                )
            material = module.get_temp_cred(token["accessToken"], token["site"])
            module.save_credential(token, material, source.profile)
        else:
            token = raw["sso"]
            remaining = int(token["expiresAt"] - time.time())
            if remaining < 300:
                raise AuthenticationError("SsoSessionExpired")
            saml = module.gen_saml_response(
                token["token"],
                "RoleSAML",
                token["uin"],
                "",
                token["roleConfigurationId"],
                token["site"],
            )
            credential = module.assume_role_with_saml(
                saml["SAMLResponse"],
                "qcs::cam::uin/%s:saml-provider/TencentReservedSSO-%s"
                % (token["uin"], token["zoneId"]),
                "qcs::cam::uin/%s:roleName/TencentCloudSSO-%s"
                % (token["uin"], token["roleConfigurationName"]),
                "ses-" + str(uuid.uuid4()),
                min(7200, remaining),
                token["site"],
            )
            module.save_credential(credential, token, source.profile)
        if not saved:
            raise AuthenticationError("AuthRefreshFailed")
        return load_source(source.profile)


def common_client(service, version, material, region, endpoint, timeout):
    from tencentcloud.common.common_client import CommonClient
    from tencentcloud.common.credential import Credential
    from tencentcloud.common.profile.client_profile import ClientProfile
    from tencentcloud.common.profile.http_profile import HttpProfile

    http = HttpProfile(endpoint=endpoint, reqTimeout=timeout, reqMethod="POST")
    http.scheme = "https"
    profile = ClientProfile(httpProfile=http, signMethod="TC3-HMAC-SHA256")
    profile.request_client = "TencentCloudCartography"
    client = CommonClient(
        service,
        version,
        Credential(material.secret_id, material.secret_key, material.token) if material else None,
        region,
        profile,
    )
    request = client.request.conn._session.request

    def fixed_request(*args, **kwargs):
        kwargs["allow_redirects"] = False
        return request(*args, **kwargs)

    client.request.conn._session.request = fixed_request
    return client


def issued_material(response, provider, account=None):
    credentials = response["Credentials"]
    result = Material.parse(
        dict(
            secretId=credentials["TmpSecretId"],
            secretKey=credentials["TmpSecretKey"],
            token=credentials["Token"],
            expiresAt=response["ExpiredTime"],
            provider=provider,
            target_account=account,
        )
    )
    if result.expires_at <= time.time() + 30 or not result.token:
        raise AuthenticationError("AuthSessionExpired")
    return result


def resolve(profile, timeout, force=False):
    # Import to verify that this interpreter really belongs to an installed CLI.
    import tccli  # noqa: F401

    source = load_source(profile)
    if source.base_kind in {"oauth", "sso"} and (
        force or source.raw["expiresAt"] <= time.time() + 300
    ):
        try:
            source = refresh_login(source, timeout, force)
        except AuthenticationError:
            raise
        except Exception:
            raise AuthenticationError("AuthRefreshFailed") from None
    if source.base_kind == "tke-oidc":
        raw = source.raw
        with open(raw["TKE_WEB_IDENTITY_TOKEN_FILE"], "r") as stream:
            token = stream.read(65537).strip()
        if not token or len(token) > 65536 or any(ord(c) < 32 for c in token):
            raise AuthenticationError("InvalidCredentialConfiguration")
        client = common_client(
            "sts", "2018-08-13", None, raw["TKE_REGION"], "sts.tencentcloudapi.com", timeout
        )
        response = client.call_json(
            "AssumeRoleWithWebIdentity",
            dict(
                ProviderId=raw["TKE_PROVIDER_ID"],
                WebIdentityToken=token,
                RoleArn=raw["TKE_ROLE_ARN"],
                RoleSessionName="cartography-" + str(uuid.uuid4()),
                DurationSeconds=7200,
            ),
            options={"SkipSign": True},
        )
        material = issued_material(
            response["Response"], "tke-oidc", ROLE.fullmatch(raw["TKE_ROLE_ARN"])[1]
        )
    elif source.base_kind == "cvm-role":
        from tencentcloud.common.credential import CVMRoleCredential

        cred = CVMRoleCredential()
        sid, key, token = cred.get_credential_info()
        expiry = getattr(cred, "_expired_ts", None)
        material = Material.parse(
            dict(
                secretId=sid,
                secretKey=key,
                token=token,
                expiresAt=expiry,
                provider=source.base_kind,
            )
        )
        if not material.expires_at or not material.token:
            raise AuthenticationError("AuthRefreshFailed")
    else:
        material = source.material()
    if material.expires_at is not None and material.expires_at <= time.time() + 30:
        raise AuthenticationError("AuthSessionExpired")
    if source.role_arn:
        client = common_client(
            "sts", "2018-08-13", material, "ap-guangzhou", "sts.tencentcloudapi.com", timeout
        )
        result = client.call_json(
            "AssumeRole",
            dict(
                RoleArn=source.role_arn, RoleSessionName=source.role_session, DurationSeconds=7200
            ),
        )
        material = issued_material(result["Response"], "role", ROLE.fullmatch(source.role_arn)[1])
    return material.wire()


def metadata(payload):
    from tencent_cloud_cartography.catalog import (
        ALLOWED_ACTIONS,
        API_SERVICE_NAMES,
        API_VERSIONS,
        SES_ENDPOINTS,
    )

    service, action, region, params = (
        payload.get(k) for k in ("service", "action", "region", "params")
    )
    if (service, action) not in ALLOWED_ACTIONS or service == "cos":
        raise CollectionError("BlockedAction")
    if not isinstance(params, dict) or any(
        not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", k) for k in params
    ):
        raise CollectionError("BlockedParameterScope")
    if (service, action) == ("postgres", "DescribeDBInstanceParameters"):
        from tencent_cloud_cartography.database_depth import PG_PARAMETERS

        if (
            set(params) != {"DBInstanceId", "ParamName"}
            or params.get("ParamName") not in PG_PARAMETERS
        ):
            raise CollectionError("BlockedParameterScope")
    if region and region != "global" and not re.fullmatch(r"[a-z]+-[a-z0-9-]+", region):
        raise CollectionError("InvalidRegion")
    material = Material.parse(payload["material"])
    if material.expires_at and material.expires_at <= time.time() + 5:
        raise AuthenticationError("AuthSessionExpired")
    native_service = API_SERVICE_NAMES.get(service, service)
    endpoint = native_service + ".tencentcloudapi.com"
    if service == "ses":
        if region not in SES_ENDPOINTS:
            raise CollectionError("UnsupportedSesRegion")
        endpoint = SES_ENDPOINTS[region]
    client = common_client(
        native_service,
        API_VERSIONS[service],
        material,
        region if region and region != "global" else "ap-guangzhou",
        endpoint,
        payload["timeout"],
    )
    result = client.call_json(action, params)
    if not isinstance(result, dict) or not isinstance(result.get("Response"), dict):
        raise CollectionError("InvalidResponse")
    return result["Response"]


def dispatch(payload):
    operation = payload.get("operation")
    if operation == "resolve":
        return resolve(payload["profile"], payload["timeout"], payload.get("force", False))
    if operation == "metadata":
        return metadata(payload)
    raise CollectionError("BlockedRuntimeOperation")


def main():
    output = sys.stdout
    logging.disable(logging.CRITICAL)
    try:
        payload = json.loads(sys.stdin.read())
        # No native SDK diagnostics or token-containing error strings escape IPC.
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            result = dispatch(payload)
        response = {"result": result}
    except Exception as exc:
        if isinstance(exc, CollectionError):
            code = exc.code
        elif hasattr(exc, "get_code"):
            code = exc.get_code()
        elif isinstance(exc, (ImportError, AttributeError)):
            code = "UnsupportedTccliRuntime"
        else:
            code = (
                "AuthenticationRuntimeFailed"
                if isinstance(locals().get("payload"), dict)
                and payload.get("operation") == "resolve"
                else "TccliRuntimeFailed"
            )
        if not isinstance(code, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9.]{0,100}", code):
            code = "TccliRuntimeFailed"
        response = {"error": code}
    output.write(json.dumps(response, allow_nan=False))


if __name__ == "__main__":
    main()
