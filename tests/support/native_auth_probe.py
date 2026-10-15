"""Run real TCCLI providers/signing offline in its own interpreter, without pytest."""

import importlib
import json
import os
import socket
import stat
import sys
import time
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, sys.argv[1])

import requests  # noqa: E402
from tencentcloud.common import credential  # noqa: E402

from tencent_cloud_cartography import _tccli_bridge as bridge  # noqa: E402
from tencent_cloud_cartography.auth_source import Material  # noqa: E402
from tencent_cloud_cartography.catalog import API_SERVICE_NAMES, API_VERSIONS  # noqa: E402
from tencent_cloud_cartography.errors import CollectionError  # noqa: E402

now = int(time.time())
directory = Path.home() / ".tccli"
directory.mkdir()
calls = []


def no_network(*args, **kwargs):
    raise AssertionError("Native fixture must not use the network")


socket.create_connection = no_network
socket.socket.connect = no_network


def write(name, value):
    (directory / (name + ".credential")).write_text(json.dumps(value))


def temporary():
    return dict(
        Credentials=dict(TmpSecretId="ISSUED_ID", TmpSecretKey="ISSUED_KEY", Token="ISSUED_TOKEN"),
        ExpiredTime=now + 3600,
    )


def response(value):
    reply = requests.Response()
    reply.status_code = 200
    reply._content = json.dumps(value).encode()
    reply.headers["Content-Type"] = "application/json"
    return reply


def post(url, **kwargs):
    assert url.startswith("https://cli.cloud.tencent.com/")
    assert kwargs["verify"] is True and kwargs["allow_redirects"] is False
    assert kwargs["timeout"] == 9
    calls.append((url, kwargs["json"]))
    if url.endswith("/refresh_user_token"):
        return response(dict(AccessToken="FRESH_ACCESS", ExpiresAt=now + 7200))
    if url.endswith("/get_temp_cred"):
        return response(
            dict(
                secretId="unused",
                SecretId="FRESH_ID",
                SecretKey="FRESH_KEY",
                Token="FRESH_TOKEN",
                ExpiresAt=now + 3600,
            )
        )
    if url.endswith("/gen_saml_response"):
        return response(dict(SAMLResponse="PRIVATE_ASSERTION"))
    if url.endswith("/assume_role_with_saml"):
        return response(temporary())
    raise AssertionError("Unexpected authentication URL")


requests.post = post


def signed_request(self, **kwargs):
    assert kwargs["method"] == "POST" and kwargs["url"].startswith("https://")
    assert kwargs["verify"] and kwargs["timeout"] == 9
    assert kwargs["allow_redirects"] is False
    headers = kwargs["headers"]
    action = headers["X-TC-Action"]
    body = json.loads(kwargs["data"])
    calls.append((action, body))
    if action == "AssumeRoleWithWebIdentity":
        assert (
            body["WebIdentityToken"] == "PRIVATE_OIDC_TOKEN"
            and body["ProviderId"] == "provider-one"
        )
        assert body["RoleArn"] == "qcs::cam::uin/100:roleName/Reader"
        return response({"Response": temporary()})
    if action == "AssumeRole":
        assert headers["X-TC-Token"] in {"SOURCE_TOKEN", "FRESH_TOKEN"}
        assert "Credential=" in headers["Authorization"]
        assert body["RoleArn"] == "qcs::cam::uin/100:roleName/Reader"
        assert body["RoleSessionName"] == "cartography-scan" and body["DurationSeconds"] == 7200
        return response({"Response": temporary()})
    if action == "DescribeAutoScalingGroups":
        assert kwargs["url"] in {
            "https://as.tencentcloudapi.com",
            "https://as.tencentcloudapi.com/",
        }, "AS endpoint mismatch"
        assert "/as/tc3_request" in headers["Authorization"], "AS signing name mismatch"
        assert headers["X-TC-Version"] == "2018-04-19", "AS version mismatch"
        return response({"Response": {"AutoScalingGroupSet": [], "TotalCount": 0}})
    assert action == "DescribeVpcs" and headers["X-TC-Token"] == "FROZEN_TOKEN"
    assert "Credential=FROZEN_ID/" in headers["Authorization"]
    assert headers["X-TC-Version"] == "2017-03-12" and headers["X-TC-Region"] == "eu-frankfurt"
    return response({"Response": {"VpcSet": [], "TotalCount": 0, "RequestId": "offline"}})


requests.Session.request = signed_request

oauth = dict(
    type="oauth",
    secretId="CACHED_ID",
    secretKey="CACHED_KEY",
    token="CACHED_TOKEN",
    expiresAt=now + 1,
    oauth=dict(
        accessToken="OLD_ACCESS",
        refreshToken="PRIVATE_REFRESH",
        openId="OPEN",
        site="intl",
        expiresAt=now + 1,
    ),
)
write("browser", oauth)
material = bridge.resolve("browser", 9)
assert material["secretId"] == "FRESH_ID" and material["provider"] == "oauth"
saved = json.loads((directory / "browser.credential").read_text())
assert saved["oauth"]["accessToken"] == "FRESH_ACCESS"
assert stat.S_IMODE((directory / "browser.credential").stat().st_mode) == 0o600
assert len(calls) == 2
# Forced replay renews credentials even when the on-disk expiry is still future.
bridge.resolve("browser", 9, force=True)
assert len(calls) == 3

write(
    "sso",
    dict(
        type="sso",
        secretId="CACHED",
        secretKey="CACHED",
        token="CACHED",
        expiresAt=now + 1,
        sso=dict(
            token="SSO_LOGIN",
            uin=100,
            roleConfigurationId="c-1",
            roleConfigurationName="Reader",
            zoneId="z-1",
            site="intl",
            authUrl="https://example.test",
            expiresAt=now + 7200,
        ),
    ),
)
material = bridge.resolve("sso", 9)
assert material["secretId"] == "ISSUED_ID" and material["provider"] == "sso"
assert json.loads((directory / "sso.credential").read_text())["type"] == "sso"
assert calls[-1][1]["SAMLAssertion"] == "PRIVATE_ASSERTION"
assert calls[-1][1]["RoleArn"] == "qcs::cam::uin/100:roleName/TencentCloudSSO-Reader"
saved = json.loads((directory / "sso.credential").read_text())
saved["sso"]["expiresAt"] = now - 1
saved["expiresAt"] = now - 1
write("expired", saved)
before = len(calls)
try:
    bridge.resolve("expired", 9)
    raise AssertionError("Expired SSO accepted")
except CollectionError as exc:
    assert exc.code == "SsoSessionExpired"
assert len(calls) == before

configured = {
    "role-arn": "qcs::cam::uin/100:roleName/Reader",
    "role-session-name": "cartography-scan",
}
write(
    "role", dict(secretId="SOURCE_ID", secretKey="SOURCE_KEY", token="SOURCE_TOKEN", **configured)
)
material = bridge.resolve("role", 9)
assert material["provider"] == "role" and material["target_account"] == "100"
write("browser-role", dict(oauth, **configured))
assert bridge.resolve("browser-role", 9)["provider"] == "role"
assert (
    json.loads((directory / "browser-role.credential").read_text())["role-arn"]
    == configured["role-arn"]
)

# Frozen metadata must ignore ambient TKE, source credentials and profile endpoints.
for key in (
    "TENCENTCLOUD_SECRET_ID",
    "TENCENTCLOUD_SECRET_KEY",
    "TKE_ROLE_ARN",
    "TKE_REGION",
    "TKE_PROVIDER_ID",
    "TKE_WEB_IDENTITY_TOKEN_FILE",
):
    os.environ[key] = "OTHER_ACCOUNT"
result = bridge.metadata(
    dict(
        service="vpc",
        action="DescribeVpcs",
        region="eu-frankfurt",
        params=dict(Offset=0, Limit=100),
        material=Material("FROZEN_ID", "FROZEN_KEY", "FROZEN_TOKEN").wire(),
        timeout=9,
    )
)
assert result["RequestId"] == "offline"
bridge.metadata(
    dict(
        service="autoscaling",
        action="DescribeAutoScalingGroups",
        region="eu-frankfurt",
        params=dict(Offset=0, Limit=100),
        material=Material("FROZEN_ID", "FROZEN_KEY", "FROZEN_TOKEN").wire(),
        timeout=9,
    )
)
# Reconcile every generic service's signing name/endpoint against the installed
# official client, rather than assuming all CLI module names are API names.
for service, version in API_VERSIONS.items():
    if service == "tic":  # Isolated legacy SDK adapter has a separate contract.
        continue
    module = importlib.import_module(
        f"tencentcloud.{service}.v{version.replace('-', '')}.{service}_client"
    )
    clients = [
        value
        for value in vars(module).values()
        if isinstance(value, type)
        and value.__module__ == module.__name__
        and hasattr(value, "_service")
    ]
    assert len(clients) == 1
    native = API_SERVICE_NAMES.get(service, service)
    assert clients[0]._service == native and clients[0]._endpoint == native + ".tencentcloudapi.com"
before = len(calls)
for service, action, params in (
    ("cvm", "RunInstances", {}),
    (
        "postgres",
        "DescribeDBInstanceParameters",
        {"DBInstanceId": "postgres-one", "ParamName": "password"},
    ),
):
    try:
        bridge.metadata(
            dict(service=service, action=action, params=params, region="eu-frankfurt", timeout=9)
        )
        raise AssertionError("Blocked metadata operation executed")
    except CollectionError:
        pass
assert len(calls) == before

# The installed native CVM provider is explicit; its fixed IMDS endpoints return
# only the caller's session, never inventory payloads.
write("instance", dict(type="cvm-role"))


def imds(url):
    assert url.startswith(
        "http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/"
    )
    if url.endswith("credentials/"):
        return SimpleNamespace(read=lambda: b"Reader")
    return SimpleNamespace(
        read=lambda: json.dumps(
            dict(
                Code="Success",
                TmpSecretId="INSTANCE_ID",
                TmpSecretKey="INSTANCE_KEY",
                Token="INSTANCE_TOKEN",
                ExpiredTime=now + 3600,
            )
        ).encode()
    )


credential.urlopen = imds
assert bridge.resolve("instance", 9)["provider"] == "cvm-role"
# The explicit TKE file uses STS's supported web-identity exchange. No ambient
# instance role or source static credential is consulted.
for key in ("TENCENTCLOUD_SECRET_ID", "TENCENTCLOUD_SECRET_KEY"):
    os.environ.pop(key, None)
token_path = Path.home() / "oidc-token"
token_path.write_text("PRIVATE_OIDC_TOKEN\n")
os.environ.update(
    TKE_REGION="eu-frankfurt",
    TKE_PROVIDER_ID="provider-one",
    TKE_WEB_IDENTITY_TOKEN_FILE=str(token_path),
    TKE_ROLE_ARN="qcs::cam::uin/100:roleName/Reader",
)
assert bridge.resolve("default", 9)["provider"] == "tke-oidc"
assert not list(directory.glob(".cartography-auth-*"))
assert not (directory / "log").exists()
print(json.dumps({"native_auth": "passed"}))
