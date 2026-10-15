import json
import os
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.auth_source import ENV_KEYS, TKE_KEYS, Material, load_source
from tencent_cloud_cartography.authentication import (
    ProfileResolver,
    VerifiedSession,
    stable_identity,
    validate_report,
)
from tencent_cloud_cartography.collect import CollectorRunner, collect
from tencent_cloud_cartography.errors import CollectionError
from tencent_cloud_cartography.storage import validate
from tencent_cloud_cartography.tccli_runtime import TccliRuntime, runtime_python
from tencent_cloud_cartography.transport import TccliTransport

NOW = 2_000_000_000


def user(account="100", principal="101"):
    return dict(
        AccountId=account,
        PrincipalId=principal,
        Arn=f"qcs::cam:{account}:uin/{principal}",
        Type="CAMUser",
        UserId=principal,
    )


def role(account="100", role_id="1234", session="one"):
    return dict(
        AccountId=account,
        PrincipalId="101",
        Arn=f"qcs::sts:{account}:assumed-role/{role_id}",
        Type="CAMRole",
        UserId=f"{role_id}:{session}",
    )


@pytest.fixture
def profiles(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    for key in (*ENV_KEYS, *TKE_KEYS, "TENCENTCLOUD_ROLE_ARN", "TENCENTCLOUD_ROLE_SESSION_NAME"):
        monkeypatch.delenv(key, raising=False)
    directory = tmp_path / ".tccli"
    directory.mkdir()

    def write(name="default", **changes):
        value = {
            "secretId": "PRIVATE_ID",
            "secretKey": "PRIVATE_KEY",
            "token": "PRIVATE_TOKEN",
            **changes,
        }
        (directory / (name + ".credential")).write_text(json.dumps(value))
        return value

    return write


@pytest.mark.parametrize("name", ["default", "prod", "frankfurt-team"])
def test_explicit_profile_precedes_all_environment_sources(profiles, monkeypatch, name):
    profiles(name)
    for key in (*ENV_KEYS, *TKE_KEYS, "TENCENTCLOUD_ROLE_ARN", "TENCENTCLOUD_ROLE_SESSION_NAME"):
        monkeypatch.setenv(key, "DIFFERENT_ACCOUNT")
    source = load_source(name)
    assert source.provider == "profile" and source.material().secret_id == "PRIVATE_ID"
    assert "PRIVATE" not in repr(source) + repr(source.material())


def test_no_named_profile_fallback_or_source_merging(profiles, monkeypatch):
    monkeypatch.setenv("TENCENTCLOUD_SECRET_ID", "environment-id")
    with pytest.raises(CollectionError) as failure:
        load_source("default")
    assert failure.value.code == "InvalidCredentialConfiguration"
    monkeypatch.setenv("TENCENTCLOUD_SECRET_KEY", "environment-key")
    assert load_source("default").provider == "environment"
    with pytest.raises(CollectionError) as failure:
        load_source("missing")
    assert failure.value.code == "MissingProfile"
    profiles(secretKey=None)
    with pytest.raises(CollectionError):
        load_source("default")


@pytest.mark.parametrize("value", ["../other", "", ".", "..", "team/role", "name\n"])
def test_profile_validation_before_path_read(value):
    with pytest.raises(CollectionError):
        load_source(value, home="/does-not-exist", environ={})


@pytest.mark.parametrize(
    "changes",
    [
        {"role-arn": "qcs::cam::uin/100:roleName/Reader"},
        {"role-session-name": "scan"},
        {"role-arn": "https://other.invalid", "role-session-name": "scan"},
        {"type": "unknown"},
        {"expiresAt": float("inf")},
    ],
)
def test_invalid_role_or_expiry_fails_closed(profiles, changes):
    profiles(**changes)
    with pytest.raises(CollectionError):
        load_source("default")


def test_explicit_cvm_and_complete_tke_configuration(profiles, monkeypatch):
    profiles("instance", type="cvm-role")
    assert load_source("instance").provider == "cvm-role"
    monkeypatch.setenv("TKE_REGION", "eu-frankfurt")
    with pytest.raises(CollectionError):
        load_source("default")
    for key, value in zip(
        TKE_KEYS,
        ("eu-frankfurt", "provider-one", "/fixture/token", "qcs::cam::uin/100:roleName/Reader"),
    ):
        monkeypatch.setenv(key, value)
    assert load_source("default").provider == "tke-oidc"


def test_sso_configuration_without_login_has_correct_remediation(profiles):
    profiles(
        type="sso",
        secretId=None,
        secretKey=None,
        token=None,
        sso={"authUrl": "https://example.test"},
    )
    session = VerifiedSession("default", Runtime())
    with pytest.raises(CollectionError):
        session.material()
    assert session.report()["provider"] == "sso"
    assert session.report()["remediation"] == "tccli sso login --profile default"


def test_sso_target_account_accepts_native_numeric_uin(profiles):
    profiles(
        type="sso",
        expiresAt=NOW,
        sso=dict(
            token="PRIVATE_SSO",
            uin=100,
            roleConfigurationId="c1",
            roleConfigurationName="Reader",
            zoneId="z1",
            site="intl",
            authUrl="https://example.test",
            expiresAt=NOW,
        ),
    )
    assert load_source("default").material().target_account == "100"


class Runtime:
    def __init__(self, identity=None):
        self.identity = identity or user()
        self.calls = []
        self.next = Material(
            "ROTATED_ID", "ROTATED_KEY", "ROTATED_TOKEN", NOW + 3600, "role", "100"
        )

    def invoke(self, operation, **payload):
        self.calls.append((operation, payload))
        if operation == "resolve":
            return self.next.wire()
        assert payload["service"] == "sts" and payload["action"] == "GetCallerIdentity"
        if isinstance(self.identity, Exception):
            raise self.identity
        return deepcopy(self.identity)


def test_shared_material_and_role_refresh_checked_before_use(profiles):
    profiles(**{"role-arn": "qcs::cam::uin/100:roleName/Reader", "role-session-name": "scan"})
    runtime = Runtime(role())
    resolver = ProfileResolver("default", runtime, clock=lambda: NOW)
    session = VerifiedSession("default", runtime, resolver)
    first = session.material()
    assert session.material() is first and len(runtime.calls) == 2
    runtime.next = Material("SECOND_ID", "SECOND_KEY", "SECOND_TOKEN", NOW + 7200, "role", "100")
    runtime.identity = role(session="refreshed")
    second = session.material(force=True)
    assert second.secret_id == "SECOND_ID"
    assert [operation for operation, _ in runtime.calls] == [
        "resolve",
        "metadata",
        "resolve",
        "metadata",
    ]
    assert session.report()["generations"] == 2 and session.report()["refreshes"] == 1
    validate_report(session.report())
    assert "SECOND" not in json.dumps(session.report())


@pytest.mark.parametrize(
    "identity",
    [user("200"), user(principal="202"), role(), CollectionError("UnauthorizedOperation")],
)
def test_changed_or_unverified_generation_is_sticky_even_if_profile_reverts(profiles, identity):
    profiles()
    runtime = Runtime()
    session = VerifiedSession("default", runtime)
    session.material()
    profiles(secretId="DIFFERENT_ID")
    runtime.identity = identity
    with pytest.raises(CollectionError):
        session.material()
    runtime.identity = user()
    profiles()
    with pytest.raises(CollectionError):
        session.material()
    assert session.generations == 1 and session.report()["status"] == "failed"


@pytest.mark.parametrize(
    "change",
    [
        {"AccountId": "200"},
        {"PrincipalId": "202"},
        {"Arn": "qcs::sts:100:assumed-role/4321", "UserId": "4321:new"},
        {"Type": "CAMUser"},
    ],
)
def test_role_refresh_never_ignores_account_source_principal_or_role(change):
    assert stable_identity(role()) != stable_identity(dict(role(), **change))
    assert stable_identity(role()) == stable_identity(role(session="new"))


def test_federated_user_identity_is_not_weakened_to_ignore_session():
    original = dict(user(), UserId="101:person-one", Arn="qcs::sts:100:federated-user/101")
    assert stable_identity(original) != stable_identity(dict(original, UserId="101:person-two"))


def test_static_expiry_after_rejection_requires_login_not_repeated_attempts(profiles):
    profiles()
    session = VerifiedSession("default", Runtime())
    calls = []

    def expired(material):
        calls.append(material.secret_id)
        raise CollectionError("AuthFailure.TokenExpired")

    with pytest.raises(CollectionError) as failure:
        session.execute(expired)
    assert failure.value.code == "AuthSessionExpired"
    with pytest.raises(CollectionError):
        session.execute(expired)
    assert calls == ["PRIVATE_ID"]
    assert session.report()["status"] == "login-required"


def test_one_refresh_replay_no_refresh_for_permission_denial(profiles):
    profiles(**{"role-arn": "qcs::cam::uin/100:roleName/Reader", "role-session-name": "scan"})
    runtime = Runtime(role())
    session = VerifiedSession(
        "default", runtime, ProfileResolver("default", runtime, clock=lambda: NOW)
    )
    calls = []

    def operation(material):
        calls.append(material.secret_id)
        if len(calls) == 1:
            runtime.next = Material("FRESH", "FRESH_KEY", "FRESH_TOKEN", NOW + 7200, "role", "100")
            raise CollectionError("AuthFailure.TokenFailure")
        return {"done": True}

    assert session.execute(operation) == {"done": True}
    assert calls == ["ROTATED_ID", "FRESH"]
    before = len(runtime.calls)

    def denied(material):
        raise CollectionError("UnauthorizedOperation")

    with pytest.raises(CollectionError):
        session.execute(denied)
    assert len(runtime.calls) == before


def test_refresh_due_during_long_scan(profiles):
    value = profiles(
        type="oauth",
        expiresAt=NOW + 3600,
        oauth=dict(
            accessToken="ACCESS",
            refreshToken="REFRESH",
            openId="OPEN",
            expiresAt=NOW + 7200,
            site="intl",
        ),
    )
    clock = [NOW]
    runtime = Runtime()
    resolver = ProfileResolver("default", runtime, clock=lambda: clock[0])
    session = VerifiedSession("default", runtime, resolver)
    assert session.material().secret_id == value["secretId"]
    clock[0] += 3400
    runtime.next = Material("FRESH", "KEY", "TOKEN", NOW + 7200, "oauth")
    assert session.material().secret_id == "FRESH"
    assert session.generations == 2 and resolver.refreshes == 1


def test_all_transports_receive_same_verified_generation(monkeypatch, profiles):
    from tencent_cloud_cartography import cos_transport, international, tic_transport

    profiles()
    runtime = Runtime()
    session = VerifiedSession("default", runtime)
    transport = TccliTransport(session=session)
    seen = []

    def adapter(*args, material=None):
        seen.append(material)
        return {"Buckets": {"Bucket": [{"Name": "assets-12345", "Location": "eu-frankfurt"}]}}

    for module in (cos_transport, international, tic_transport):
        monkeypatch.setattr(module, "call", adapter)
    transport.buckets()
    transport.call("cos", "get_bucket_logging", "eu-frankfurt", Bucket="assets-12345")
    transport.call("tic", "DescribeStacks", "eu-frankfurt", Offset=0, Limit=100)
    transport.call("cvm", "DescribeReservedInstances", "eu-frankfurt", Offset=0, Limit=100)
    assert len(seen) == 4 and all(material is seen[0] for material in seen)
    assert len(runtime.calls) == 1


def test_bucket_listing_continuation_and_changed_owner_fail_closed(monkeypatch, frozen_session):
    transport = TccliTransport(session=frozen_session)
    requests = []

    def listing(service, action, region=None, **params):
        requests.append(params)
        if not params["Marker"]:
            return dict(
                Owner=dict(ID="one"),
                Buckets=dict(Bucket=[dict(Name="first-12345", Location="eu-frankfurt")]),
                NextMarker="next",
            )
        return dict(
            Owner=dict(ID="one"),
            Buckets=dict(Bucket=dict(Name="second-12345", Location="ap-singapore")),
        )

    monkeypatch.setattr(transport, "call", listing)
    assert transport.buckets() == [
        dict(name="first-12345", region="eu-frankfurt"),
        dict(name="second-12345", region="ap-singapore"),
    ]
    assert requests == [dict(Marker="", MaxKeys=2000), dict(Marker="next", MaxKeys=2000)]
    original = listing

    def changed(service, action, region=None, **params):
        response = original(service, action, region, **params)
        if params["Marker"]:
            response["Owner"]["ID"] = "different"
        return response

    monkeypatch.setattr(transport, "call", changed)
    with pytest.raises(CollectionError) as failure:
        transport.buckets()
    assert failure.value.code == "InventoryChanged"


@pytest.mark.parametrize(
    "response",
    [
        {"Buckets": {}, "NextMarker": "stalled"},
        {"Buckets": {}, "IsTruncated": True},
        {
            "Buckets": {"Bucket": [{"Name": "one-12345", "Location": "eu-frankfurt"}]},
            "NextMarker": "stalled",
        },
        {
            "Buckets": {
                "Bucket": [
                    {"Name": "one-12345", "Location": "eu-frankfurt"},
                    {"Name": "one-12345", "Location": "eu-frankfurt"},
                ]
            }
        },
    ],
)
def test_bucket_pagination_never_silently_publishes_truncation(
    monkeypatch, frozen_session, response
):
    transport = TccliTransport(session=frozen_session)
    monkeypatch.setattr(transport, "call", lambda *args, **kwargs: response)
    with pytest.raises(CollectionError):
        transport.buckets()


def test_authentication_report_rejects_credential_fields(profiles):
    profiles()
    session = VerifiedSession("default", Runtime())
    session.material()
    report = session.report()
    report["secretKey"] = "PRIVATE_KEY"
    with pytest.raises(ValueError):
        validate_report(report)


def test_auth_failure_discards_only_failed_account_and_reports_remediation(monkeypatch, profiles):
    profiles("healthy")
    profiles(
        "expired",
        type="sso",
        expiresAt=1,
        sso=dict(
            token="PRIVATE_SSO",
            uin="200",
            roleConfigurationId="c1",
            roleConfigurationName="reader",
            zoneId="z1",
            site="intl",
            authUrl="https://example.test",
            expiresAt=1,
        ),
    )
    sessions = {}
    for name in ("healthy", "expired"):
        runtime = Runtime()
        if name == "expired":

            def fail(*args, **kwargs):
                raise CollectionError("SsoSessionExpired")

            runtime.invoke = fail
        sessions[name] = VerifiedSession(name, runtime)

    def transport(name):
        t = TccliTransport(name, session=sessions[name])
        t.runtime = sessions[name].runtime
        return t

    def stage(runner, services):
        runner.graph.add(runner.account, "eu-frankfurt", "cvm.instance", "ins-one")

    monkeypatch.setattr(CollectorRunner, "run", stage)
    progress = []
    snapshot = collect(
        ["expired", "healthy"],
        ["eu-frankfurt"],
        {"cvm"},
        transport_factory=transport,
        progress=progress.append,
    )
    assert [a["id"] for a in snapshot["accounts"]] == ["100"]
    auth = snapshot["collection"]["profiles"][0]["authentication"]
    assert (
        auth["status"] == "login-required"
        and auth["remediation"] == "tccli sso login --profile expired"
    )
    assert "PRIVATE" not in json.dumps(snapshot) + "".join(progress)
    validate(snapshot)


def test_runtime_ipc_never_places_credentials_in_arguments_or_leaks_stderr(monkeypatch):
    runtime = TccliRuntime(timeout=12)
    runtime._resolved = "/fixture/python"

    def execute(args, **options):
        assert args[:2] == ["/fixture/python", "-I"]
        assert "PRIVATE" not in json.dumps(args)
        assert "PRIVATE" in options["input"] and options["timeout"] == 42
        return SimpleNamespace(returncode=1, stdout="PRIVATE_RAW", stderr="PRIVATE_KEY")

    monkeypatch.setattr(subprocess, "run", execute)
    with pytest.raises(CollectionError) as failure:
        runtime.invoke("metadata", material=Material("PRIVATE_ID", "PRIVATE_KEY").wire())
    assert failure.value.code == "InvalidTccliRuntimeResponse" and "PRIVATE" not in str(
        failure.value
    )


def test_tccli_python_detection_and_explicit_wrapper_override(tmp_path, monkeypatch):
    python = tmp_path / "python3.13"
    python.touch()
    python.chmod(0o700)
    cli = tmp_path / "tccli"
    cli.write_text("#!" + str(python) + "\n")
    cli.chmod(0o700)
    assert runtime_python(str(cli)) == str(python)
    cli.write_text("#!/bin/sh\n")
    with pytest.raises(CollectionError):
        runtime_python(str(cli))
    assert runtime_python(str(cli), str(python)) == str(python)


def test_native_tccli_runtime_providers_offline(tmp_path):
    override = os.environ.get("TCCLI_TEST_PYTHON")
    try:
        python = runtime_python(override=override)
    except CollectionError:
        pytest.skip("Install tccli or set TCCLI_TEST_PYTHON for native runtime validation")
    script = Path(__file__).resolve().parents[1] / "support" / "native_auth_probe.py"
    environment = {
        k: v
        for k, v in os.environ.items()
        if k
        not in (*ENV_KEYS, *TKE_KEYS, "TENCENTCLOUD_ROLE_ARN", "TENCENTCLOUD_ROLE_SESSION_NAME")
    }
    environment["HOME"] = str(tmp_path)
    result = subprocess.run(
        [python, "-I", str(script), str(Path(__file__).resolve().parents[2])],
        capture_output=True,
        text=True,
        timeout=60,
        env=environment,
    )
    # Fixture material is fake. Still suppress failed subprocess diagnostics in
    # assertion output to maintain the same invariant as the application.
    assert result.returncode == 0, "Native TCCLI auth fixture validation failed"
    assert json.loads(result.stdout) == {"native_auth": "passed"}


def test_installed_bridge_does_not_expose_application_site_packages(tmp_path):
    try:
        python = runtime_python(override=os.environ.get("TCCLI_TEST_PYTHON"))
    except CollectionError:
        pytest.skip("Native TCCLI runtime unavailable")
    import tencent_cloud_cartography

    application_site = tmp_path / "application-site-packages"
    package = application_site / "tencent_cloud_cartography"
    shutil.copytree(
        Path(tencent_cloud_cartography.__file__).parent,
        package,
        ignore=shutil.ignore_patterns("_web", "__pycache__"),
    )
    foreign = application_site / "tccli"
    foreign.mkdir()
    (foreign / "__init__.py").write_text(
        'raise RuntimeError("APPLICATION_DEPENDENCY_MUST_NOT_SHADOW_NATIVE_TCCLI")\n'
    )
    home = tmp_path / "home"
    cache = home / ".tccli"
    cache.mkdir(parents=True)
    (cache / "isolated.credential").write_text(
        json.dumps(dict(secretId="FIXTURE", secretKey="FIXTURE"))
    )
    environment = dict(os.environ, HOME=str(home))
    result = subprocess.run(
        [python, "-I", str(package / "_tccli_bridge.py")],
        input=json.dumps(dict(operation="resolve", profile="isolated", timeout=9)),
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0
    assert json.loads(result.stdout)["result"]["secretId"] == "FIXTURE"
