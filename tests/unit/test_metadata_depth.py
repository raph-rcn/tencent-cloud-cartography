import base64
import copy
import importlib
import json
from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.cam import add_document, parse_document
from tencent_cloud_cartography.catalog import ALLOWED_ACTIONS, API_VERSIONS
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.cos_notifications import link_destinations, notification
from tencent_cloud_cartography.database_depth import (
    ACTIONS,
    PG_PARAMETERS,
    apply,
    collect,
    postgres_groups,
    postgres_parameters,
)
from tencent_cloud_cartography.federation_metadata import (
    configuration,
    link_providers,
    managed_policy,
    provider_details,
    provisioning,
    saml,
)
from tencent_cloud_cartography.gateway import api, link_backends
from tencent_cloud_cartography.gateway_depth import mappings
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.identity_center import identifier
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.transport import CollectionError, TccliTransport

REGION = "eu-frankfurt"
XML = '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="idp"><IDPSSODescriptor><SingleSignOnService Binding="POST" Location="https://idp.test/login?token=OMIT#OMIT"/></IDPSSODescriptor></EntityDescriptor>'


def node(g, kind, rid, region=REGION, account="100", **props):
    nid = g.add(account, region, kind, rid)
    g.nodes[nid]["properties"].update(props)
    return g.nodes[nid]


def runner(g, call):
    return CollectorRunner(g, SimpleNamespace(call=call), "100", [REGION], lambda _: None)


def notification_data():
    return dict(
        CloudFunctionConfiguration=dict(
            Id="function",
            CloudFunction=f"qcs:0:scf:{REGION}:appid/12345:default.handler.prod",
            Event="cos:ObjectCreated:*",
            Filter=dict(Key=dict(FilterRule=dict(Name="Prefix", Value="uploads/"))),
        ),
        CkafkaConfiguration=dict(
            Id="kafka",
            Ckafka=dict(InstanceId="ckafka-one", TopicName="events"),
            Event=["cos:ObjectCreated:Put", "cos:ObjectRemove:Delete"],
            RoleArn="qcs::cam::uin/100:roleName/COSNotifyRole",
        ),
    )


def test_notifications_link_only_uniquely_collected_scoped_targets_and_role():
    g = Graph()
    b = node(g, "cos.bucket", "assets-12345")
    f = node(g, "scf.function", "lam-one", Namespace="default")
    f["name"] = "handler"
    topic = node(
        g, "ckafka.topic", "ckafka-one/topic-one", InstanceId="ckafka-one", TopicName="events"
    )
    role = node(g, "cam.role", "7", region="global", RoleName="COSNotifyRole")
    node(
        g,
        "ckafka.topic",
        "wrong-region",
        region="ap-guangzhou",
        InstanceId="ckafka-one",
        TopicName="events",
    )
    notification(g, b, notification_data(), "fixture")
    link_destinations(g)
    edges = [
        e for e in g.edges.values() if e["relationship"] == "CONFIGURED_NOTIFICATION_DESTINATION"
    ]
    assert {e["target"] for e in edges} == {f["id"], topic["id"]}
    assert any(
        e["target"] == role["id"] and e["relationship"] == "CONFIGURED_DELIVERY_ROLE"
        for e in g.edges.values()
    )
    assert b["properties"]["notification_rule_count"] == 2
    assert all(icon_for(n["kind"]) != "unmapped.svg" for n in g.nodes.values())


@pytest.mark.parametrize(
    "change", ["foreign-appid", "duplicate-function", "wrong-account", "wrong-region"]
)
def test_notification_no_guessed_destination(change):
    g = Graph()
    b = node(g, "cos.bucket", "assets-12345")
    f = node(
        g,
        "scf.function",
        "lam-one",
        Namespace="default",
        account="200" if change == "wrong-account" else "100",
        region="ap-guangzhou" if change == "wrong-region" else REGION,
    )
    f["name"] = "handler"
    d = notification_data()
    d.pop("CkafkaConfiguration")
    if change == "foreign-appid":
        d["CloudFunctionConfiguration"]["CloudFunction"] = d["CloudFunctionConfiguration"][
            "CloudFunction"
        ].replace("12345", "999")
    if change == "duplicate-function":
        node(g, "scf.function", "lam-two", Namespace="default")["name"] = "handler"
    notification(g, b, d, "fixture")
    link_destinations(g)
    assert not any(
        e["relationship"] == "CONFIGURED_NOTIFICATION_DESTINATION" for e in g.edges.values()
    )


@pytest.mark.parametrize("change", ["duplicate", "filter", "event", "unknown", "target"])
def test_notification_response_validates_before_mutation(change):
    g = Graph()
    b = node(g, "cos.bucket", "assets-12345")
    d = notification_data()
    if change == "duplicate":
        d["CkafkaConfiguration"]["Id"] = "function"
    elif change == "filter":
        d["CloudFunctionConfiguration"]["Filter"] = {
            "Key": {"FilterRule": {"Name": "Unknown", "Value": "x"}}
        }
    elif change == "event":
        d["CkafkaConfiguration"]["Event"] = ["not-an-event"]
    elif change == "unknown":
        d["QueueConfiguration"] = {}
    else:
        d["CkafkaConfiguration"]["Ckafka"]["InstanceId"] = "https://outside.test"
    before = g.dump()
    with pytest.raises(CollectionError):
        notification(g, b, d, "fixture")
    assert g.dump() == before


def proxy():
    return dict(
        Count=1,
        ProxyInfos=[
            dict(
                ProxyGroupId="proxy-one",
                Status="1",
                ProxyVersion="2",
                ProxyNode=[dict(ProxyId="node-one", Region=REGION, Cpu=2, Mem=1024)],
                ProxyAddress=[
                    dict(
                        ProxyAddressId="addr-one",
                        UniqVpcId="vpc-one",
                        UniqSubnetId="subnet-one",
                        Vip="10.0.0.2",
                        VPort=3306,
                        ReadOnly=True,
                        Password="OMIT",
                    )
                ],
            )
        ],
    )


def test_mysql_proxy_backup_replica_depth_excludes_unselected_payloads():
    g = Graph()
    db = node(g, "cdb.instance", "cdb-one")
    apply(g, db, "cdb", "DescribeCdbProxyInfo", proxy())
    apply(
        g,
        db,
        "cdb",
        "DescribeBackupConfig",
        dict(
            BackupExpireDays=7,
            BackupTimeWindow=dict(Monday="02:00-06:00", Days=[1, 4], Password="OMIT"),
        ),
    )
    apply(
        g,
        db,
        "cdb",
        "DescribeRoGroups",
        dict(
            RoGroups=[
                dict(
                    RoGroupId="ro-one",
                    RoGroupRegion=REGION,
                    RoInstances=[
                        dict(
                            InstanceId="cdbro-one",
                            MasterInstanceId="cdb-one",
                            Region="ap-guangzhou",
                            Weight=20,
                        )
                    ],
                )
            ]
        ),
    )
    assert "OMIT" not in g.dump()
    assert {"cdb.proxygroup", "cdb.proxynode", "cdb.proxyaddress", "cdb.rogroup"} <= {
        n["kind"] for n in g.nodes.values()
    }
    assert any(
        e["relationship"] == "HAS_READ_ONLY_MEMBER"
        and g.nodes[e["target"]]["region"] == "ap-guangzhou"
        for e in g.edges.values()
    )
    assert (
        json.loads(db["properties"]["DescribeBackupConfig"])["BackupTimeWindow"]["Monday"]
        == "02:00-06:00"
    )


@pytest.mark.parametrize("change", ["count", "duplicate", "region", "port", "network", "late-node"])
def test_proxy_invalid_response_cannot_publish_partial_children(change):
    g = Graph()
    db = node(g, "cdb.instance", "cdb-one")
    d = proxy()
    if change == "count":
        d["Count"] = 2
    elif change == "duplicate":
        d["ProxyInfos"].append(copy.deepcopy(d["ProxyInfos"][0]))
        d["Count"] = 2
    elif change == "region":
        d["ProxyInfos"][0]["ProxyNode"][0]["Region"] = "ap-guangzhou"
    elif change == "port":
        d["ProxyInfos"][0]["ProxyAddress"][0]["VPort"] = 70000
    elif change == "network":
        d["ProxyInfos"][0]["ProxyAddress"][0]["UniqVpcId"] = "subnet-wrong"
    else:
        d["ProxyInfos"][0]["ProxyNode"].append(dict(ProxyId="../bad"))
    before = g.dump()
    with pytest.raises(CollectionError):
        apply(g, db, "cdb", "DescribeCdbProxyInfo", d)
    assert g.dump() == before


@pytest.mark.parametrize(
    "service,action,data",
    [
        (
            "postgres",
            "DescribeBackupPlans",
            dict(Plans=[dict(PlanId="plan-one", PlanName="weekly", BaseBackupRetentionPeriod=7)]),
        ),
        ("postgres", "DescribeDBInstanceHAConfig", dict(SyncMode="Semi-Sync", MaxStandbyLag=10)),
        (
            "sqlserver",
            "DescribeDBSecurityGroups",
            dict(SecurityGroupSet=[dict(SecurityGroupId="sg-one")]),
        ),
        (
            "sqlserver",
            "DescribeDBInstancesAttribute",
            dict(
                RegularBackupEnable="enable",
                RegularBackupSaveDays=365,
                SSLConfig=dict(Encryption="enable", SSLValidity=1),
                TDEConfig=dict(Encryption="enable", CertificateAttribution="self"),
            ),
        ),
        ("mariadb", "DescribeDBSecurityGroups", dict(Groups=[dict(SecurityGroupId="sg-one")])),
        ("mariadb", "DescribeLogFileRetentionPeriod", dict(InstanceId="db-one", Days=7)),
        (
            "mariadb",
            "DescribeDcnDetail",
            dict(
                DcnDetails=[
                    dict(InstanceId="tdsql-dr", Region="ap-guangzhou", DcnFlag=2, DcnStatus=2)
                ]
            ),
        ),
    ],
)
def test_other_engine_configuration(service, action, data):
    g = Graph()
    db = node(g, service + ".instance", "db-one")
    apply(g, db, service, action, data)
    assert db["properties"] or g.edges
    assert all(icon_for(n["kind"]) != "unmapped.svg" for n in g.nodes.values())


def test_database_scope_denial_does_not_hide_backup_or_proxy_configuration():
    g = Graph()
    db = node(g, "cdb.instance", "cdb-one")
    responses = dict(
        DescribeBackupConfig=dict(BackupExpireDays=7),
        DescribeRemoteBackupConfig=dict(ExpireDays=7),
        DescribeDBInstanceConfig=dict(ProtectMode=1),
        DescribeCdbProxyInfo=proxy(),
        DescribeRoGroups=dict(RoGroups=[]),
    )

    def call(s, a, r, **params):
        assert params == {"InstanceId": "cdb-one"}
        if a == "DescribeRemoteBackupConfig":
            raise CollectionError("UnauthorizedOperation")
        return responses[a]

    collect(runner(g, call), db, "cdb")
    assert len(g.coverage) == 5 and sum(r["status"] == "denied" for r in g.coverage) == 1
    assert any(n["kind"] == "cdb.proxyaddress" for n in g.nodes.values())


def test_pg_fixed_parameter_queries_and_independent_missing_parameters():
    g = Graph()
    db = node(g, "postgres.dbinstanceid", "postgres-one")
    calls = []

    def call(s, a, r, **params):
        calls.append(params)
        name = params["ParamName"]
        if name == "ssl":
            return dict(TotalCount=0, Detail=[])
        return dict(
            TotalCount=1,
            Detail=[
                dict(
                    Name=name,
                    ParamValueType="integer",
                    CurrentValue="100",
                    DefaultValue="50",
                    NeedReboot=True,
                    Password="OMIT",
                )
            ],
        )

    postgres_parameters(runner(g, call), db)
    assert {p["ParamName"] for p in calls} == PG_PARAMETERS
    assert (
        len([n for n in g.nodes.values() if n["kind"] == "postgres.parameter"])
        == len(PG_PARAMETERS) - 1
    )
    assert "OMIT" not in g.dump() and g.coverage[-1]["status"] in ("complete", "empty")


@pytest.mark.parametrize(
    "params",
    [
        {"DBInstanceId": "postgres-one"},
        {"DBInstanceId": "postgres-one", "ParamName": "primary_conninfo"},
        {"DBInstanceId": "postgres-one", "ParamName": "max_connections", "Extra": "x"},
    ],
)
def test_pg_parameter_scope_guard_before_subprocess(params, monkeypatch):
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: pytest.fail("unsafe request executed"))
    with pytest.raises(CollectionError, match="Collection failed"):
        TccliTransport().call("postgres", "DescribeDBInstanceParameters", REGION, **params)


def test_pg_parameter_scope_mismatch_never_creates_nodes():
    g = Graph()
    db = node(g, "postgres.dbinstanceid", "postgres-one")
    postgres_parameters(
        runner(
            g,
            lambda *a, **kw: dict(
                TotalCount=1, Detail=[dict(Name="primary_conninfo", CurrentValue="OMIT")]
            ),
        ),
        db,
    )
    assert len(g.nodes) == 1 and "OMIT" not in g.dump()
    assert all(r["error"] == "DatabaseParameterScopeMismatch" for r in g.coverage)


def test_pg_replica_group_scope_and_member_references():
    g = Graph()
    db = node(g, "postgres.dbinstanceid", "postgres-one")

    def call(s, a, r, **params):
        assert params["Filters"] == [dict(Name="db-master-instance-id", Values=["postgres-one"])]
        return dict(
            ReadOnlyGroupList=[
                dict(
                    ReadOnlyGroupId="group-one",
                    MasterDBInstanceId="postgres-one",
                    Region=REGION,
                    VpcId="vpc-one",
                    ReadOnlyDBInstanceList=[dict(DBInstanceId="postgres-ro")],
                )
            ]
        )

    postgres_groups(runner(g, call), db)
    assert any(e["relationship"] == "HAS_READ_ONLY_MEMBER" for e in g.edges.values())
    assert g.coverage[0]["status"] == "complete"


def test_saml_safe_public_metadata_and_identity_controls():
    parsed = saml(XML)
    assert parsed == saml(base64.b64encode(XML.encode()).decode(), True)
    assert parsed[0]["sso_endpoints"][0]["location"] == "https://idp.test/login"
    assert "OMIT" not in json.dumps(parsed)
    assert identifier("up-one", "rc") == "up-one"
    with pytest.raises(CollectionError):
        provider_details(
            dict(EntityId="wrong", EncodedMetadataDocument=base64.b64encode(XML.encode()).decode())
        )


@pytest.mark.parametrize(
    "value",
    [
        "not XML",
        '<!DOCTYPE foo [<!ENTITY x "expansion">]><foo>&x;</foo>',
        '<EntityDescriptor xmlns="wrong" entityID="idp"/>',
        '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"/>',
        XML.replace("https://idp.test/login?token=OMIT#OMIT", "https://user:OMIT@idp.test/login"),
    ],
)
def test_bad_saml_is_rejected(value):
    with pytest.raises(CollectionError):
        saml(value)


def test_federation_trust_links_declaration_without_granting_access():
    g = Graph()
    role = node(g, "cam.role", "7", region="global")
    idp = node(g, "cam.samlprovider", "idp", region="global")
    node(g, "cam.samlprovider", "idp", region="global", account="200")
    doc = dict(
        version="2.0",
        statement=[
            dict(
                effect="deny",
                action="name/sts:AssumeRoleWithSAML",
                principal=dict(federated=["qcs::cam::uin/100:saml-provider/idp"]),
            )
        ],
    )
    add_document(g, role["id"], parse_document(json.dumps(doc), True), "fixture", True)
    link_providers(g)
    assert [
        e["target"]
        for e in g.edges.values()
        if e["relationship"] == "REFERENCES_FEDERATION_PROVIDER"
    ] == [idp["id"]]
    assert not any(e["relationship"].startswith("CAN_") for e in g.edges.values())


def test_cic_role_detail_provisioning_user_sync_and_managed_policy_metadata():
    g = Graph()
    zone = node(g, "organization.ciczone", "z-one", region="global")
    config = node(
        g,
        "organization.cicconfiguration",
        "z-one/rc-one",
        region="global",
        RoleConfigurationId="rc-one",
    )
    p = node(
        g,
        "organization.cicpolicy",
        "policy",
        region="global",
        RolePolicyId=1,
        RolePolicyName="ReadOnly",
    )

    def call(s, a, r, **params):
        if a == "GetRoleConfiguration":
            return dict(
                RoleConfigurationInfo=dict(
                    RoleConfigurationId="rc-one",
                    SessionDuration=3600,
                    RelayState="https://console.test/home?token=OMIT",
                )
            )
        if a == "GetPolicy":
            return dict(
                PolicyName="ReadOnly",
                PolicyDocument=json.dumps(
                    dict(
                        version="2.0",
                        statement=[
                            dict(effect="allow", action="name/cvm:DescribeInstances", resource="*")
                        ],
                    )
                ),
            )
        key = (
            "RoleConfigurationProvisionings"
            if a == "ListRoleConfigurationProvisionings"
            else "UserProvisionings"
        )
        props = (
            dict(
                TargetUin=200,
                TargetType="MemberUin",
                DeploymentStatus="DeployedRequired",
                RoleConfigurationId="rc-one",
            )
            if key.startswith("Role")
            else dict(
                TargetUin=200,
                TargetType="MemberUin",
                UserProvisioningId="sync-one",
                PrincipalId="g-one",
                PrincipalType="Group",
                Status="Enabled",
                Password="OMIT",
            )
        )
        return {key: [props], "TotalCounts": 1, "IsTruncated": False}

    r = runner(g, call)
    configuration(r, zone, config)
    provisioning(r, zone, config)
    provisioning(r, zone)
    managed_policy(r, p)
    assert all(c["status"] == "complete" for c in g.coverage)
    assert "OMIT" not in g.dump() and not g.accounts
    assert p["properties"]["policy_document_collected"]
    assert any(
        n["properties"].get("DeploymentStatus") == "DeployedRequired" for n in g.nodes.values()
    )


@pytest.mark.parametrize("change", ["foreign-config", "duplicate", "total", "cursor"])
def test_cic_provisioning_invalid_pages_fail_visibly(change):
    g = Graph()
    zone = node(g, "organization.ciczone", "z-one", region="global")
    config = node(
        g,
        "organization.cicconfiguration",
        "z-one/rc-one",
        region="global",
        RoleConfigurationId="rc-one",
    )
    row = dict(
        RoleConfigurationId="rc-other" if change == "foreign-config" else "rc-one",
        TargetUin=200,
        TargetType="MemberUin",
        DeploymentStatus="Deployed",
    )
    data = dict(
        RoleConfigurationProvisionings=[row, row] if change == "duplicate" else [row],
        TotalCounts=2 if change in ("total", "duplicate") else 1,
        IsTruncated=change == "cursor",
    )
    provisioning(runner(g, lambda *a, **kw: data), zone, config)
    assert g.coverage[-1]["status"] == "error" and len(g.nodes) == 2


def test_gateway_mapping_backend_vpc_address_and_tsf_configuration():
    g = Graph()
    service = node(g, "apigateway.service", "service-one")
    domain = node(g, "apigateway.domain", "service-one/example.test")
    mappings(
        g,
        service,
        domain,
        dict(
            Result=dict(
                IsDefaultMapping=False, PathMappingSet=[dict(Path="/app", Environment="release")]
            )
        ),
    )
    backend = node(g, "clb.clb", "lb-one", ip_addresses="10.0.0.2")
    vpc = node(g, "vpc.vpc", "vpc-one")
    g.edge(backend["id"], vpc["id"], "IN_VPC", "fixture")
    api(
        g,
        service,
        dict(
            ServiceId="service-one",
            ApiId="api-one",
            ServiceType="HTTP",
            ServiceConfig=dict(
                Product="clb", UniqVpcId="vpc-one", Url="https://10.0.0.2:443/path?token=OMIT"
            ),
        ),
        True,
    )
    api(
        g,
        service,
        dict(
            ServiceId="service-one",
            ApiId="api-tsf",
            ServiceType="TSF",
            MicroServices=[
                dict(ClusterId="cls-one", NamespaceId="ns-one", MicroServiceName="checkout")
            ],
            ServiceTsfLoadBalanceConf=dict(IsLoadBalance=True, Method="RoundRobin"),
        ),
        True,
    )
    link_backends(g)
    assert any(
        e["relationship"] == "CONFIGURED_HTTP_BACKEND" and e["target"] == backend["id"]
        for e in g.edges.values()
    )
    assert any(e["relationship"] == "CONFIGURED_TSF_BACKEND" for e in g.edges.values())
    assert "OMIT" not in g.dump()


@pytest.mark.parametrize("change", ["account", "region", "vpc", "duplicate", "dns"])
def test_http_gateway_backend_does_not_guess(change):
    g = Graph()
    service = node(g, "apigateway.service", "service-one")
    backend = node(
        g,
        "cvm.instance",
        "ins-one",
        ip_addresses="10.0.0.2",
        account="200" if change == "account" else "100",
        region="ap-guangzhou" if change == "region" else REGION,
    )
    vpc = node(g, "vpc.vpc", "vpc-other" if change == "vpc" else "vpc-one")
    g.edge(backend["id"], vpc["id"], "IN_VPC", "fixture")
    if change == "duplicate":
        other = node(g, "cvm.instance", "ins-two", ip_addresses="10.0.0.2")
        g.edge(other["id"], vpc["id"], "IN_VPC", "fixture")
    api(
        g,
        service,
        dict(
            ServiceId="service-one",
            ApiId="api-one",
            ServiceType="HTTP",
            ServiceConfig=dict(
                Product="cvm",
                UniqVpcId="vpc-one",
                Url="https://db.test" if change == "dns" else "https://10.0.0.2",
            ),
        ),
        True,
    )
    link_backends(g)
    assert not any(e["relationship"] == "CONFIGURED_HTTP_BACKEND" for e in g.edges.values())


@pytest.mark.parametrize(
    "service,action",
    [(s, a) for s, actions in ACTIONS.items() for a in actions]
    + [
        ("postgres", "DescribeDBInstanceParameters"),
        ("postgres", "DescribeReadOnlyGroups"),
        ("postgres", "DescribeBaseBackups"),
        ("postgres", "DescribeLogBackups"),
        ("apigateway", "DescribeUpstreamBindApis"),
        ("apigateway", "DescribeServiceSubDomainMappings"),
        ("cam", "GetSAMLProvider"),
        ("organization", "ListRoleConfigurationProvisionings"),
        ("organization", "ListUserSyncProvisionings"),
        ("organization", "GetRoleConfiguration"),
    ],
)
def test_new_action_contracts_exist_in_official_sdk(service, action):
    models = importlib.import_module(
        f"tencentcloud.{service}.v{API_VERSIONS[service].replace('-', '')}.models"
    )
    assert (service, action) in ALLOWED_ACTIONS
    assert getattr(models, action + "Request") and getattr(models, action + "Response")


def test_notification_fixed_signed_xml_request_and_repeated_elements(
    tmp_path, monkeypatch, frozen_session
):
    import qcloud_cos

    monkeypatch.setattr(
        "tencent_cloud_cartography.cos_transport.credentials",
        lambda _: dict(SecretId="fixture", SecretKey="fixture"),
    )
    calls = []
    xml = b"<NotificationConfiguration><CkafkaConfiguration><Id>kafka</Id><Ckafka><InstanceId>ckafka-one</InstanceId><TopicName>events</TopicName></Ckafka><Event>cos:ObjectCreated:Put</Event><Event>cos:ObjectCreated:Post</Event></CkafkaConfiguration></NotificationConfiguration>"

    def send(self, **kwargs):
        calls.append(kwargs)
        assert kwargs["method"] == "GET"
        assert kwargs["url"] == "https://assets-12345.cos.eu-frankfurt.myqcloud.com/"
        assert kwargs["params"] == {"notification": "", "notify-type": "2"}
        assert kwargs["headers"] == {} and kwargs["auth"] is not None
        return SimpleNamespace(content=xml)

    monkeypatch.setattr(qcloud_cos.CosS3Client, "send_request", send)
    data = TccliTransport(session=frozen_session).call(
        "cos", "get_bucket_notification", REGION, Bucket="assets-12345"
    )
    g = Graph()
    b = node(g, "cos.bucket", "assets-12345")
    notification(g, b, data, "fixture")
    assert len(calls) == 1 and b["properties"]["notification_rule_count"] == 1
    assert (
        len(
            json.loads(
                next(
                    n["properties"]["events"]
                    for n in g.nodes.values()
                    if n["kind"] == "cos.notification"
                )
            )
        )
        == 2
    )


@pytest.mark.parametrize(
    "body",
    [
        b"bad XML",
        b'<!DOCTYPE x [<!ENTITY a "expand">]><NotificationConfiguration>&a;</NotificationConfiguration>',
        '<!DOCTYPE x [<!ENTITY a "expand">]><NotificationConfiguration>&a;</NotificationConfiguration>'.encode(
            "utf-16"
        ),
        b"<Unexpected/>",
        b'<NotificationConfiguration xmlns="https://untrusted.test"/>',
    ],
)
def test_notification_xml_rejects_entities_encodings_and_unexpected_root(body):
    from tencent_cloud_cartography.cos_notifications import parse_xml

    with pytest.raises(CollectionError):
        parse_xml(body)


def test_saml_public_certificate_fingerprint_without_pem_storage():
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture-idp")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    body = XML.replace(
        "<IDPSSODescriptor>",
        '<IDPSSODescriptor><KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>'
        + base64.b64encode(der).decode()
        + "</X509Certificate></X509Data></KeyInfo></KeyDescriptor>",
    )
    p = saml(body)[0]["certificates"][0]
    assert p["sha256"] == cert.fingerprint(hashes.SHA256()).hex()
    assert p["use"] == "signing" and "not_after" in p
    assert base64.b64encode(der).decode() not in json.dumps(p)


def test_upstream_bindings_use_safe_independent_api_and_composite_identities():
    from tencent_cloud_cartography.gateway_depth import collect_upstream_bindings

    g = Graph()
    service = node(g, "apigateway.service", "service-one")
    api(
        g,
        service,
        dict(
            ServiceId="service-one",
            ApiId="api-one",
            ServiceType="HTTP",
            ServiceConfig=dict(Product="upstream", UpstreamId="upstream-one"),
        ),
        True,
    )
    calls = []

    def call(s, a, region=None, **params):
        calls.append(a)
        assert a == "DescribeUpstreamBindApis" and params["UpstreamId"] == "upstream-one"
        return dict(
            Result=dict(
                TotalCount=2,
                BindApiSet=[
                    dict(ServiceId="service-one", ApiId="api-one", BindTime="2026-10-14"),
                    dict(ServiceId="service-two", ApiId="api-one"),
                ],
            )
        )

    r = runner(g, call)
    collect_upstream_bindings(r, service)
    collect_upstream_bindings(r, service)
    link_backends(g)
    assert calls == ["DescribeUpstreamBindApis"]
    assert len([n for n in g.nodes.values() if n["kind"] == "apigateway.upstreambinding"]) == 2
    assert any(e["relationship"] == "CONFIGURED_UPSTREAM" for e in g.edges.values())
    assert not next(n for n in g.nodes.values() if n["kind"] == "apigateway.integration")[
        "properties"
    ]["backend_resolved"]
    assert all(icon_for(n["kind"]) != "unmapped.svg" for n in g.nodes.values())


@pytest.mark.parametrize(
    "data",
    [
        dict(IsDefaultMapping="false", PathMappingSet=[]),
        dict(IsDefaultMapping=False, PathMappingSet=[dict(Path="/app", Environment="wrong")]),
        dict(
            IsDefaultMapping=False,
            PathMappingSet=[
                dict(Path="/app", Environment="release"),
                dict(Path="/app", Environment="test"),
            ],
        ),
        dict(
            IsDefaultMapping=False,
            PathMappingSet=[dict(Path="/app?token=OMIT", Environment="release")],
        ),
    ],
)
def test_invalid_domain_mappings_do_not_publish_routes(data):
    g = Graph()
    service = node(g, "apigateway.service", "service-one")
    domain = node(g, "apigateway.domain", "service-one/domain")
    before = g.dump()
    with pytest.raises(CollectionError):
        mappings(g, service, domain, {"Result": data})
    assert g.dump() == before


def test_remote_backup_regions_are_lists_without_guessed_resources():
    g = Graph()
    db = node(g, "cdb.instance", "cdb-one")
    apply(
        g,
        db,
        "cdb",
        "DescribeRemoteBackupConfig",
        dict(
            RemoteBackupSave="on",
            RemoteRegion=["ap-guangzhou"],
            RegionList=["ap-guangzhou", "ap-singapore"],
        ),
    )
    assert json.loads(db["properties"]["DescribeRemoteBackupConfig"])["RemoteRegion"] == [
        "ap-guangzhou"
    ]
    assert len(g.nodes) == 1


@pytest.mark.parametrize("wrong_instance", [False, True])
def test_pg_backup_inventory_scoped_metadata_and_download_exclusion(wrong_instance):
    from tencent_cloud_cartography.database_depth import postgres_backups

    g = Graph()
    db = node(g, "postgres.dbinstanceid", "postgres-one")
    calls = []

    def call(s, a, region=None, **params):
        calls.append(a)
        assert params["Filters"] == [dict(Name="db-instance-id", Values=["postgres-one"])]
        assert params["MinFinishTime"] == "1970-01-01 00:00:00"
        key = "BaseBackupSet" if a == "DescribeBaseBackups" else "LogBackupSet"
        return {
            "TotalCount": 1,
            key: [
                dict(
                    Id="backup-one",
                    DBInstanceId="postgres-other" if wrong_instance else "postgres-one",
                    State="finished",
                    Size=1024,
                    InternetUrl="OMIT",
                )
            ],
        }

    postgres_backups(runner(g, call), db)
    assert calls == ["DescribeBaseBackups", "DescribeLogBackups"]
    assert "OMIT" not in g.dump()
    assert all(r["status"] == ("error" if wrong_instance else "complete") for r in g.coverage)
    assert len(g.nodes) == (1 if wrong_instance else 3)


def test_gateway_clb_resolution_uses_actual_native_collector_kind_and_vips():
    from tencent_cloud_cartography.catalog import COLLECTORS

    g = Graph()
    service = node(g, "apigateway.service", "service-one")
    spec = next(s for s in COLLECTORS if s.service == "clb")
    nid = g.native(
        "100",
        REGION,
        spec,
        dict(LoadBalancerId="lb-one", LoadBalancerVips=["10.0.0.2"], VpcId="vpc-one"),
        "clb.DescribeLoadBalancers",
    )
    assert g.nodes[nid]["kind"] == "clb.clb"
    api(
        g,
        service,
        dict(
            ServiceId="service-one",
            ApiId="api-one",
            ServiceType="HTTP",
            ServiceConfig=dict(Product="clb", UniqVpcId="vpc-one", Url="http://10.0.0.2:8080"),
        ),
        True,
    )
    link_backends(g)
    assert [
        e["target"] for e in g.edges.values() if e["relationship"] == "CONFIGURED_HTTP_BACKEND"
    ] == [nid]
