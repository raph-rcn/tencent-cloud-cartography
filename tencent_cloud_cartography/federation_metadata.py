"""Public SAML metadata, CIC provisioning and verified policy configuration."""

import base64
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit, urlunsplit

from cryptography import x509

from .cam import add_document, parse_document
from .transport import CollectionError
from .vpc import fields

MD = "{urn:oasis:names:tc:SAML:2.0:metadata}"
DS = "{http://www.w3.org/2000/09/xmldsig#}"


def url(value):
    if not isinstance(value, str) or len(value) > 4096 or any(ord(c) < 32 for c in value):
        raise CollectionError("InvalidFederationUrl")
    try:
        p = urlsplit(value)
        if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
            raise ValueError
        p.port
    except ValueError:
        raise CollectionError("InvalidFederationUrl") from None
    return urlunsplit((p.scheme, p.netloc, p.path, "", ""))


def saml(value, encoded=False):
    if not isinstance(value, str) or len(value) > 1_000_000:
        raise CollectionError("InvalidSamlMetadata")
    try:
        body = base64.b64decode(value, validate=True) if encoded else value.encode()
        text = body.decode("utf-8")
        if "\x00" in text or "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
            raise ValueError
        root = ET.fromstring(text)
        if root.tag not in (MD + "EntityDescriptor", MD + "EntitiesDescriptor"):
            raise ValueError
        entities = (
            [root]
            if root.tag == MD + "EntityDescriptor"
            else root.findall(".//" + MD + "EntityDescriptor")
        )
        if not entities or len(entities) > 100:
            raise ValueError
        result = []
        for entity in entities:
            entity_id = entity.get("entityID")
            if not entity_id or len(entity_id) > 4096 or any(ord(c) < 32 for c in entity_id):
                raise ValueError
            info = dict(
                entity_id=entity_id,
                valid_until=entity.get("validUntil", ""),
                sso_endpoints=[],
                certificates=[],
            )
            for descriptor in entity.findall(MD + "IDPSSODescriptor"):
                for service in descriptor.findall(MD + "SingleSignOnService"):
                    info["sso_endpoints"].append(
                        dict(
                            binding=service.get("Binding", ""),
                            location=url(service.get("Location")),
                        )
                    )
                for key in descriptor.findall(MD + "KeyDescriptor"):
                    for cert in key.findall(".//" + DS + "X509Certificate"):
                        raw = base64.b64decode("".join((cert.text or "").split()), validate=True)
                        parsed = x509.load_der_x509_certificate(raw)
                        info["certificates"].append(
                            dict(
                                use=key.get("use", "unspecified"),
                                sha256=hashlib.sha256(raw).hexdigest(),
                                not_before=parsed.not_valid_before_utc.isoformat(),
                                not_after=parsed.not_valid_after_utc.isoformat(),
                            )
                        )
            result.append(info)
        if len({r["entity_id"] for r in result}) != len(result):
            raise ValueError
        return result
    except (ValueError, ET.ParseError):
        raise CollectionError("InvalidSamlMetadata") from None


def collect_cam(runner):
    for node in list(runner.graph.nodes.values()):
        if (
            node["kind"] != "cam.samlprovider"
            or node["account"] != runner.account
            or node["status"] != "enriched"
        ):
            continue

        def operation(record, node=node):
            data = runner.transport.call(
                "cam", "GetSAMLProvider", "global", Name=node["resource_id"]
            )
            if data.get("RequestId"):
                record["request_ids"].append(data["RequestId"])
            if data.get("Name") != node["resource_id"]:
                raise CollectionError("FederationProviderMismatch")
            value = data.get("SAMLMetadata")
            parsed = saml(
                value, encoded=isinstance(value, str) and not value.lstrip().startswith("<")
            )
            node["properties"].update(
                saml_metadata=json.dumps(parsed, sort_keys=True),
                saml_metadata_collected=True,
                federation_login_verified=False,
            )
            record["count"] = 1

        runner.scope("cam", "GetSAMLProvider", "global", operation, node["resource_id"])


def provider_details(data):
    p = fields(data, ("EntityId", "SSOStatus", "CreateTime", "UpdateTime"))
    if data.get("LoginUrl"):
        p["LoginUrl"] = url(data["LoginUrl"])
    if data.get("CertificateIds") is not None:
        ids = data["CertificateIds"]
        if not isinstance(ids, list) or not all(
            isinstance(i, str) and re.fullmatch(r"[A-Za-z0-9-]+", i) for i in ids
        ):
            raise CollectionError("InvalidFederationCertificateIds")
        p["CertificateIds"] = ids
    if data.get("EncodedMetadataDocument"):
        parsed = saml(data["EncodedMetadataDocument"], True)
        if p.get("EntityId") and p["EntityId"] not in {r["entity_id"] for r in parsed}:
            raise CollectionError("FederationEntityMismatch")
        p["saml_metadata"] = parsed
    return p


def configuration(runner, zone, config):
    def operation(record):
        data = runner.transport.call(
            "organization",
            "GetRoleConfiguration",
            "global",
            ZoneId=zone["resource_id"],
            RoleConfigurationId=config["properties"]["RoleConfigurationId"],
        )
        if data.get("RequestId"):
            record["request_ids"].append(data["RequestId"])
        raw = data.get("RoleConfigurationInfo")
        p = fields(
            raw,
            (
                "RoleConfigurationId",
                "RoleConfigurationName",
                "Description",
                "CreateTime",
                "UpdateTime",
            ),
            integers=("SessionDuration",),
        )
        if p.get("RoleConfigurationId") != config["properties"]["RoleConfigurationId"]:
            raise CollectionError("IdentityCenterConfigurationMismatch")
        if raw.get("RelayState"):
            p["RelayState"] = url(raw["RelayState"])
        config["properties"].update(p, detail_collected=True)
        record["count"] = 1

    runner.scope("organization", "GetRoleConfiguration", "global", operation, config["resource_id"])


def provisioning(runner, zone, config=None):
    from .identity_center import identifier, paged

    def prepare(raw):
        p = fields(
            raw,
            (
                "DeploymentStatus",
                "RoleConfigurationId",
                "RoleConfigurationName",
                "TargetType",
                "TargetName",
                "CreateTime",
                "UpdateTime",
            ),
            integers=("TargetUin",),
        )
        if p.get("RoleConfigurationId") != config["properties"]["RoleConfigurationId"] or p.get(
            "DeploymentStatus"
        ) not in ("Deployed", "DeployedRequired", "DeployFailed"):
            raise CollectionError("InvalidIdentityCenterProvisioning")
        target(p)
        return p["RoleConfigurationId"] + "/" + str(p["TargetUin"]), p

    def sync_prepare(raw):
        p = fields(
            raw,
            (
                "UserProvisioningId",
                "Status",
                "PrincipalId",
                "PrincipalType",
                "PrincipalName",
                "TargetType",
                "TargetName",
                "DuplicationStrategy",
                "DeletionStrategy",
                "CreateTime",
                "UpdateTime",
            ),
            integers=("TargetUin",),
        )
        target(p)
        if p.get("Status") not in ("Enabled", "Disabled") or p.get("PrincipalType") not in (
            "User",
            "Group",
        ):
            raise CollectionError("InvalidIdentityCenterUserSync")
        identifier(p.get("PrincipalId"), "u" if p["PrincipalType"] == "User" else "g")
        rid = p.get("UserProvisioningId")
        if not isinstance(rid, str) or not re.fullmatch(r"[A-Za-z0-9-]+", rid):
            raise CollectionError("InvalidIdentityCenterUserSync")
        return rid, p

    action = "ListRoleConfigurationProvisionings" if config else "ListUserSyncProvisionings"
    nodes = paged(
        runner,
        zone,
        action,
        "RoleConfigurationProvisionings" if config else "UserProvisionings",
        "organization.cicprovisioning" if config else "organization.cicusersync",
        prepare if config else sync_prepare,
        {"RoleConfigurationId": config["properties"]["RoleConfigurationId"]} if config else None,
        config,
    )
    for n in nodes:
        p = n["properties"]
        root = runner.graph.add(
            str(p["TargetUin"]),
            "global",
            "cam.root",
            str(p["TargetUin"]),
            status="reference",
            source="organization." + action,
        )
        runner.graph.edge(n["id"], root, "TARGETS_ACCOUNT", "organization." + action)
        p["effective_access_verified"] = False
        if not config:
            principal = runner.graph.add(
                runner.account,
                "global",
                "organization.cicuser" if p["PrincipalType"] == "User" else "organization.cicgroup",
                zone["resource_id"] + "/" + p["PrincipalId"],
                status="reference",
                source="organization." + action,
            )
            runner.graph.edge(
                principal, n["id"], "HAS_SYNC_CONFIGURATION", "organization." + action
            )


def target(props):
    if (
        type(props.get("TargetUin")) is not int
        or props["TargetUin"] <= 0
        or props.get("TargetType") not in ("ManagerUin", "MemberUin")
    ):
        raise CollectionError("InvalidIdentityCenterTarget")


def managed_policy(runner, node):
    node["properties"].setdefault("policy_document_collected", False)
    pid = node["properties"].get("RolePolicyId")
    if type(pid) is not int or pid <= 0:
        node["properties"]["document_collection_status"] = "missing_policy_id"
        return

    def operation(record):
        data = runner.transport.call("cam", "GetPolicy", "global", PolicyId=pid)
        if data.get("RequestId"):
            record["request_ids"].append(data["RequestId"])
        if data.get("PolicyName") != node["properties"]["RolePolicyName"]:
            raise CollectionError("IdentityCenterPolicyMismatch")
        if data.get("PolicyId") not in (None, pid):
            raise CollectionError("IdentityCenterPolicyMismatch")
        document = parse_document(data.get("PolicyDocument"))
        add_document(runner.graph, node["id"], document, "cam.GetPolicy")
        node["properties"]["policy_document_collected"] = True
        record["count"] = 1

    runner.scope("cam", "GetPolicy", "global", operation, "CIC:" + node["resource_id"])


def link_providers(graph):
    """Exact declared federation principal references, including deny statements."""
    for principal in list(graph.nodes.values()):
        if (
            principal["kind"] != "cam.principal"
            or principal["properties"].get("principal_type") != "federated"
        ):
            continue
        m = re.fullmatch(
            r"qcs::cam::uin/(\d+):saml-provider/(.+)", principal["properties"].get("expression", "")
        )
        if not m:
            continue
        candidates = [
            n
            for n in graph.nodes.values()
            if n["kind"] == "cam.samlprovider"
            and n["account"] == m[1]
            and n["resource_id"] == m[2]
            and n["status"] == "enriched"
        ]
        if len(candidates) == 1:
            graph.edge(
                principal["id"],
                candidates[0]["id"],
                "REFERENCES_FEDERATION_PROVIDER",
                "exact declared SAML provider QCS",
            )
