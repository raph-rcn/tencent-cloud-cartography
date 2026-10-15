"""Certificate inventory from the list API; private-key detail endpoints are excluded."""

import json

from .transport import CollectionError


def enrich_certificate(node, raw):
    fields = (
        "OwnerUin",
        "ProjectId",
        "From",
        "CertificateType",
        "Domain",
        "Status",
        "VerifyType",
        "CertBeginTime",
        "CertEndTime",
        "InsertTime",
        "IsDv",
        "IsWildcard",
        "IsSM",
        "EncryptAlgorithm",
        "AutoRenewFlag",
        "IsExpiring",
        "ValidationPassedTime",
        "CertRevokedTime",
        "PackageType",
        "ProductZhName",
        "Alias",
        "VulnerabilityStatus",
        "StatusMsg",
        "ValidityPeriod",
        "PackageTypeName",
        "StatusName",
        "IsVip",
        "IsVulnerability",
        "RenewAble",
        "Deployable",
        "IsIgnore",
        "HostingStatus",
        "HostingCompleteTime",
        "HostingRenewCertId",
        "HasRenewOrder",
        "ReplaceOriCertIsDelete",
        "DVAuthDeadline",
        "AllowDownload",
        "IsDNSPODResolve",
        "IsPackage",
        "KeyPasswordCustomFlag",
        "IsHostingUploadRenewCert",
        "ServiceId",
        "ServiceStatus",
        "CertServiceBeginTime",
        "CertServiceEndTime",
        "CertServiceShareEnabled",
        "CertServiceValidCertificateCount",
    )
    props = {key: raw[key] for key in fields if type(raw.get(key)) in (str, int, bool)}
    for key in (
        "SubjectAltName",
        "CertSANs",
        "CAEncryptAlgorithms",
        "CAEndTimes",
        "CACommonNames",
        "HostingResourceTypes",
    ):
        if raw.get(key) is not None:
            if not isinstance(raw[key], list) or not all(isinstance(s, str) for s in raw[key]):
                raise CollectionError("InvalidCertificateMetadata")
            props[key] = json.dumps(raw[key], ensure_ascii=False)
    from .data_metadata import project, schema

    for field, spec in {
        "CertificateExtra": schema(
            "DomainNumber OriginCertificateId ReplacedBy ReplacedFor RenewOrder ServiceRenewCertificateId ServiceOriginCertificateId",
            "SMCert CompanyType",
        ),
        "HostingConfig": schema("ReplaceStartTime ReplaceEndTime", "ReplaceTime"),
        "ProjectInfo": schema(
            "ProjectName ProjectCreateTime ProjectResume ProjectId", "ProjectCreatorUin OwnerUin"
        ),
    }.items():
        if raw.get(field) is not None:
            # Public lifecycle metadata only. No detail endpoint is called.
            props[field] = json.dumps(project(raw[field], spec), sort_keys=True)
    props.update(private_key_collected=False, certificate_consumers_complete=False)
    props.update(certificate_time_zone="Asia/Shanghai", metadata_collected=True)
    # BoundResource is documented as unavailable. Consumers assert their own links.
    node["properties"].update(props)
