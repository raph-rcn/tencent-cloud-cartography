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
    )
    props = {key: raw[key] for key in fields if type(raw.get(key)) in (str, int, bool)}
    for key in ("SubjectAltName", "CertSANs", "CAEncryptAlgorithms", "CAEndTimes", "CACommonNames"):
        if raw.get(key) is not None:
            if not isinstance(raw[key], list) or not all(isinstance(s, str) for s in raw[key]):
                raise CollectionError("InvalidCertificateMetadata")
            props[key] = json.dumps(raw[key], ensure_ascii=False)
    props.update(certificate_time_zone="Asia/Shanghai", metadata_collected=True)
    # BoundResource is documented as unavailable. Consumers assert their own links.
    node["properties"].update(props)
