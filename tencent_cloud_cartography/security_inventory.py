"""Vendor-reported package/vulnerability metadata; no scan, repair or PoC execution."""

import math

from .catalog import Collector
from .model import stable_id
from .transport import CollectionError, pages
from .vpc import fields


def collect(runner):
    graph = runner.graph
    for parent in list(graph.nodes.values()):
        if parent["account"] != runner.account or parent["status"] != "enriched":
            continue
        if parent["kind"] == "cwp.machine":
            queries = (
                (
                    "DescribeAssetSystemPackageList",
                    "Packages",
                    "Total",
                    "cwp.package",
                    dict(Uuid=parent["resource_id"]),
                ),
                (
                    "DescribeVulList",
                    "VulInfoList",
                    "TotalCount",
                    "cwp.vulnerability",
                    dict(Filters=[dict(Name="Uuid", Values=[parent["resource_id"]])]),
                ),
            )
        elif parent["kind"] == "tcss.image":
            queries = (
                (
                    "DescribeAssetImageVulList",
                    "List",
                    "TotalCount",
                    "tcss.vulnerability",
                    dict(ImageID=parent["resource_id"]),
                ),
            )
        else:
            continue
        for action, result, total, kind, params in queries:
            service = kind.split(".")[0]
            spec = Collector(
                service, action, result, kind, ("Name",), total=total, require_total=True
            )

            def operation(
                record, parent=parent, action=action, kind=kind, spec=spec, params=params
            ):
                seen = set()
                for batch, request in pages(runner.transport, spec, parent["region"], params):
                    if request:
                        record["request_ids"].append(request)
                    prepared = []
                    for raw in batch:
                        if kind == "cwp.package":
                            if raw.get("Uuid") not in (None, parent["resource_id"]):
                                raise CollectionError("SecurityAssetMismatch")
                            props = fields(
                                raw,
                                (
                                    "Name",
                                    "Version",
                                    "Type",
                                    "InstallTime",
                                    "UpdateTime",
                                    "FirstTime",
                                ),
                            )
                            if not props.get("Name") or not props.get("Version"):
                                raise CollectionError("InvalidPackageIdentity")
                            key = stable_id(props["Name"], props.get("Type"), props["Version"])
                        elif kind == "cwp.vulnerability":
                            props = fields(
                                raw,
                                (
                                    "Name",
                                    "CveId",
                                    "PublishTime",
                                    "LastTime",
                                    "FirstAppearTime",
                                    "LatestFixTime",
                                    "Labels",
                                    "StatusStr",
                                ),
                                ("FixNoNeedRestart",),
                                (
                                    "VulId",
                                    "Status",
                                    "Level",
                                    "HostCount",
                                    "Method",
                                    "VulCategory",
                                    "AttackLevel",
                                    "FixSwitch",
                                    "VulFixSwitch",
                                    "DefenseAttackCount",
                                ),
                            )
                            if not props.get("VulId"):
                                raise CollectionError("InvalidVulnerabilityIdentity")
                            key = str(props["VulId"]) + "/" + str(props.get("Status"))
                        else:
                            props = fields(
                                raw,
                                (
                                    "CVEID",
                                    "Name",
                                    "Component",
                                    "Version",
                                    "Category",
                                    "CategoryType",
                                    "SubmitTime",
                                    "FixedVersions",
                                    "CVSSV3Desc",
                                ),
                                ("IsSuggest",),
                                ("Level", "AttackLevel"),
                            )
                            if (
                                not props.get("CVEID")
                                or not props.get("Component")
                                or not props.get("Version")
                            ):
                                raise CollectionError("InvalidVulnerabilityIdentity")
                            key = stable_id(props["CVEID"], props["Component"], props["Version"])
                        score = raw.get("CvssScore" if kind.startswith("cwp.") else "CVSSV3Score")
                        if score is not None:
                            if (
                                type(score) not in (int, float)
                                or not math.isfinite(score)
                                or not 0 <= score <= 10
                            ):
                                raise CollectionError("InvalidVendorCvss")
                            props["vendor_cvss_score"] = score
                        if key in seen:
                            raise CollectionError("DuplicateSecurityMetadata")
                        seen.add(key)
                        prepared.append((key, props))
                    for key, props in prepared:
                        nid = graph.add(
                            runner.account,
                            parent["region"],
                            kind,
                            parent["resource_id"] + "/" + key,
                            props.get("Name"),
                            source=service + "." + action,
                        )
                        graph.nodes[nid]["properties"].update(
                            props,
                            evidence_scope="vendor_reported_metadata",
                            independently_validated=False,
                            exploit_executed=False,
                        )
                        graph.edge(
                            parent["id"],
                            nid,
                            "HAS_PACKAGE"
                            if kind == "cwp.package"
                            else "HAS_REPORTED_VULNERABILITY",
                            service + "." + action,
                        )
                        record["count"] += 1

            runner.scope(service, action, parent["region"], operation, parent["resource_id"])
