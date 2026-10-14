"""Credential identifiers, protection settings and permission-boundary configuration."""

import json

from .cam import _unique_object, add_document, parse_document
from .transport import CollectionError
from .vpc import fields


def collect(runner):
    graph = runner.graph
    for node in list(graph.nodes.values()):
        if (
            node["kind"] not in ("cam.user", "cam.role")
            or node["account"] != runner.account
            or node["status"] != "enriched"
        ):
            continue
        rid = node["resource_id"]
        if node["kind"] == "cam.user":
            user(runner, node)
        action = (
            "GetUserPermissionBoundary"
            if node["kind"] == "cam.user"
            else "GetRolePermissionBoundary"
        )
        params = dict(TargetUin=int(rid)) if node["kind"] == "cam.user" else dict(RoleId=rid)

        def boundary(record, node=node, action=action, params=params):
            data = runner.transport.call("cam", action, "global", **params)
            if data.get("RequestId"):
                record["request_ids"].append(data["RequestId"])
            props = fields(data, ("PolicyName",), integers=("PolicyId", "PolicyType", "CreateMode"))
            if type(props.get("PolicyId")) is not int or props["PolicyId"] <= 0:
                # Null does not establish that no boundary exists.
                node["properties"]["boundary_collection_status"] = "unknown"
                raise CollectionError("UnresolvedPermissionBoundary")
            raw = data.get("PolicyDocument")
            if not isinstance(raw, str) or len(raw.encode()) > 1_000_000:
                raise CollectionError("InvalidPolicyDocument")
            if isinstance(raw, str):
                try:
                    raw = json.loads(raw, object_pairs_hook=_unique_object)
                except ValueError:
                    raise CollectionError("InvalidPolicyDocument") from None
            if isinstance(raw, dict) and set(raw) == {"strategyInfo"}:
                raw = raw["strategyInfo"]
            document = parse_document(json.dumps(raw, allow_nan=False))
            pid = graph.add(
                runner.account,
                "global",
                "cam.boundary",
                node["resource_id"] + "/" + str(props["PolicyId"]),
                props.get("PolicyName"),
                source="cam." + action,
            )
            graph.nodes[pid]["properties"].update(props)
            add_document(graph, pid, document, "cam." + action)
            graph.edge(node["id"], pid, "HAS_PERMISSION_BOUNDARY", "cam." + action)
            node["properties"]["boundary_collection_status"] = "collected"
            record["count"] = 1

        runner.scope("cam", action, "global", boundary, rid)


def user(runner, node):
    for action in ("ListAccessKeys", "DescribeSafeAuthFlagColl"):

        def operation(record, action=action):
            params = (
                dict(TargetUin=int(node["resource_id"]))
                if action == "ListAccessKeys"
                else dict(SubUin=int(node["resource_id"]))
            )
            data = runner.transport.call("cam", action, "global", **params)
            if data.get("RequestId"):
                record["request_ids"].append(data["RequestId"])
            if action == "ListAccessKeys":
                batch = data.get("AccessKeys")
                if not isinstance(batch, list):
                    raise CollectionError("InvalidCredentialMetadata")
                prepared = [
                    fields(row, ("AccessKeyId", "Status", "CreateTime", "Description"))
                    for row in batch
                ]
                if any(not row.get("AccessKeyId") for row in prepared) or len(
                    {row["AccessKeyId"] for row in prepared}
                ) != len(prepared):
                    raise CollectionError("InvalidCredentialMetadata")
                for props in prepared:
                    nid = runner.graph.add(
                        runner.account,
                        "global",
                        "cam.accesskey",
                        node["resource_id"] + "/" + props["AccessKeyId"],
                        props["AccessKeyId"],
                        source="cam." + action,
                    )
                    runner.graph.nodes[nid]["properties"].update(
                        props, secret_material_collected=False
                    )
                    runner.graph.edge(node["id"], nid, "HAS_ACCESS_KEY_METADATA", "cam." + action)
                    record["count"] += 1
            else:
                props = fields(data, integers=("PromptTrust",))
                for key, numbers in (
                    (
                        "LoginFlag",
                        (
                            "Phone",
                            "Token",
                            "Stoken",
                            "Wechat",
                            "Custom",
                            "Mail",
                            "U2FToken",
                            "Passkey",
                        ),
                    ),
                    (
                        "ActionFlag",
                        (
                            "Phone",
                            "Token",
                            "Stoken",
                            "Wechat",
                            "Custom",
                            "Mail",
                            "U2FToken",
                            "Passkey",
                        ),
                    ),
                    (
                        "OffsiteFlag",
                        ("VerifyFlag", "NotifyPhone", "NotifyEmail", "NotifyWechat", "Tips"),
                    ),
                ):
                    if data.get(key) is not None:
                        props[key] = fields(data[key], integers=numbers)
                if not props:
                    raise CollectionError("MissingProtectionConfiguration")
                node["properties"]["protection_configuration"] = json.dumps(props, sort_keys=True)
                record["count"] = 1

        runner.scope("cam", action, "global", operation, node["resource_id"])
