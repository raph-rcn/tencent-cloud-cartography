"""CIC spaces, groups, safe membership views, permissions and account assignments."""

import json
import re

from .cam import add_document, parse_document
from .transport import CollectionError
from .vpc import fields


def identifier(value, prefix):
    if not isinstance(value, str) or not re.fullmatch(
        ("(?:rc|up)" if prefix == "rc" else prefix) + r"-[a-z0-9]+", value
    ):
        raise CollectionError("InvalidIdentityCenterId")
    return value


def collect(runner):
    graph = runner.graph
    selected = []

    def center(record):
        data = runner.transport.call("organization", "DescribeIdentityCenter", "global")
        if data.get("RequestId"):
            record["request_ids"].append(data["RequestId"])
        props = fields(
            data,
            ("ZoneId", "ZoneName", "ServiceStatus", "ScimSyncStatus", "CreateTime", "UpdateTime"),
        )
        if props.get("ServiceStatus") == "Disabled":
            record["reported_service_status"] = "Disabled"
            return
        if props.get("ServiceStatus") != "Enabled":
            raise CollectionError("UnknownIdentityCenterStatus")
        rid = identifier(props.get("ZoneId"), "z")
        nid = graph.add(
            runner.account,
            "global",
            "organization.ciczone",
            rid,
            props.get("ZoneName"),
            source="organization.DescribeIdentityCenter",
        )
        graph.nodes[nid]["properties"].update(
            props, collection_view="query_account", full_user_inventory_collected=False
        )
        selected.append(graph.nodes[nid])
        record["count"] = 1

    runner.scope("organization", "DescribeIdentityCenter", "global", center)
    for zone in selected:
        groups = paged(
            runner,
            zone,
            "ListGroups",
            "Groups",
            "organization.cicgroup",
            lambda row: (
                identifier(row.get("GroupId"), "g"),
                fields(
                    row,
                    (
                        "GroupId",
                        "GroupName",
                        "Description",
                        "CreateTime",
                        "GroupType",
                        "UpdateTime",
                    ),
                    integers=("MemberCount",),
                ),
            ),
        )
        for group in groups:
            memberships(runner, zone, group)
        configs = paged(
            runner,
            zone,
            "ListRoleConfigurations",
            "RoleConfigurations",
            "organization.cicconfiguration",
            lambda row: (
                identifier(row.get("RoleConfigurationId"), "rc"),
                fields(
                    row,
                    (
                        "RoleConfigurationId",
                        "RoleConfigurationName",
                        "Description",
                        "CreateTime",
                        "UpdateTime",
                    ),
                    integers=("SessionDuration",),
                ),
            ),
        )
        for config in configs:
            from .federation_metadata import configuration, provisioning

            configuration(runner, zone, config)
            policies(runner, zone, config)
            assignments(runner, zone, config)
            provisioning(runner, zone, config)
        provider(runner, zone)
        from .federation_metadata import provisioning

        provisioning(runner, zone)


def paged(runner, zone, action, result, kind, prepare, params=None, parent=None):
    graph = runner.graph
    selected = []

    def operation(record):
        token = None
        seen = set()
        tokens = set()
        count = 0
        expected = None
        for _ in range(10000):
            args = dict(ZoneId=zone["resource_id"], MaxResults=100, **(params or {}))
            if token:
                args["NextToken"] = token
            data = runner.transport.call("organization", action, "global", **args)
            if data.get("RequestId"):
                record["request_ids"].append(data["RequestId"])
            total, truncated = data.get("TotalCounts"), data.get("IsTruncated")
            batch = data.get(result)
            if (
                type(total) is not int
                or total < 0
                or type(truncated) is not bool
                or not isinstance(batch, list)
            ):
                raise CollectionError("InvalidIdentityCenterPagination")
            if expected is not None and expected != total:
                raise CollectionError("IdentityCenterInventoryChanged")
            expected = total
            prepared = [prepare(row) for row in batch]
            ids = [rid for rid, _ in prepared]
            if len(set(ids)) != len(ids) or seen.intersection(ids):
                raise CollectionError("DuplicateIdentityCenterResource")
            cursor = data.get("NextToken")
            count += len(prepared)
            if (
                count > total
                or (not truncated and count != total)
                or (
                    truncated
                    and (
                        not prepared
                        or not isinstance(cursor, str)
                        or not cursor
                        or cursor in tokens
                    )
                )
            ):
                raise CollectionError("IdentityCenterCountOrCursorMismatch")
            seen.update(ids)
            for rid, props in prepared:
                nid = graph.add(
                    runner.account,
                    "global",
                    kind,
                    zone["resource_id"] + "/" + rid,
                    props.get("GroupName")
                    or props.get("RoleConfigurationName")
                    or props.get("UserName"),
                    source="organization." + action,
                )
                graph.nodes[nid]["properties"].update(props, ZoneId=zone["resource_id"])
                graph.edge((parent or zone)["id"], nid, "CONTAINS", "organization." + action)
                selected.append(graph.nodes[nid])
                record["count"] += 1
            if not truncated:
                return
            tokens.add(cursor)
            token = cursor
        raise CollectionError("IdentityCenterPageLimit")

    runner.scope(
        "organization",
        action,
        "global",
        operation,
        json.dumps(dict(ZoneId=zone["resource_id"], **(params or {})), sort_keys=True),
    )
    return selected


def memberships(runner, zone, group):
    def prepare(row):
        uid = identifier(row.get("UserId"), "u")
        props = fields(
            row,
            (
                "UserId",
                "UserName",
                "DisplayName",
                "Description",
                "UserStatus",
                "UserType",
                "JoinTime",
            ),
        )
        return group["properties"]["GroupId"] + "/" + uid, props

    nodes = paged(
        runner,
        zone,
        "ListGroupMembers",
        "GroupMembers",
        "organization.cicmembership",
        prepare,
        dict(GroupId=group["properties"]["GroupId"]),
        group,
    )
    for member in nodes:
        props = member["properties"]
        uid = runner.graph.add(
            runner.account,
            "global",
            "organization.cicuser",
            zone["resource_id"] + "/" + props["UserId"],
            props.get("UserName"),
            source="organization.ListGroupMembers",
        )
        runner.graph.nodes[uid]["properties"].update(
            {k: v for k, v in props.items() if k != "JoinTime"},
            identity_source="group_membership_metadata",
            full_profile_collected=False,
        )
        runner.graph.edge(uid, group["id"], "MEMBER_OF", "organization.ListGroupMembers")
        runner.graph.edge(member["id"], uid, "IDENTIFIES_USER", "organization.ListGroupMembers")


def policies(runner, zone, config):
    for policy_type in ("System", "Custom"):

        def operation(record, policy_type=policy_type):
            data = runner.transport.call(
                "organization",
                "ListPermissionPoliciesInRoleConfiguration",
                "global",
                ZoneId=zone["resource_id"],
                RoleConfigurationId=config["properties"]["RoleConfigurationId"],
                RolePolicyType=policy_type,
            )
            if data.get("RequestId"):
                record["request_ids"].append(data["RequestId"])
            batch = data.get("RolePolicies")
            if (
                not isinstance(batch, list)
                or type(data.get("TotalCounts")) is not int
                or len(batch) != data["TotalCounts"]
            ):
                raise CollectionError("IdentityCenterPolicyCountMismatch")
            prepared = []
            for row in batch:
                props = fields(
                    row, ("RolePolicyName", "RolePolicyType", "AddTime"), integers=("RolePolicyId",)
                )
                if props.get("RolePolicyType") != policy_type or not props.get("RolePolicyName"):
                    raise CollectionError("InvalidIdentityCenterPolicy")
                doc = (
                    parse_document(row.get("RolePolicyDocument"))
                    if policy_type == "Custom"
                    else None
                )
                prepared.append((props, doc))
            if len({p["RolePolicyName"] for p, _ in prepared}) != len(prepared):
                raise CollectionError("DuplicateIdentityCenterPolicy")
            for props, doc in prepared:
                nid = runner.graph.add(
                    runner.account,
                    "global",
                    "organization.cicpolicy",
                    config["resource_id"] + "/" + policy_type + "/" + props["RolePolicyName"],
                    props["RolePolicyName"],
                    source="organization.ListPermissionPoliciesInRoleConfiguration",
                )
                runner.graph.nodes[nid]["properties"].update(props, effective_access_verified=False)
                if doc:
                    add_document(
                        runner.graph,
                        nid,
                        doc,
                        "organization.ListPermissionPoliciesInRoleConfiguration",
                    )
                runner.graph.edge(
                    config["id"],
                    nid,
                    "HAS_PERMISSION_POLICY",
                    "organization.ListPermissionPoliciesInRoleConfiguration",
                )
                record["count"] += 1
                if policy_type == "System":
                    from .federation_metadata import managed_policy

                    managed_policy(runner, runner.graph.nodes[nid])

        runner.scope(
            "organization",
            "ListPermissionPoliciesInRoleConfiguration",
            "global",
            operation,
            config["resource_id"] + ":" + policy_type,
        )


def assignments(runner, zone, config):
    def prepare(row):
        props = fields(
            row,
            (
                "RoleConfigurationId",
                "RoleConfigurationName",
                "TargetType",
                "PrincipalId",
                "PrincipalType",
                "PrincipalName",
                "CreateTime",
                "UpdateTime",
            ),
            integers=("TargetUin",),
        )
        if props.get("RoleConfigurationId") != config["properties"][
            "RoleConfigurationId"
        ] or not props.get("TargetUin"):
            raise CollectionError("IdentityCenterAssignmentMismatch")
        category = props.get("PrincipalType")
        if category not in ("User", "Group") or props.get("TargetType") not in (
            "ManagerUin",
            "MemberUin",
        ):
            raise CollectionError("InvalidIdentityCenterAssignment")
        identifier(props.get("PrincipalId"), "u" if category == "User" else "g")
        rid = (
            config["properties"]["RoleConfigurationId"]
            + "/"
            + str(props["TargetUin"])
            + "/"
            + category
            + "/"
            + props["PrincipalId"]
        )
        return rid, props

    nodes = paged(
        runner,
        zone,
        "ListRoleAssignments",
        "RoleAssignments",
        "organization.cicassignment",
        prepare,
        dict(RoleConfigurationId=config["properties"]["RoleConfigurationId"]),
        config,
    )
    for assignment in nodes:
        props = assignment["properties"]
        principal = runner.graph.add(
            runner.account,
            "global",
            "organization.cicuser" if props["PrincipalType"] == "User" else "organization.cicgroup",
            zone["resource_id"] + "/" + props["PrincipalId"],
            props.get("PrincipalName"),
            source="organization.ListRoleAssignments",
            status="reference",
        )
        runner.graph.edge(
            principal,
            assignment["id"],
            "HAS_ACCOUNT_ASSIGNMENT",
            "organization.ListRoleAssignments",
        )
        target = runner.graph.add(
            str(props["TargetUin"]),
            "global",
            "cam.root",
            str(props["TargetUin"]),
            source="organization.ListRoleAssignments",
            status="reference",
        )
        runner.graph.edge(
            assignment["id"], target, "TARGETS_ACCOUNT", "organization.ListRoleAssignments"
        )
        assignment["properties"]["effective_access_verified"] = False


def provider(runner, zone):
    def operation(record):
        data = runner.transport.call(
            "organization", "GetExternalSAMLIdentityProvider", "global", ZoneId=zone["resource_id"]
        )
        if data.get("RequestId"):
            record["request_ids"].append(data["RequestId"])
        from .federation_metadata import provider_details

        props = provider_details(data.get("SAMLIdentityProviderConfiguration"))
        if not props:
            raise CollectionError("MissingIdentityProviderConfiguration")
        zone["properties"]["saml_provider_configuration"] = json.dumps(props, sort_keys=True)
        record["count"] = 1

    runner.scope(
        "organization", "GetExternalSAMLIdentityProvider", "global", operation, zone["resource_id"]
    )
