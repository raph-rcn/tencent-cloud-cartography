import base64
import json

import pytest

from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.identity_center import collect
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.transport import CollectionError


def test_identity_center_groups_members_policies_and_foreign_account_assignments():
    calls = []

    class T:
        def call(self, s, a, region=None, **params):
            calls.append((a, params))
            assert s == "organization" and region == "global"
            if a == "DescribeIdentityCenter":
                return dict(ZoneId="z-one", ServiceStatus="Enabled", ZoneName="cic")
            if a == "GetExternalSAMLIdentityProvider":
                return dict(
                    SAMLIdentityProviderConfiguration=dict(
                        EntityId="idp",
                        SSOStatus="Enabled",
                        EncodedMetadataDocument=base64.b64encode(
                            b'<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="idp"/>'
                        ).decode(),
                    )
                )
            if a == "GetRoleConfiguration":
                return dict(RoleConfigurationInfo=dict(RoleConfigurationId="rc-one"))
            if a in ("ListRoleConfigurationProvisionings", "ListUserSyncProvisionings"):
                return {
                    "RoleConfigurationProvisionings"
                    if a == "ListRoleConfigurationProvisionings"
                    else "UserProvisionings": [],
                    "TotalCounts": 0,
                    "IsTruncated": False,
                }
            if a == "ListPermissionPoliciesInRoleConfiguration":
                kind = params["RolePolicyType"]
                return dict(
                    TotalCounts=1,
                    RolePolicies=[
                        dict(
                            RolePolicyType=kind,
                            RolePolicyName="policy",
                            RolePolicyDocument=json.dumps(
                                dict(
                                    version="2.0",
                                    statement=[dict(effect="allow", action="*", resource="*")],
                                )
                            )
                            if kind == "Custom"
                            else "",
                        )
                    ],
                )
            arrays = {
                "ListGroups": ("Groups", [dict(GroupId="g-one", GroupName="group", MemberCount=1)]),
                "ListGroupMembers": (
                    "GroupMembers",
                    [dict(UserId="u-one", UserName="user", UserStatus="Enabled", Email="OMIT")],
                ),
                "ListRoleConfigurations": (
                    "RoleConfigurations",
                    [
                        dict(
                            RoleConfigurationId="rc-one",
                            RoleConfigurationName="config",
                            SessionDuration=3600,
                        )
                    ],
                ),
                "ListRoleAssignments": (
                    "RoleAssignments",
                    [
                        dict(
                            RoleConfigurationId="rc-one",
                            TargetUin=200,
                            TargetType="MemberUin",
                            PrincipalType="Group",
                            PrincipalId="g-one",
                        )
                    ],
                ),
            }
            result, batch = arrays[a]
            return {result: batch, "TotalCounts": len(batch), "IsTruncated": False}

    g = Graph()
    collect(CollectorRunner(g, T(), "100", [], lambda _: None))
    assert all(r["status"] in ("complete", "empty") for r in g.coverage)
    assert "OMIT" not in g.dump()
    assert not any(a in ("ListUsers", "GetUser", "ListSCIMCredentials") for a, _ in calls)
    assert {"MEMBER_OF", "HAS_PERMISSION_POLICY", "HAS_ACCOUNT_ASSIGNMENT", "TARGETS_ACCOUNT"} <= {
        e["relationship"] for e in g.edges.values()
    }
    assert any(
        n["kind"] == "cam.root" and n["account"] == "200" and n["status"] == "reference"
        for n in g.nodes.values()
    )
    assert not g.accounts
    assert not next(n for n in g.nodes.values() if n["kind"] == "organization.ciczone")[
        "properties"
    ]["full_user_inventory_collected"]


@pytest.mark.parametrize("failure", ["stalled", "total", "parent", "denied"])
def test_identity_center_partial_pages_and_assignments_do_not_hide_independent_scopes(failure):
    class T:
        def call(self, s, a, region=None, **params):
            if a == "DescribeIdentityCenter":
                return dict(ZoneId="z-one", ServiceStatus="Enabled")
            if a == "ListGroups":
                if failure == "denied":
                    raise CollectionError("UnauthorizedOperation")
                if not params.get("NextToken"):
                    return dict(
                        Groups=[dict(GroupId="g-one")],
                        TotalCounts=2,
                        IsTruncated=True,
                        NextToken="next",
                    )
                return dict(
                    Groups=[dict(GroupId="g-two")],
                    TotalCounts=3 if failure == "total" else 2,
                    IsTruncated=failure == "stalled",
                    NextToken="next",
                )
            if a == "ListGroupMembers":
                return dict(GroupMembers=[], TotalCounts=0, IsTruncated=False)
            if a == "ListRoleConfigurations":
                return dict(
                    RoleConfigurations=[dict(RoleConfigurationId="rc-one")],
                    TotalCounts=1,
                    IsTruncated=False,
                )
            if a == "ListRoleAssignments":
                return dict(
                    RoleAssignments=[
                        dict(
                            RoleConfigurationId="rc-other" if failure == "parent" else "rc-one",
                            TargetUin=200,
                            TargetType="MemberUin",
                            PrincipalType="User",
                            PrincipalId="u-one",
                        )
                    ],
                    TotalCounts=1,
                    IsTruncated=False,
                )
            if a == "ListPermissionPoliciesInRoleConfiguration":
                return dict(RolePolicies=[], TotalCounts=0)
            if a == "GetExternalSAMLIdentityProvider":
                return dict(SAMLIdentityProviderConfiguration=dict(SSOStatus="Disabled"))
            if a == "GetRoleConfiguration":
                return dict(RoleConfigurationInfo=dict(RoleConfigurationId="rc-one"))
            if a in ("ListRoleConfigurationProvisionings", "ListUserSyncProvisionings"):
                return {
                    "RoleConfigurationProvisionings"
                    if a == "ListRoleConfigurationProvisionings"
                    else "UserProvisionings": [],
                    "TotalCounts": 0,
                    "IsTruncated": False,
                }
            raise AssertionError(a)

    g = Graph()
    collect(CollectorRunner(g, T(), "100", [], lambda _: None))
    assert any(r["status"] in ("error", "denied") for r in g.coverage)
    assert any(n["kind"] == "organization.cicconfiguration" for n in g.nodes.values())
    if failure == "parent":
        assert not any(n["kind"] == "organization.cicassignment" for n in g.nodes.values())
    if failure in ("stalled", "total"):
        assert len([n for n in g.nodes.values() if n["kind"] == "organization.cicgroup"]) == 1
