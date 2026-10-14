"""Offline authorization fixtures; no cloud account or credential is used."""

import json

from tencent_cloud_cartography.cam import add_document, parse_document
from tencent_cloud_cartography.cos import acl, policy
from tencent_cloud_cartography.model import Graph

PREFIX = "qcs::cos:eu-frankfurt:uid/12345:docs-12345/"


def statement(effect="allow", action="cos:GetObject", resource="*", **extra):
    return dict(effect=effect, action=[action], resource=[resource], **extra)


def add_policy(g, parent, rows, boundary=False):
    node = g.nodes[parent]
    pid = g.add(
        node["account"],
        "global",
        "cam.boundary" if boundary else "cam.policy",
        parent + ("/boundary" if boundary else "/policy"),
    )
    add_document(
        g, pid, parse_document(json.dumps(dict(version="2.0", statement=rows))), "offline-fixture"
    )
    g.edge(parent, pid, "HAS_PERMISSION_BOUNDARY" if boundary else "HAS_POLICY", "offline-fixture")
    if boundary:
        g.nodes[parent]["properties"]["boundary_collection_status"] = "collected"
    return pid


def principal(g, account="100", rid="101", kind="cam.user", rows=None, boundary=True):
    nid = g.add(account, "global", kind, rid, "Reader" if kind == "cam.user" else "Role" + rid)
    if kind == "cam.role":
        g.nodes[nid]["properties"].update(
            RoleName="Role" + rid, RoleArn=f"qcs::cam::uin/{account}:role/{rid}"
        )
    for action in ("ListUsers", "ListGroups", "DescribeRoleList"):
        g.coverage.append(
            dict(
                account=account,
                region="global",
                service="cam",
                action=action,
                status="complete",
                count=1,
                request_ids=[],
            )
        )
    g.coverage.append(
        dict(
            account=account,
            region="global",
            service="cam",
            action="ListAttachedUserPolicies" if kind == "cam.user" else "ListAttachedRolePolicies",
            detail=json.dumps(dict(TargetUin=int(rid)) if kind == "cam.user" else dict(RoleId=rid)),
            status="complete",
            count=1,
            request_ids=[],
        )
    )
    if rows:
        add_policy(g, nid, rows)
    if boundary:
        add_policy(g, nid, [statement(action="*")], True)
    return nid


def bucket(g, account="100", rows=None):
    nid = g.add(account, "eu-frankfurt", "cos.bucket", "docs-12345", "Documentation")
    node = g.nodes[nid]
    acl(
        g,
        node,
        dict(
            Owner=dict(ID=f"qcs::cam::uin/{account}:uin/{account}"),
            AccessControlList=dict(Grant=[]),
        ),
        "offline-fixture",
    )
    if rows:
        policy(
            g, node, dict(Policy=json.dumps(dict(version="2.0", statement=rows))), "offline-fixture"
        )
    else:
        node["properties"].update(policy_absent=True, policy_collected=True)
    return nid


def fixture(identity=None, resource=None, owner="100", boundary=True):
    g = Graph(mode="demo")
    g.accounts = {"100": dict(id="100", display="Offline fixture", name="Offline fixture")}
    uid = principal(g, rows=[statement()] if identity is None else identity, boundary=boundary)
    bid = bucket(g, owner, resource)
    return g, uid, bid


def trust(g, role, rows):
    add_document(
        g,
        role,
        parse_document(json.dumps(dict(version="2.0", statement=rows)), trust=True),
        "offline-fixture",
        trust=True,
    )
    g.coverage.append(
        dict(
            account=g.nodes[role]["account"],
            region="global",
            service="cam",
            action="GetRole",
            detail=g.nodes[role]["resource_id"],
            status="complete",
            count=1,
            request_ids=[],
        )
    )
