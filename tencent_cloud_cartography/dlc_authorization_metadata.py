"""DLC native users, workgroups and configured data/engine grants; no queries."""

from .catalog import Collector
from .data_metadata import emit, key_for, project, schema
from .model import stable_id
from .transport import CollectionError, pages

ACTIONS = {
    ("dlc", a)
    for a in ("DescribeUsers", "DescribeWorkGroups", "DescribeUserInfo", "DescribeWorkGroupInfo")
}
KINDS = {"dlc.user", "dlc.workgroup", "dlc.accesspolicy", "dlc.membership"}
USER = schema(
    "UserId UserDescription Creator CreateTime UserType UserAlias AccountType", booleans="IsOwner"
)
GROUP = schema("WorkGroupName WorkGroupDescription Creator CreateTime", "WorkGroupId UserNum")
POLICY = schema(
    "Database Catalog Table Operation PolicyType Function View Column DataEngine Source Mode Operator CreateTime SourceName EngineGeneration Model PolicyId",
    "SourceId Id",
    "ReAuth IsAdminPolicy",
)


def inventory(runner, region, kind, account_type=None):
    action, result, selection = (
        ("DescribeUsers", "UserSet", USER)
        if kind == "dlc.user"
        else ("DescribeWorkGroups", "WorkGroupSet", GROUP)
    )
    found = []

    def operation(record):
        params = {"AccountType": account_type} if account_type else {}
        spec = Collector("dlc", action, result, kind, (), require_total=True)
        seen = set()
        for rows, request in pages(runner.transport, spec, region, params):
            prepared = []
            for raw in rows:
                p = project(raw, selection)
                if kind == "dlc.user":
                    if p.get("AccountType") not in (None, account_type):
                        raise CollectionError("DlcAccountNamespaceMismatch")
                    p["AccountType"] = account_type
                    key_for(p, ("UserId",))
                    rid = stable_id(account_type, p["UserId"])
                else:
                    if type(p.get("WorkGroupId")) is not int or p["WorkGroupId"] < 0:
                        raise CollectionError("InvalidDlcWorkGroup")
                    rid = str(p["WorkGroupId"])
                prepared.append((rid, p))
            ids = [rid for rid, _ in prepared]
            if len(set(ids)) != len(ids) or seen.intersection(ids):
                raise CollectionError("DuplicateDlcIdentity")
            seen.update(ids)
            for rid, p in prepared:
                node = emit(runner.graph, runner.account, region, kind, rid, p, "dlc." + action)
                node["properties"].update(
                    query_access_verified=False, identity_namespace="dlc_native"
                )
                found.append(node)
                record["count"] += 1
            if request:
                record["request_ids"].append(request)

    runner.scope("dlc", action, region, operation, account_type or "")
    return found


def details(runner, parent, typ):
    user = parent["kind"] == "dlc.user"
    action = "DescribeUserInfo" if user else "DescribeWorkGroupInfo"
    root = "UserInfo" if user else "WorkGroupInfo"
    data_key = {
        "DataAuth": "DataPolicyInfo",
        "EngineAuth": "EnginePolicyInfo",
        "Group": "WorkGroupInfo",
        "User": "UserInfo",
    }[typ]
    result = (
        "PolicySet" if typ in {"DataAuth", "EngineAuth"} else "WorkGroupSet" if user else "UserSet"
    )
    selection = POLICY if result == "PolicySet" else GROUP if user else USER

    def operation(record):
        params = {"Type": typ}
        if user:
            params.update(
                UserId=parent["properties"]["UserId"],
                AccountType=parent["properties"]["AccountType"],
            )
        else:
            params["WorkGroupId"] = parent["properties"]["WorkGroupId"]

        class ScopedTransport:
            def call(self, service, method, region=None, **query):
                data = runner.transport.call(service, method, region, **query)
                meta = data.get(root)
                key = "UserId" if user else "WorkGroupId"
                if (
                    not isinstance(meta, dict)
                    or meta.get(key) != params[key]
                    or meta.get("Type") != typ
                    or (user and meta.get("AccountType") not in (None, params["AccountType"]))
                ):
                    raise CollectionError("DlcPolicyIdentityMismatch")
                return data

        spec = Collector(
            "dlc",
            action,
            root + "." + data_key + "." + result,
            "dlc.accesspolicy",
            (),
            total=root + "." + data_key + ".TotalCount",
            require_total=True,
        )
        seen = set()
        for rows, request in pages(ScopedTransport(), spec, parent["region"], params):
            selected = [project(raw, selection) for raw in rows]
            for p in selected:
                if result == "PolicySet" and (not p.get("Operation") or not p.get("PolicyType")):
                    raise CollectionError("InvalidDlcPolicy")
                if result == "WorkGroupSet":
                    key_for(p, ("WorkGroupId",))
                if result == "UserSet":
                    key_for(p, ("UserId",))
            ids = [key_for(p, ()) for p in selected]
            if len(set(ids)) != len(ids) or seen.intersection(ids):
                raise CollectionError("DuplicateDlcPolicy")
            seen.update(ids)
            for rid, p in zip(ids, selected, strict=True):
                emit(
                    runner.graph,
                    runner.account,
                    parent["region"],
                    "dlc.accesspolicy" if result == "PolicySet" else "dlc.membership",
                    stable_id(parent["id"], typ, rid),
                    {
                        **p,
                        "configuration_type": typ,
                        "query_access_verified": False,
                        "parent_native_id": str(params["UserId" if user else "WorkGroupId"]),
                    },
                    "dlc." + action,
                    parent,
                    "HAS_CONFIGURED_GRANT" if result == "PolicySet" else "HAS_NATIVE_MEMBERSHIP",
                )
                record["count"] += 1
            if request:
                record["request_ids"].append(request)

    runner.scope("dlc", action, parent["region"], operation, parent["resource_id"] + "/" + typ)


def collect(runner, region):
    users = []
    for account_type in ("TencentAccount", "EntraAccount"):
        users.extend(inventory(runner, region, "dlc.user", account_type))
    groups = inventory(runner, region, "dlc.workgroup")
    for node in [*users, *groups]:
        for typ in ("DataAuth", "EngineAuth", "Group" if node["kind"] == "dlc.user" else "User"):
            details(runner, node, typ)


def link(graph):
    """Declared grants/memberships stay separate from CAM identity and query access."""
    source = "analysis.dlc-authorization-metadata-links"
    graph.edges = {i: e for i, e in graph.edges.items() if e.get("provenance") != source}
    index = {
        (n["account"], n["region"], n["kind"], n["resource_id"]): n
        for n in graph.nodes.values()
        if n["status"] == "enriched"
    }
    engines = {}
    for node in graph.nodes.values():
        if node["kind"] == "dlc.engine" and node["status"] == "enriched":
            name = node["properties"].get("DataEngineName")
            if name:
                engines.setdefault((node["account"], node["region"], name), []).append(node)
    for node in list(graph.nodes.values()):
        p, kind = node["properties"], node["kind"]
        target = None
        if kind == "dlc.membership":
            if p.get("configuration_type") == "Group":
                target = index.get(
                    (node["account"], node["region"], "dlc.workgroup", str(p.get("WorkGroupId")))
                )
            elif p.get("AccountType") in {"TencentAccount", "EntraAccount"} and p.get("UserId"):
                target = index.get(
                    (
                        node["account"],
                        node["region"],
                        "dlc.user",
                        stable_id(p["AccountType"], p["UserId"]),
                    )
                )
            if target:
                graph.edge(node["id"], target["id"], "REFERENCES_NATIVE_MEMBER", source)
        elif kind == "dlc.accesspolicy" and p.get("DataEngine"):
            candidates = engines.get((node["account"], node["region"], p["DataEngine"]), [])
            p["engine_reference_resolution"] = (
                "matched" if len(candidates) == 1 else "ambiguous" if candidates else "unresolved"
            )
            if len(candidates) == 1:
                graph.edge(node["id"], candidates[0]["id"], "REFERENCES_DATA_ENGINE", source)
