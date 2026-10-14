import json

import pytest

from tencent_cloud_cartography.catalog import ALLOWED_ACTIONS, EXTRA_COLLECTORS
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.families import collect, run
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.transport import CollectionError


def response(spec, batch):
    data = {}
    for path, value in (
        [(spec.result, batch), (spec.total, len(batch))] if spec.total else [(spec.result, batch)]
    ):
        target = data
        keys = path.split(".")
        for key in keys[:-1]:
            target = target.setdefault(key, {})
        target[keys[-1]] = value
    return data


@pytest.mark.parametrize("spec", EXTRA_COLLECTORS, ids=lambda s: s.kind)
def test_each_family_contract_scope_safe_fields_and_icon(spec):
    identity = "123" if spec.kind.startswith("organization.") else "resource-one"
    raw = {
        spec.ids[0]: int(identity) if spec.kind.startswith("organization.") else identity,
        "Password": "OMIT",
        "Env": {"key": "OMIT"},
        "UserData": "OMIT",
        "InstanceId": "ins-one",
    }
    if spec.names:
        raw[spec.names[0]] = "name"
    # A name can also be the primary key (SAML providers).
    data = response(spec, [raw])

    class Transport:
        def call(self, s, a, region=None, **params):
            assert (s, a) in ALLOWED_ACTIONS
            if spec.paging == "number-page":
                assert params == dict(PageNumber=1, PageSize=10)
            return data

    g = Graph()
    collect(
        CollectorRunner(g, Transport(), "100", ["eu-frankfurt"], lambda _: None),
        spec,
        "eu-frankfurt" if spec.regional else "global",
    )
    assert g.coverage[-1]["status"] == "complete"
    assert "OMIT" not in g.dump()
    node = next(n for n in g.nodes.values() if n["kind"] == spec.kind)
    assert icon_for(node["kind"]) != "unmapped.svg"


@pytest.mark.parametrize("failure", ["duplicate", "missing-total", "denied"])
def test_family_failures_stay_partial_and_do_not_invent_zero_inventory(failure):
    spec = next(s for s in EXTRA_COLLECTORS if s.kind == "ciam.userstore")

    # Non-paginated list without a total must still reject duplicate identifiers.
    class Transport:
        def call(self, *args, **kwargs):
            if failure == "denied":
                raise CollectionError("UnauthorizedOperation")
            if failure == "missing-total":
                return {}
            return response(spec, [dict(UserStoreId="one"), dict(UserStoreId="one")])

    g = Graph()
    collect(
        CollectorRunner(g, Transport(), "100", ["eu-frankfurt"], lambda _: None),
        spec,
        "eu-frankfurt",
    )
    assert g.coverage[-1]["status"] in ("error", "denied")
    assert not g.nodes


def test_ti_registry_summary_excludes_instance_details_and_keeps_capacity_units():
    calls = []

    class Transport:
        def call(self, s, a, region=None, **params):
            calls.append((s, a, params))
            if a == "DescribeBillingResourceGroups":
                assert params["DontShowInstanceSet"] is True
                return dict(
                    ResourceGroupSet=[
                        dict(
                            ResourceGroupId="rg-one",
                            ResourceGroupName="one",
                            FreeInstance=0,
                            TotalInstance=2,
                            UsedResource=dict(Cpu=1000, Memory=1024, Gpu=100),
                        )
                    ],
                    TotalCount=1,
                )
            return dict(NotebookSet=[], TotalCount=0)

    g = Graph()
    run(CollectorRunner(g, Transport(), "100", ["eu-frankfurt"], lambda _: None), {"tione"})
    props = next(n for n in g.nodes.values() if n["kind"] == "tione.resourcegroup")["properties"]
    assert props["FreeInstance"] == 0
    assert json.loads(props["UsedResource"]) == dict(Cpu=1000, Memory=1024, Gpu=100)
    assert all(
        a not in ("DescribeModelServiceGroups", "DescribeTrainingTasks", "DescribeNotebook")
        for _, a, _ in calls
    )


def test_dlc_explicit_engine_generation_type_and_execution_scopes():
    calls = []

    class Transport:
        def call(self, s, a, region=None, **params):
            calls.append(params)
            return dict(DataEngines=[], TotalCount=0)

    g = Graph()
    run(CollectorRunner(g, Transport(), "100", ["eu-frankfurt"], lambda _: None), {"dlc"})
    assert len(calls) == 12
    assert {p["EngineGeneration"] for p in calls} == {"Native", "SuperSQL"}
    assert {p["EngineType"] for p in calls} == {"spark", "presto", "kyuubi"}
    assert {p["EngineExecType"] for p in calls} == {"SQL", "BATCH"}
    assert all(p["ExcludePublicEngine"] is True for p in calls)


def test_wedata_project_workflow_task_ids_scoped_and_no_scripts_read():
    calls = []

    class Transport:
        def call(self, s, a, region=None, **params):
            calls.append((a, params))
            rows = {
                "ListProjects": [dict(ProjectId="one", ProjectName="p")],
                "ListWorkflows": [dict(WorkflowId="wf", WorkflowName="flow")],
                "ListTasks": [
                    dict(TaskId="task", TaskName="job", WorkflowId="wf", TaskTypeId=35, Submit=True)
                ],
            }[a]
            return dict(Data=dict(Items=rows, TotalCount=1))

    g = Graph()
    run(CollectorRunner(g, Transport(), "100", ["eu-frankfurt"], lambda _: None), {"wedata"})
    assert {n["resource_id"] for n in g.nodes.values()} == {"one", "one/wf", "one/task"}
    assert {a for a, _ in calls} == {"ListProjects", "ListWorkflows", "ListTasks"}
    assert all(p.get("ProjectId") == "one" for a, p in calls if a != "ListProjects")


def test_organization_members_do_not_claim_cross_account_inventory():
    spec = next(s for s in EXTRA_COLLECTORS if s.kind == "organization.member")

    class Transport:
        def call(self, *args, **kwargs):
            return dict(Total=1, Items=[dict(MemberUin=200, NodeId=10, Name="member")])

    g = Graph()
    collect(
        CollectorRunner(g, Transport(), "100", ["eu-frankfurt"], lambda _: None), spec, "global"
    )
    assert not g.accounts
    n = next(n for n in g.nodes.values() if n["kind"] == "organization.member")
    assert n["account"] == "100" and n["properties"]["MemberUin"] == 200
    assert not n["properties"]["member_inventory_collected"]


def test_tcaplus_groups_use_only_preidentified_clusters_and_never_password_or_idl_apis():
    from tencent_cloud_cartography.families import tcaplus_groups

    g = Graph()
    g.add("100", "eu-frankfurt", "tcaplusdb.cluster", "123", status="inventory-only")
    calls = []

    class T:
        def call(self, s, a, region=None, **params):
            calls.append((s, a, params))
            assert a == "DescribeTableGroups" and params["ClusterId"] == "123"
            return dict(
                TotalCount=1,
                TableGroups=[dict(TableGroupId="456", TableGroupName="group", TableCount=3)],
            )

    tcaplus_groups(CollectorRunner(g, T(), "100", ["eu-frankfurt"], lambda _: None))
    assert (
        next(n for n in g.nodes.values() if n["kind"] == "tcaplusdb.tablegroup")["resource_id"]
        == "123/456"
    )
    assert len(calls) == 1 and g.coverage[-1]["status"] == "complete"
