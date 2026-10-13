import json
from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.catalog import COLLECTORS
from tencent_cloud_cartography.collect import CollectorRunner, collect
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.transport import CollectionError

REGION = "eu-frankfurt"
SPECS = {s.kind: s for s in COLLECTORS if s.service in {"cls", "monitor"}}


def add(g, kind, raw, account="100", region=REGION):
    spec = SPECS[kind]
    return g.native(account, region, spec, raw, f"{spec.service}.{spec.action}")


def alarm(i=1, **extra):
    return dict(
        AlarmId=f"alarm-{i}",
        Name=f"alarm-{i}",
        Status=False,
        TriggerCount=3,
        AlarmPeriod=10,
        Condition="count > 0",
        **extra,
    )


def query(number=1, **extra):
    return dict(
        Number=number,
        TopicId=f"topic-{number}",
        LogsetId="logset-1",
        Query="status:500 | select count(*) as count",
        StartTimeOffset=-5,
        EndTimeOffset=0,
        SyntaxRule=1,
        BizType=0,
        **extra,
    )


def runner(g, call):
    return CollectorRunner(g, SimpleNamespace(call=call), "100", [REGION], lambda _: None)


def test_query_schedule_rules_and_reference_enrichment():
    g = Graph()
    nid = add(
        g,
        "cls.alarm",
        alarm(
            AlarmTargets=[query(), query(2)],
            MonitorTime=dict(Type="Cron", CronExpression="*/5 * * * *"),
            MultiConditions=[dict(Condition="count > 10", AlarmLevel=2)],
            GroupTriggerStatus=True,
            GroupTriggerCondition=["service"],
            Classifications=[dict(Key="service", Value="api")],
            AlarmNoticeIds=["notice-1"],
        ),
    )
    topic = add(
        g, "cls.topic", dict(TopicId="topic-1", TopicName="Errors", LogsetId="logset-1", BizType=0)
    )
    notice = add(
        g, "cls.alarmnotice", dict(AlarmNoticeId="notice-1", Name="Operations", Type="All")
    )
    props = g.nodes[nid]["properties"]
    assert props["Status"] is False and props["evaluation_verified"] is False
    assert json.loads(props["schedule"])["CronExpression"] == "*/5 * * * *"
    assert json.loads(props["multi_conditions"])[0]["AlarmLevel"] == 2
    queries = [n for n in g.nodes.values() if n["kind"] == "cls.alarmquery"]
    assert len(queries) == 2
    config = json.loads(queries[0]["properties"]["configuration"])
    assert config["Query"] == query()["Query"] and config["StartTimeOffset"] == -5
    assert g.nodes[topic]["status"] == "enriched" and g.nodes[notice]["status"] == "enriched"
    assert any(e["source"] == nid and e["target"] == notice for e in g.edges.values())
    assert all(icon_for(n["kind"]) != "unmapped.svg" for n in g.nodes.values())


def test_notification_rules_escalation_and_sensitive_fields_are_filtered():
    g = Graph()
    receiver = dict(
        ReceiverType="Uin",
        ReceiverIds=[100, 200],
        ReceiverChannels=["Email"],
        StartTime="09:00:00",
        EndTime="17:00:00",
    )
    callback = dict(
        CallbackType="Http",
        WebCallbackId="callback-1",
        Method="POST",
        NoticeContentId="Default-en",
        Url="https://SENSITIVE_SENTINEL",
        Headers=["SENSITIVE_SENTINEL"],
        Body="SENSITIVE_SENTINEL",
        Mobiles=["SENSITIVE_SENTINEL"],
        PrivateIpAddress="SENSITIVE_SENTINEL",
        InstanceId="ins-SENSITIVE_SENTINEL",
    )
    nid = add(
        g,
        "cls.alarmnotice",
        dict(
            AlarmNoticeId="notice-1",
            Name="Operations",
            Type="All",
            SecureDetailStatus=2,
            AlarmShieldStatus=1,
            DeliverStatus=1,
            DeliverFlag=3,
            CallbackPrioritize=False,
            NoticeReceivers=[receiver],
            WebCallbacks=[callback],
            NoticeRules=[
                dict(
                    Rule='{"Type":"Condition","Value":"Level"}',
                    Escalate=True,
                    Interval=10,
                    NoticeReceivers=[receiver],
                    WebCallbacks=[callback],
                    EscalateNotice=dict(Escalate=False, Interval=20, WebCallbacks=[callback]),
                )
            ],
            AlarmNoticeDeliverConfig=dict(
                DeliverConfig=dict(Region="ap-guangzhou", TopicId="delivery-topic", Scope=1),
                ErrMsg="SENSITIVE_SENTINEL",
            ),
        ),
    )
    props = g.nodes[nid]["properties"]
    assert props["delivery_verified"] is False and props["DeliverFlag"] == 3
    assert json.loads(props["receivers"])[0]["receiver_count"] == 2
    assert json.loads(props["callbacks"])[0]["WebCallbackId"] == "callback-1"
    rule = next(n for n in g.nodes.values() if n["kind"] == "cls.noticerule")
    config = json.loads(rule["properties"]["configuration"])
    assert config["EscalateNotice"]["Interval"] == 20
    destination = next(n for n in g.nodes.values() if n["kind"] == "cls.topic")
    assert destination["account"] == "100" and destination["region"] == "ap-guangzhou"
    assert "SENSITIVE_SENTINEL" not in json.dumps(g.snapshot())
    assert not any(n["kind"] == "cvm.instance" for n in g.nodes.values())


def test_alarm_payloads_do_not_create_properties_or_inferred_resources():
    g = Graph()
    nid = add(
        g,
        "cls.alarm",
        alarm(
            CallBack=dict(
                Body="SENSITIVE_SENTINEL",
                Headers=["SENSITIVE_SENTINEL"],
                InstanceId="ins-leak",
                PrivateIpAddress="SENSITIVE_SENTINEL",
            ),
            MessageTemplate="SENSITIVE_SENTINEL",
            AIAnalysis={"Prompt": "SENSITIVE_SENTINEL"},
        ),
    )
    assert len(g.nodes) == 1 and not g.edges
    assert "SENSITIVE_SENTINEL" not in json.dumps(g.nodes[nid])


@pytest.mark.parametrize("account,region", [("200", REGION), ("100", "ap-guangzhou")])
def test_regional_cls_notice_references_do_not_merge_across_scope(account, region):
    g = Graph()
    nid = add(g, "cls.alarm", alarm(AlarmNoticeIds=["notice-1"], AlarmTargets=[query()]))
    other = add(g, "cls.alarmnotice", dict(AlarmNoticeId="notice-1", Name="other"), account, region)
    assert not any(e["source"] == nid and e["target"] == other for e in g.edges.values())
    refs = [
        n for n in g.nodes.values() if n["kind"] == "cls.alarmnotice" and n["status"] == "reference"
    ]
    assert len(refs) == 1 and refs[0]["account"] == "100" and refs[0]["region"] == REGION


def test_monitor_notice_is_global_and_distinct_from_cls_notice():
    g = Graph()
    nid = add(
        g,
        "cls.alarm",
        alarm(
            MonitorNotice=dict(
                Notices=[dict(NoticeId="notice-1", ContentTmplId="tmpl-1", AlarmLevels=[0, 2])]
            ),
            AlarmNoticeIds=["notice-1"],
        ),
    )
    notices = [n for n in g.nodes.values() if n["kind"] in {"cls.alarmnotice", "monitor.notice"}]
    assert {(n["kind"], n["region"]) for n in notices} == {
        ("monitor.notice", "global"),
        ("cls.alarmnotice", REGION),
    }
    bindings = json.loads(g.nodes[nid]["properties"]["monitor_notice_bindings"])
    assert bindings[0]["AlarmLevels"] == [0, 2]
    assert len([e for e in g.edges.values() if e["relationship"] == "USES_ALARM_NOTICE"]) == 2


@pytest.mark.parametrize(
    "kind,result,id_key,prefix",
    [
        ("cls.alarm", "Alarms", "AlarmId", "alarm"),
        ("cls.alarmnotice", "AlarmNotices", "AlarmNoticeId", "notice"),
    ],
)
def test_pagination_and_duplicate_controls(kind, result, id_key, prefix):
    g, offsets = Graph(), []

    def call(*a, **kw):
        offset = kw["Offset"]
        offsets.append(offset)
        rows = [
            {id_key: f"{prefix}-{i}", "Name": str(i)} for i in range(offset, min(101, offset + 100))
        ]
        return {result: rows, "TotalCount": 101, "RequestId": str(offset)}

    runner(g, call).native(SPECS[kind], REGION)
    assert offsets == [0, 100] and g.coverage[-1]["count"] == 101
    assert g.coverage[-1]["request_ids"] == ["0", "100"]
    runner(g, lambda *a, **kw: {result: [{id_key: prefix + "-1"}] * 2, "TotalCount": 2}).native(
        SPECS[kind], REGION
    )
    assert g.coverage[-1]["error"] == "DuplicateClsAlarmIdentity"


@pytest.mark.parametrize(
    "data,error",
    [
        (alarm(AlarmTargets=[{**query(), "Number": True}]), "InvalidClsAlarmQueryNumber"),
        (alarm(AlarmTargets=[query(), query()]), "InvalidClsAlarmQueryNumber"),
        (alarm(AlarmTargets={}), "InvalidClsAlarmConfiguration"),
        (
            alarm(MonitorNotice={"Notices": [{"NoticeId": "notice-1", "AlarmLevels": [True]}]}),
            "InvalidClsAlarmLevel",
        ),
        ({**alarm(), "AlarmId": 123}, "InvalidClsAlarmIdentity"),
    ],
)
def test_invalid_alarm_configuration_is_partial(data, error):
    g = Graph()
    runner(g, lambda *a, **kw: dict(Alarms=[data], TotalCount=1)).native(SPECS["cls.alarm"], REGION)
    assert g.coverage[-1]["status"] == "error" and g.coverage[-1]["error"] == error


def test_invalid_delivery_region_and_escalation_depth():
    for extra, error in [
        (
            dict(
                AlarmNoticeDeliverConfig={
                    "DeliverConfig": {"TopicId": "topic-1", "Region": "global"}
                }
            ),
            "InvalidClsDeliveryRegion",
        ),
        (
            dict(
                NoticeRules=[
                    {
                        "EscalateNotice": {
                            "EscalateNotice": {
                                "EscalateNotice": {
                                    "EscalateNotice": {"EscalateNotice": {"EscalateNotice": {}}}
                                }
                            }
                        }
                    }
                ]
            ),
            "InvalidEscalationDepth",
        ),
    ]:
        g = Graph()
        row = dict(AlarmNoticeId="notice-1", **extra)
        runner(g, lambda *a, **kw: dict(AlarmNotices=[row], TotalCount=1)).native(
            SPECS["cls.alarmnotice"], REGION
        )
        assert g.coverage[-1]["error"] == error


def test_cls_selected_regions_and_independent_denial():
    class Transport:
        def call(self, service, action, region=None, **params):
            if service == "sts":
                return dict(AccountId="100", PrincipalId="reader")
            if service == "cloudrc":
                return dict(Resources=[])
            if action == "DescribeAlarms":
                if region == "ap-guangzhou":
                    raise CollectionError("UnauthorizedOperation")
                return dict(Alarms=[alarm(AlarmNoticeIds=["notice-1"])], TotalCount=1)
            if action == "DescribeAlarmNotices":
                return dict(
                    AlarmNotices=[dict(AlarmNoticeId="notice-1", Name=region)], TotalCount=1
                )
            spec = next(s for s in SPECS.values() if s.action == action and s.service == service)
            return {spec.result: [], "TotalCount": 0}

    data = collect(
        ["test"],
        [REGION, "ap-guangzhou"],
        services={"cls"},
        progress=lambda _: None,
        transport_factory=lambda _: Transport(),
    )
    scopes = [c for c in data["coverage"] if c["action"] == "DescribeAlarms"]
    assert [c["status"] for c in scopes] == ["complete", "denied"]
    assert len([n for n in data["nodes"] if n["kind"] == "cls.alarmnotice"]) == 2
    assert all(n["status"] == "enriched" for n in data["nodes"])
