import json

import pytest

from tencent_cloud_cartography.catalog import ALLOWED_ACTIONS, SCF_FUNCTIONS
from tencent_cloud_cartography.collect import CollectorRunner, collect
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.scf import (
    alias,
    collect_function,
    layer_version,
    link_trigger_sources,
    trigger,
    version,
)
from tencent_cloud_cartography.topology import topology
from tencent_cloud_cartography.transport import CollectionError


def function(g, namespace="default", owner="100", region="eu-frankfurt"):
    raw = dict(FunctionName="handler", Namespace=namespace, FunctionId=namespace + "/handler")
    nid = g.native(owner, region, SCF_FUNCTIONS, raw, "fixture")
    return g.nodes[nid]


def test_aliases_versions_and_triggers_preserve_scope_and_configuration():
    g = Graph()
    for fn in (
        function(g),
        function(g, "other"),
        function(g, owner="200"),
        function(g, region="ap-guangzhou"),
    ):
        version(g, fn, dict(Version="1", Status="Active"), "fixture")
        aid = alias(
            g,
            fn,
            dict(
                Name="prod",
                FunctionVersion="1",
                RoutingConfig=dict(
                    AdditionalVersionWeights=[dict(Version="2", Weight=0)],
                    AddtionVersionMatchs=[
                        dict(
                            Version="3",
                            Key="invoke.headers.User",
                            Method="exact",
                            Expression="canary",
                        )
                    ],
                ),
            ),
            "fixture",
        )
        tid = trigger(
            g,
            fn,
            dict(
                TriggerName="schedule",
                Type="timer",
                Qualifier="prod",
                Enable=0,
                TriggerDesc="0 */5 * * * * *",
                CustomArgument="PRIVATE_PAYLOAD",
            ),
            "fixture",
        )
        assert g.nodes[tid]["properties"]["state"] == "disabled"
        assert json.loads(g.nodes[aid]["properties"]["weighted_versions"])[0]["Weight"] == 0
    assert len([n for n in g.nodes.values() if n["kind"] == "scf.alias"]) == 4
    assert len([n for n in g.nodes.values() if n["kind"] == "scf.version"]) == 12
    assert "PRIVATE_PAYLOAD" not in g.dump()
    assert all(icon_for(n["kind"]) != "unmapped.svg" for n in g.nodes.values())
    assert topology(g.snapshot())["stats"]["resources"] == 4
    assert (
        len([e for e in g.edges.values() if e["relationship"] == "CONFIGURED_TRIGGER_TARGET"]) == 4
    )


@pytest.mark.parametrize("weight", [float("nan"), float("inf"), -0.1, 1.1, True, "0.5"])
def test_invalid_alias_weights_create_no_partial_alias(weight):
    g = Graph()
    fn = function(g)
    with pytest.raises(CollectionError):
        alias(
            g,
            fn,
            dict(
                Name="prod",
                FunctionVersion="1",
                RoutingConfig=dict(AdditionalVersionWeights=[dict(Version="2", Weight=weight)]),
            ),
            "fixture",
        )
    assert len(g.nodes) == 1


def test_trigger_targets_distinguish_version_and_alias_and_reused_names():
    g = Graph()
    fn = function(g)
    for qualifier in ("1", "$LATEST", "$DEFAULT", "prod"):
        trigger(
            g,
            fn,
            dict(
                TriggerName="same", Type="timer", Qualifier=qualifier, TriggerDesc="* * * * * * *"
            ),
            "fixture",
        )
    targets = [
        g.nodes[e["target"]]
        for e in g.edges.values()
        if e["relationship"] == "CONFIGURED_TRIGGER_TARGET"
    ]
    assert len(targets) == 4
    assert [n["kind"] for n in targets].count("scf.version") == 2
    assert [n["kind"] for n in targets].count("scf.alias") == 2
    assert all(n["status"] == "reference" for n in targets)


def test_event_sources_match_only_collected_account_region_and_resource():
    g = Graph()
    fn = function(g)
    triggers = [
        dict(
            Type="cos",
            TriggerName="assets-12345.cos.eu-frankfurt.myqcloud.com",
            TriggerDesc=json.dumps(
                dict(event="cos:ObjectCreated:*", filter=dict(Prefix="in/", Suffix=".json"))
            ),
        ),
        dict(
            Type="ckafka",
            TriggerName="ckafka-abc-topic-with-hyphen",
            TriggerDesc=json.dumps(
                dict(maxMsgNum=0, easConfig=dict(userName="SECRET", password="SECRET"))
            ),
        ),
        dict(
            Type="apigw",
            TriggerName="gateway",
            TriggerDesc=json.dumps(dict(service=dict(serviceId="service-one"))),
        ),
    ]
    for raw in triggers:
        trigger(g, fn, {**raw, "Qualifier": "$LATEST"}, "fixture")
    for kind, rid in [
        ("cos.bucket", "assets-12345"),
        ("ckafka.instance", "ckafka-abc"),
        ("apigateway.service", "service-one"),
    ]:
        for owner, region in [
            ("100", "eu-frankfurt"),
            ("200", "eu-frankfurt"),
            ("100", "ap-guangzhou"),
        ]:
            g.add(owner, region, kind, rid)
    link_trigger_sources(g)
    edges = [e for e in g.edges.values() if e["relationship"] == "CONFIGURED_EVENT_SOURCE"]
    assert len(edges) == 3
    assert all(
        g.nodes[e["source"]]["account"] == "100"
        and g.nodes[e["source"]]["region"] == "eu-frankfurt"
        for e in edges
    )
    assert "SECRET" not in g.dump()
    kafka = next(
        n
        for n in g.nodes.values()
        if n["kind"] == "scf.trigger" and n["properties"]["trigger_type"] == "ckafka"
    )
    assert kafka["properties"]["topic_name"] == "topic-with-hyphen"


def test_http_configuration_discards_auth_payloads_url_credentials_and_query_values():
    g = Graph()
    fn = function(g)
    raw = dict(
        AuthType="NONE",
        Token="SECRET",
        NetConfig=dict(
            EnableExtranet=False,
            ExtranetUrl="https://function.example/path?token=SECRET#SECRET",
            IntranetUrl="https://user:SECRET@private.example/",
        ),
    )
    tid = trigger(
        g, fn, dict(TriggerName="url", Type="http", TriggerDesc=json.dumps(raw)), "fixture"
    )
    props = g.nodes[tid]["properties"]
    config = json.loads(props["configuration"])
    assert config == {
        "AuthType": "NONE",
        "NetConfig.EnableExtranet": False,
        "NetConfig.ExtranetUrl": "https://function.example/path",
    }
    assert "SECRET" not in g.dump()
    assert not any(
        "PUBLIC" in e["relationship"] or "ACCESS" in e["relationship"] for e in g.edges.values()
    )


def test_duplicate_trigger_json_fields_rejected_without_trigger():
    g = Graph()
    fn = function(g)
    with pytest.raises(CollectionError) as e:
        trigger(
            g,
            fn,
            dict(TriggerName="x", Type="http", TriggerDesc='{"AuthType":"NONE","AuthType":"CAM"}'),
            "fixture",
        )
    assert e.value.code == "DuplicateTriggerField" and len(g.nodes) == 1


def test_layers_keep_versions_separate_and_do_not_invent_function_usage():
    g = Graph()
    function(g)
    for v in (1, 2):
        layer_version(
            g,
            "100",
            "eu-frankfurt",
            dict(
                LayerName="shared",
                LayerVersion=v,
                CompatibleRuntimes=["Python3.9"],
                LicenseInfo="MIT",
            ),
            "fixture",
        )
    assert len([n for n in g.nodes.values() if n["kind"] == "scf.layerversion"]) == 2
    assert all(
        e["relationship"] == "HAS_VERSION" and g.nodes[e["source"]]["kind"] == "scf.layer"
        for e in g.edges.values()
    )
    before = len(g.nodes)
    with pytest.raises(CollectionError) as e:
        layer_version(
            g,
            "100",
            "eu-frankfurt",
            dict(LayerName="foreign", LayerVersion=3),
            "fixture",
            expected="shared",
        )
    assert e.value.code == "ScfLayerMismatch" and len(g.nodes) == before


def test_function_namespace_mismatch_is_rejected_before_insertion():
    g = Graph()

    class T:
        def call(self, *args, **kwargs):
            return dict(Functions=[dict(FunctionName="handler", Namespace="foreign")], TotalCount=1)

    CollectorRunner(g, T(), "100", [], lambda _: None).native(
        SCF_FUNCTIONS, "eu-frankfurt", {"Namespace": "default"}
    )
    assert not g.nodes and g.coverage[-1]["error"] == "ScfNamespaceMismatch"


def test_paginated_triggers_keep_partial_count_after_duplicate_and_alias_denial():
    g = Graph()
    fn = function(g)
    calls = []

    class T:
        def call(self, service, action, region=None, **params):
            calls.append((action, params))
            assert params["Namespace"] == "default" and params["FunctionName"] == "handler"
            if action == "ListVersionByFunction":
                return dict(Versions=[], TotalCount=0)
            if action == "ListAliases":
                raise CollectionError("UnauthorizedOperation")
            rows = (
                [
                    dict(
                        TriggerName=f"t{i}",
                        Type="timer",
                        Qualifier="$LATEST",
                        TriggerDesc="* * * * * * *",
                    )
                    for i in range(100)
                ]
                if params["Offset"] == 0
                else [
                    dict(
                        TriggerName="t0",
                        Type="timer",
                        Qualifier="$LATEST",
                        TriggerDesc="* * * * * * *",
                    )
                ]
            )
            return dict(Triggers=rows, TotalCount=101, RequestId=str(params["Offset"]))

    collect_function(
        CollectorRunner(g, T(), "100", [], lambda _: None),
        fn["id"],
        dict(FunctionName="handler", Namespace="default"),
    )
    assert g.coverage[1]["status"] == "denied"
    assert g.coverage[2]["error"] == "DuplicateScfResource" and g.coverage[2]["count"] == 100
    assert g.coverage[2]["request_ids"] == ["0", "100"]


def test_end_to_end_function_alias_trigger_layer_collection():
    class T:
        def call(self, service, action, region=None, **params):
            assert (service, action) in ALLOWED_ACTIONS
            if service == "sts":
                return dict(AccountId="100", PrincipalId="reader")
            if service == "cloudrc":
                return dict(Resources=[])
            if action == "ListNamespaces":
                return dict(Namespaces=[dict(Name="default")], TotalCount=1)
            if action == "ListFunctions":
                return dict(
                    Functions=[
                        dict(
                            FunctionName="handler",
                            Runtime="Python3.9",
                            Environment={"secret": "SECRET"},
                        )
                    ],
                    TotalCount=1,
                )
            if action == "ListVersionByFunction":
                return dict(Versions=[dict(Version="1")], TotalCount=1)
            if action == "ListAliases":
                return dict(Aliases=[dict(Name="prod", FunctionVersion="1")], TotalCount=1)
            if action == "ListTriggers":
                return dict(
                    Triggers=[
                        dict(
                            TriggerName="tick",
                            Type="timer",
                            Qualifier="prod",
                            Enable=1,
                            TriggerDesc="0 * * * * * *",
                            CustomArgument="SECRET",
                        )
                    ],
                    TotalCount=1,
                )
            if action == "ListLayers":
                return dict(Layers=[dict(LayerName="shared", LayerVersion=2)], TotalCount=1)
            if action == "ListLayerVersions":
                return dict(
                    LayerVersions=[
                        dict(LayerName="shared", LayerVersion=1),
                        dict(LayerName="shared", LayerVersion=2),
                    ]
                )
            pytest.fail(action)

    data = collect(
        ["test"],
        ["eu-frankfurt"],
        services={"scf"},
        progress=lambda _: None,
        transport_factory=lambda _: T(),
    )
    assert len(data["nodes"]) == 8
    assert "SECRET" not in json.dumps(data)
    assert all(
        c["status"] == "complete"
        for c in data["coverage"]
        if c["service"] == "scf" and c["action"] != "GetFunction"
    )
    assert (
        next(c for c in data["coverage"] if c["action"] == "GetFunction")["status"] == "unsupported"
    )
    assert all(n["status"] == "enriched" for n in data["nodes"])


def test_unknown_trigger_type_retains_identity_without_storing_opaque_configuration():
    g = Graph()
    fn = function(g)
    nid = trigger(
        g,
        fn,
        dict(TriggerName="future-service", Type="future", TriggerDesc="opaque SECRET payload"),
        "fixture",
    )
    assert g.nodes[nid]["properties"]["configuration_supported"] is False
    assert "SECRET" not in g.dump()
    assert len(g.nodes) == 2
