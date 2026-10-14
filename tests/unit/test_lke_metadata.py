import json

from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.lke import collect
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.transport import CollectionError


def test_available_models_app_and_knowledge_links_preserve_query_configuration_views():
    calls = []

    class T:
        def call(self, service, action, region=None, **params):
            calls.append((action, params))
            if action == "ListApp":
                assert params["PageNumber"] == 1 and params["PageSize"] == 10
                return dict(
                    Total="1",
                    List=[
                        dict(
                            AppBizId="app-one",
                            Name="app",
                            AppType=params["AppType"],
                            ModelName="model-one",
                        )
                    ],
                )
            if action == "ListModel":
                return dict(
                    List=[
                        dict(
                            ModelName="model-one",
                            Source="Hunyuan",
                            IsDefault=params["Pattern"] == "standard",
                            ModelCategory=params["ModelCategory"],
                        )
                    ]
                )
            if action == "ListSharedKnowledge":
                return dict(
                    Total=1,
                    KnowledgeList=[
                        dict(
                            Knowledge=dict(
                                KnowledgeBizId="kb-one",
                                KnowledgeName="kb",
                                EmbeddingModel="model-one",
                            ),
                            AppList=[dict(AppBizId="app-one")],
                        )
                    ],
                )
            raise AssertionError(action)

    g = Graph()
    collect(CollectorRunner(g, T(), "100", ["eu-frankfurt"], lambda _: None), "eu-frankfurt")
    assert all(r["status"] == "complete" for r in g.coverage)
    assert len([n for n in g.nodes.values() if n["kind"] == "lke.model"]) == 4
    for model in [n for n in g.nodes.values() if n["kind"] == "lke.model"]:
        assert "IsDefault" not in model["properties"]
        views = json.loads(model["properties"]["configuration_views"])
        assert len(views) == 9 and {v["IsDefault"] for v in views.values()} == {True, False}
    relationships = {e["relationship"] for e in g.edges.values()}
    assert {
        "USES_SHARED_KNOWLEDGE_BASE",
        "CONFIGURED_MODELNAME",
        "CONFIGURED_EMBEDDINGMODEL",
    } <= relationships
    assert {action for action, _ in calls} == {"ListApp", "ListModel", "ListSharedKnowledge"}


def test_one_denied_configuration_does_not_suppress_other_model_scopes():
    class T:
        def call(self, s, a, region=None, **params):
            if a == "ListApp":
                return dict(Total="0", List=[])
            if a == "ListSharedKnowledge":
                return dict(Total=0, KnowledgeList=[])
            if params["Pattern"] == "agent":
                raise CollectionError("UnauthorizedOperation")
            return dict(List=[dict(ModelName="m", Source="Custom")])

    g = Graph()
    collect(CollectorRunner(g, T(), "100", ["eu-frankfurt"], lambda _: None), "eu-frankfurt")
    assert any(r["status"] == "denied" for r in g.coverage)
    assert len([n for n in g.nodes.values() if n["kind"] == "lke.model"]) == 4
    assert all(
        len(json.loads(n["properties"]["configuration_views"])) == 6
        for n in g.nodes.values()
        if n["kind"] == "lke.model"
    )
