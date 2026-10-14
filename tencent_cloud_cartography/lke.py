"""LKE application, available-model and shared-knowledge metadata; no prompts/docs."""

import json

from .catalog import Collector
from .transport import CollectionError, pages
from .vpc import fields

APPS = Collector(
    "lke",
    "ListApp",
    "List",
    "lke.application",
    ("AppBizId",),
    ("Name",),
    total="Total",
    paging="number-page",
    require_total=True,
)
MODELS = Collector(
    "lke", "ListModel", "List", "lke.model", ("ModelName",), total=None, paging="none"
)
KNOWLEDGE = Collector(
    "lke",
    "ListSharedKnowledge",
    "KnowledgeList",
    "lke.knowledgebase",
    ("KnowledgeBizId",),
    ("KnowledgeName",),
    total="Total",
    paging="number-page",
    require_total=True,
)


class MetadataTransport:
    def __init__(self, transport):
        self.transport = transport

    def call(self, service, action, region=None, **params):
        data = self.transport.call(service, action, region, **params)
        if action == "ListApp":
            total = data.get("Total")
            if isinstance(total, str) and total.isdecimal():
                data = {**data, "Total": int(total)}
        return data


def collect(runner, region):
    graph = runner.graph

    def inventory(spec, params):
        def operation(record):
            seen = set()
            for batch, request in pages(MetadataTransport(runner.transport), spec, region, params):
                if request:
                    record["request_ids"].append(request)
                prepared = []
                for raw in batch:
                    links = []
                    if spec.kind == "lke.application":
                        props = fields(
                            raw,
                            (
                                "AppBizId",
                                "Name",
                                "AppType",
                                "AppTypeDesc",
                                "Desc",
                                "AppStatusDesc",
                                "UpdateTime",
                                "ModelName",
                                "ModelAliasName",
                                "Pattern",
                                "ThoughtModelAliasName",
                            ),
                            integers=("AppStatus",),
                        )
                        rid = props.get("AppBizId")
                    elif spec.kind == "lke.model":
                        props = fields(
                            raw,
                            (
                                "ModelName",
                                "ModelDesc",
                                "AliasName",
                                "PromptWordsLimit",
                                "Source",
                                "ModelCategory",
                                "ProviderName",
                                "ProviderAliasName",
                                "ProviderType",
                            ),
                            (
                                "IsFree",
                                "IsDefault",
                                "IsExclusive",
                                "IsCloseModelParams",
                                "IsDeepThinking",
                            ),
                            (
                                "ResourceStatus",
                                "InputLenLimit",
                                "SupportWorkflowStatus",
                                "RoleLenLimit",
                                "Concurrency",
                            ),
                        )
                        if not props.get("ModelName"):
                            raise CollectionError("InvalidLkeModel")
                        category = params["ModelCategory"]
                        props["query_category"] = category
                        rid = category + "/" + props["ModelName"]
                    else:
                        metadata = raw.get("Knowledge")
                        if not isinstance(metadata, dict):
                            raise CollectionError("InvalidLkeKnowledge")
                        props = fields(
                            metadata,
                            (
                                "KnowledgeBizId",
                                "KnowledgeName",
                                "KnowledgeDescription",
                                "EmbeddingModel",
                                "QaExtractModel",
                                "UpdateTime",
                                "OwnerStaffId",
                            ),
                            integers=("KnowledgeType", "DocTotal"),
                        )
                        rid = props.get("KnowledgeBizId")
                        apps = raw.get("AppList")
                        if not isinstance(apps, list):
                            raise CollectionError("InvalidLkeKnowledgeApplications")
                        links = [fields(a, ("AppBizId", "AppName")) for a in apps]
                        if any(not a.get("AppBizId") for a in links):
                            raise CollectionError("InvalidLkeKnowledgeApplications")
                    if (
                        not isinstance(rid, str)
                        or not rid
                        or any(ord(c) < 32 for c in rid)
                        or rid in seen
                    ):
                        raise CollectionError("InvalidOrDuplicateLkeIdentity")
                    seen.add(rid)
                    prepared.append((rid, props, links))
                for rid, props, links in prepared:
                    nid = graph.add(
                        runner.account,
                        region,
                        spec.kind,
                        rid,
                        props.get("Name") or props.get("KnowledgeName") or props.get("ModelName"),
                        source="lke." + spec.action,
                    )
                    if spec.kind != "lke.model":
                        graph.nodes[nid]["properties"].update(props)
                    if spec.kind == "lke.model":
                        current = graph.nodes[nid]["properties"]
                        views = json.loads(current.get("configuration_views", "{}"))
                        views[json.dumps(params, sort_keys=True)] = props
                        current["configuration_views"] = json.dumps(views, sort_keys=True)
                        current.update(
                            {
                                k: props[k]
                                for k in (
                                    "ModelName",
                                    "AliasName",
                                    "Source",
                                    "ProviderName",
                                    "ProviderAliasName",
                                    "ProviderType",
                                    "query_category",
                                )
                                if k in props
                            }
                        )
                        graph.nodes[nid]["properties"]["catalog_scope"] = (
                            "models_available_for_queried_lke_configuration"
                        )
                    for app in links:
                        target = graph.add(
                            runner.account,
                            region,
                            "lke.application",
                            app["AppBizId"],
                            app.get("AppName"),
                            source="lke." + spec.action,
                            status="reference",
                        )
                        graph.edge(target, nid, "USES_SHARED_KNOWLEDGE_BASE", "lke." + spec.action)
                    record["count"] += 1

        runner.scope("lke", spec.action, region, operation, json.dumps(params, sort_keys=True))

    for app_type in ("knowledge_qa", "summary", "classifys"):
        for agent in ("dialogue", "wechat") if app_type == "knowledge_qa" else (None,):
            inventory(APPS, dict(AppType=app_type, **(dict(AgentType=agent) if agent else {})))
        for pattern in ("standard", "agent", "single_workflow"):
            for category in ("generate", "thought", "embedding", "rerank"):
                inventory(MODELS, dict(AppType=app_type, Pattern=pattern, ModelCategory=category))
    inventory(KNOWLEDGE, {})
    link(graph)


def link(graph):
    models = [
        n for n in graph.nodes.values() if n["kind"] == "lke.model" and n["status"] == "enriched"
    ]
    for node in list(graph.nodes.values()):
        if (
            node["kind"] not in ("lke.application", "lke.knowledgebase")
            or node["status"] != "enriched"
        ):
            continue
        for field, category in (
            ("ModelName", "generate"),
            ("EmbeddingModel", "embedding"),
            ("QaExtractModel", "generate"),
        ):
            value = node["properties"].get(field)
            if not value:
                continue
            targets = [
                m
                for m in models
                if m["account"] == node["account"]
                and m["region"] == node["region"]
                and m["properties"].get("query_category") == category
                and value in (m["properties"].get("ModelName"), m["properties"].get("AliasName"))
            ]
            if len(targets) == 1:
                graph.edge(
                    node["id"], targets[0]["id"], "CONFIGURED_" + field.upper(), "lke.metadata"
                )
