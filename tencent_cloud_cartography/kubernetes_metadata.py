"""Workload Table summaries and RBAC policy metadata; no workload bodies or secrets."""

import io
import json
import logging
import re
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from urllib.parse import quote, urlencode

from .collect import CollectorRunner
from .transport import CollectionError

ACCEPT = "application/json;as=Table;g=meta.k8s.io;v=v1"
RESOURCES = {
    "pods": ("/api/v1", "tke.pod"),
    "services": ("/api/v1", "tke.service"),
    "deployments": ("/apis/apps/v1", "tke.deployment"),
    "replicasets": ("/apis/apps/v1", "tke.replicaset"),
    "statefulsets": ("/apis/apps/v1", "tke.statefulset"),
    "daemonsets": ("/apis/apps/v1", "tke.daemonset"),
    "jobs": ("/apis/batch/v1", "tke.job"),
    "cronjobs": ("/apis/batch/v1", "tke.cronjob"),
}
COLUMNS = {
    "Node",
    "Name",
    "Status",
    "Ready",
    "Restarts",
    "Age",
    "Version",
    "Internal-IP",
    "External-IP",
    "OS-Image",
    "Kernel-Version",
    "Container-Runtime",
    "Roles",
    "Type",
    "Cluster-IP",
    "External-IP",
    "Port(s)",
    "Up-to-date",
    "Available",
    "Desired",
    "Current",
    "Number Ready",
    "Successful",
    "Active",
    "Schedule",
    "Suspend",
    "Last Schedule",
    "Containers",
    "Images",
    "Selector",
}


def name(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value):
        raise CollectionError("InvalidKubernetesName")
    return value


@contextmanager
def quiet_credentials():
    # Kubeconfig exec plugins and refresh hooks may print credential material on
    # failure. Collection is synchronous; suppress output only during credential
    # handling and restore the caller's logging setting immediately afterwards.
    previous = logging.root.manager.disable
    try:
        logging.disable(max(previous, logging.CRITICAL))
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            yield
    finally:
        logging.disable(previous)


class TableTransport:
    def __init__(self, context, endpoints):
        from kubernetes import client, config

        from .tke import endpoint

        configuration = client.Configuration()
        try:
            with quiet_credentials():
                config.load_kube_config(
                    context=context, client_configuration=configuration, persist_config=False
                )
            if not configuration.verify_ssl or endpoint(configuration.host) not in {
                endpoint(value) for value in endpoints
            }:
                raise CollectionError("KubernetesEndpointMismatch")
            self.client = client.ApiClient(configuration)
            self.host = configuration.host.rstrip("/")
        except CollectionError:
            raise
        except Exception:
            # Client exceptions may embed credential/exec output; never propagate it.
            raise CollectionError("InvalidKubernetesContext") from None

    def table(self, path, cursor=""):
        allowed = {"/api/v1/namespaces", "/api/v1/nodes"}
        valid = path in allowed or any(
            re.fullmatch(re.escape(prefix) + r"/namespaces/[a-z0-9][a-z0-9.-]*/" + resource, path)
            for resource, (prefix, _) in RESOURCES.items()
        )
        if not valid:
            raise CollectionError("BlockedKubernetesPath")
        params = {"includeObject": "None", "limit": "200"}
        if cursor:
            params["continue"] = cursor
        headers = {"Accept": ACCEPT}
        try:
            with quiet_credentials():
                self.client.update_params_for_auth(headers, [], ["BearerToken"], path, "GET", None)
            response = self.client.rest_client.pool_manager.request(
                "GET",
                self.host + path + "?" + urlencode(params),
                headers=headers,
                redirect=False,
                retries=False,
                preload_content=False,
                timeout=30,
            )
            try:
                if response.status != 200:
                    code = (
                        "UnauthorizedOperation"
                        if response.status in (401, 403)
                        else "UnsupportedKubernetesTable"
                        if response.status in (404, 406)
                        else "KubernetesApiError"
                    )
                    raise CollectionError(code)
                raw = response.read(10_000_001)
                if len(raw) > 10_000_000:
                    raise CollectionError("KubernetesTableTooLarge")
                result = json.loads(raw)
                if (
                    not isinstance(result, dict)
                    or result.get("kind") != "Table"
                    or result.get("apiVersion") != "meta.k8s.io/v1"
                ):
                    raise CollectionError("UnsupportedKubernetesProjection")
                return result
            finally:
                response.release_conn()
        except CollectionError:
            raise
        except Exception:
            raise CollectionError("KubernetesMetadataReadFailed") from None

    def rbac(self, path, cursor=""):
        from .kubernetes_rbac import PREFIX, RESOURCES

        if (
            path not in {PREFIX + r for r in RESOURCES}
            or not isinstance(cursor, str)
            or len(cursor) > 65536
        ):
            raise CollectionError("BlockedKubernetesRbacPath")
        headers = {"Accept": "application/json"}
        params = {"limit": "200"}
        if cursor:
            params["continue"] = cursor
        try:
            with quiet_credentials():
                self.client.update_params_for_auth(headers, [], ["BearerToken"], path, "GET", None)
            response = self.client.rest_client.pool_manager.request(
                "GET",
                self.host + path + "?" + urlencode(params),
                headers=headers,
                redirect=False,
                retries=False,
                preload_content=False,
                timeout=30,
            )
            try:
                if response.status != 200:
                    raise CollectionError(
                        "UnauthorizedOperation"
                        if response.status in (401, 403)
                        else "UnsupportedKubernetesRbac"
                        if response.status in (404, 406)
                        else "KubernetesApiError"
                    )
                raw = response.read(10_000_001)
                if len(raw) > 10_000_000:
                    raise CollectionError("KubernetesRbacTooLarge")
                data = json.loads(raw)
                if not isinstance(data, dict):
                    raise CollectionError("InvalidKubernetesRbacList")
                return data
            finally:
                response.close()
                response.release_conn()
        except CollectionError:
            raise
        except Exception:
            raise CollectionError("KubernetesRbacReadFailed") from None

    def review(self, kind, namespace=None, pod=None):
        return review(self, kind, namespace, pod)

    def close(self):
        self.client.close()


def rows(response):
    if response.get("kind") != "Table" or response.get("apiVersion") != "meta.k8s.io/v1":
        raise CollectionError("UnsupportedKubernetesProjection")
    columns = response.get("columnDefinitions")
    items = response.get("rows")
    if not isinstance(columns, list) or not isinstance(items, list):
        raise CollectionError("InvalidKubernetesTable")
    names = [column.get("name") if isinstance(column, dict) else None for column in columns]
    if (
        not all(isinstance(value, str) for value in names)
        or len(set(names)) != len(names)
        or "Name" not in names
    ):
        raise CollectionError("InvalidKubernetesColumns")
    prepared = []
    for row in items:
        if (
            not isinstance(row, dict)
            or row.get("object") not in (None, {})
            or not isinstance(row.get("cells"), list)
            or len(row["cells"]) != len(names)
        ):
            raise CollectionError("UnsupportedKubernetesProjection")
        cells = dict(zip(names, row["cells"], strict=True))
        rid = name(cells.get("Name"))
        props = {
            key: value
            for key, value in cells.items()
            if key in COLUMNS and type(value) in (str, int, bool)
        }
        if any(
            isinstance(value, str) and any(ord(c) < 32 for c in value) for value in props.values()
        ):
            raise CollectionError("InvalidKubernetesColumnValue")
        prepared.append((rid, props))
    metadata = response.get("metadata")
    if not isinstance(metadata, dict):
        raise CollectionError("InvalidKubernetesPagination")
    cursor = metadata.get("continue", "")
    version = metadata.get("resourceVersion", "")
    if not isinstance(cursor, str) or not isinstance(version, str):
        raise CollectionError("InvalidKubernetesPagination")
    return prepared, cursor, version


def collect(graph, cluster, transport):
    runner = CollectorRunner(graph, None, cluster["account"], [cluster["region"]], lambda _: None)
    namespaces = []

    def inventory(path, kind, namespace=None):
        def operation(record):
            cursor = ""
            seen, cursors = set(), set()
            expected = None
            for _ in range(10000):
                prepared, next_cursor, version = rows(transport.table(path, cursor))
                if expected is not None and expected != version:
                    raise CollectionError("KubernetesInventoryChanged")
                expected = version
                ids = [rid for rid, _ in prepared]
                if len(set(ids)) != len(ids) or seen.intersection(ids):
                    raise CollectionError("DuplicateKubernetesResource")
                if next_cursor and next_cursor in cursors:
                    raise CollectionError("KubernetesPaginationStalled")
                seen.update(ids)
                for rid, props in prepared:
                    key = (
                        cluster["resource_id"] + "/" + (namespace + "/" if namespace else "") + rid
                    )
                    nid = graph.add(
                        cluster["account"],
                        cluster["region"],
                        kind,
                        key,
                        rid,
                        source="kubernetes.table",
                    )
                    graph.nodes[nid]["properties"].update(
                        props,
                        cluster_id=cluster["resource_id"],
                        namespace=namespace or "",
                        identity_source="cluster_namespace_kind_name",
                        uid_available=False,
                        projection="Table/includeObject=None",
                    )
                    graph.edge(cluster["id"], nid, "HAS_KUBERNETES_RESOURCE", "kubernetes.table")
                    if namespace:
                        nsid = next(
                            n["id"]
                            for n in graph.nodes.values()
                            if n["kind"] == "tke.namespace"
                            and n["account"] == cluster["account"]
                            and n["region"] == cluster["region"]
                            and n["resource_id"] == cluster["resource_id"] + "/" + namespace
                        )
                        graph.edge(nid, nsid, "IN_NAMESPACE", "kubernetes.table")
                    if kind == "tke.namespace":
                        namespaces.append(rid)
                    record["count"] += 1
                if not next_cursor:
                    return
                cursors.add(next_cursor)
                cursor = next_cursor
            raise CollectionError("KubernetesPageLimit")

        return runner.scope(
            "kubernetes",
            "ListTable",
            cluster["region"],
            operation,
            cluster["resource_id"] + ":" + path,
        )

    inventory("/api/v1/namespaces", "tke.namespace")
    inventory("/api/v1/nodes", "tke.node")
    for namespace in namespaces:
        for resource, (prefix, kind) in RESOURCES.items():
            inventory(
                prefix + "/namespaces/" + quote(namespace, safe="") + "/" + resource,
                kind,
                namespace,
            )


def parse_contexts(values):
    result = {}
    for value in values or []:
        try:
            key, context = value.split("=", 1)
            account, region, cluster = key.split("/")
        except ValueError:
            raise ValueError("Use --kube-context ACCOUNT/REGION/CLUSTER=CONTEXT") from None
        if (
            not account.isdigit()
            or not re.fullmatch(r"[a-z0-9-]+", region)
            or not re.fullmatch(r"cls-[a-z0-9]+", cluster)
            or not context
            or any(ord(c) < 32 for c in context)
            or key in result
        ):
            raise ValueError("Invalid or duplicate Kubernetes context mapping")
        result[key] = context
    return result


def collect_contexts(graph, contexts, transport_factory=None):
    from .model import stable_id

    for cluster in list(graph.nodes.values()):
        if cluster["kind"] != "tke.cluster" or cluster["status"] != "enriched":
            continue
        key = cluster["account"] + "/" + cluster["region"] + "/" + cluster["resource_id"]
        if key not in (contexts or {}):
            runner = CollectorRunner(
                graph, None, cluster["account"], [cluster["region"]], lambda _: None
            )

            def missing(record):
                raise CollectionError("UnsupportedKubernetesContextRequired")

            runner.scope(
                "kubernetes",
                "LoadExplicitContext",
                cluster["region"],
                missing,
                cluster["resource_id"],
            )
    for key, context in (contexts or {}).items():
        account, region, rid = key.split("/")
        node = graph.nodes.get(stable_id(account, region, "tke.cluster", rid))
        runner = CollectorRunner(graph, None, account, [region], lambda _: None)

        def operation(record, node=node, context=context):
            if not node or node["status"] != "enriched":
                raise CollectionError("KubernetesClusterNotCollected")
            endpoints = [
                node["properties"][k]
                for k in ("ClusterExternalEndpoint", "ClusterIntranetEndpoint")
                if node["properties"].get(k)
            ]
            if not node["properties"].get("endpoints_collected") or not endpoints:
                raise CollectionError("KubernetesEndpointNotCollected")
            transport = (transport_factory or TableTransport)(context, endpoints)
            try:
                collect(graph, node, transport)
                from .kubernetes_permissions import collect as collect_permissions

                collect_permissions(graph, node, context, transport)
                from .kubernetes_rbac import collect as collect_rbac

                collect_rbac(graph, node, transport)
            finally:
                transport.close()
            record["count"] = 1

        runner.scope("kubernetes", "LoadExplicitContext", region, operation, rid)
    link(graph)
    containers(graph)


def link(graph):
    """Exact collected node names; no workload ownership guessed from name patterns."""
    nodes = [
        n for n in graph.nodes.values() if n["kind"] == "tke.node" and n["status"] == "enriched"
    ]
    for pod in list(graph.nodes.values()):
        if pod["kind"] != "tke.pod" or pod["status"] != "enriched":
            continue
        candidates = [
            n
            for n in nodes
            if n["account"] == pod["account"]
            and n["region"] == pod["region"]
            and n["properties"].get("cluster_id") == pod["properties"].get("cluster_id")
            and n["name"] == pod["properties"].get("Node")
        ]
        if len(candidates) == 1:
            graph.edge(pod["id"], candidates[0]["id"], "SCHEDULED_ON", "kubernetes.table")


def containers(graph):
    """Container name/image summaries from workload Table columns only."""
    for workload in list(graph.nodes.values()):
        if (
            workload["kind"] not in {kind for _, kind in RESOURCES.values()}
            or workload["status"] != "enriched"
        ):
            continue
        props = workload["properties"]
        if not props.get("Containers") or not props.get("Images"):
            continue
        names = props["Containers"].split(",")
        images = props["Images"].split(",")
        if (
            len(names) != len(images)
            or len(set(names)) != len(names)
            or any(not re.fullmatch(r"[a-z0-9][a-z0-9-]*", n) for n in names)
            or any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9./_:@-]*", i) for i in images)
        ):
            workload["properties"]["container_summary_unresolved"] = True
            continue
        for cname, image in zip(names, images, strict=True):
            nid = graph.add(
                workload["account"],
                workload["region"],
                "tke.container",
                workload["id"] + "/" + cname,
                cname,
                source="kubernetes.table",
            )
            graph.nodes[nid]["properties"].update(
                container_name=cname,
                image_reference=image,
                definition_scope="table_summary",
                full_definition_available=False,
            )
            graph.edge(workload["id"], nid, "HAS_CONTAINER_SUMMARY", "kubernetes.table")
            candidates = []
            for ref in graph.nodes.values():
                if (
                    ref["kind"] != "tcr.imagereference"
                    or ref["status"] != "enriched"
                    or (ref["account"], ref["region"]) != (workload["account"], workload["region"])
                ):
                    continue
                registry = next(
                    (
                        r
                        for r in graph.nodes.values()
                        if r["kind"] == "tcr.instance"
                        and r["account"] == ref["account"]
                        and r["region"] == ref["region"]
                        and r["resource_id"] == ref["properties"].get("RegistryId")
                    ),
                    None,
                )
                if not registry:
                    continue
                suffix = ref["resource_id"].removeprefix(registry["resource_id"] + "/")
                if any(
                    image == host + "/" + suffix
                    for host in (
                        registry["properties"].get("PublicDomain"),
                        registry["properties"].get("InternalEndpoint"),
                    )
                    if host
                ):
                    candidates.append(ref)
            if len(candidates) == 1:
                graph.edge(
                    nid, candidates[0]["id"], "CONFIGURED_IMAGE_REFERENCE", "kubernetes.table"
                )


def review_request(kind, namespace=None, pod=None):
    if kind == "SelfSubjectReview":
        return "/apis/authentication.k8s.io/v1/selfsubjectreviews", dict(
            apiVersion="authentication.k8s.io/v1", kind=kind
        )
    if kind != "SelfSubjectAccessReview":
        raise CollectionError("BlockedKubernetesReview")
    name(namespace)
    name(pod)
    return "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", dict(
        apiVersion="authorization.k8s.io/v1",
        kind=kind,
        spec=dict(
            resourceAttributes=dict(
                group="",
                resource="pods",
                subresource="exec",
                verb="create",
                namespace=namespace,
                name=pod,
            )
        ),
    )


def review(transport, kind, namespace=None, pod=None):
    """Virtual authorization/authentication reviews; never create workload objects."""
    path, body = review_request(kind, namespace, pod)
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    try:
        with quiet_credentials():
            transport.client.update_params_for_auth(
                headers, [], ["BearerToken"], path, "POST", body
            )
        response = transport.client.rest_client.pool_manager.request(
            "POST",
            transport.host + path,
            headers=headers,
            body=json.dumps(body).encode(),
            redirect=False,
            retries=False,
            preload_content=False,
            timeout=30,
        )
        try:
            if response.status not in (200, 201):
                raise CollectionError(
                    "UnauthorizedOperation"
                    if response.status in (401, 403)
                    else "UnsupportedKubernetesReview"
                    if response.status in (404, 405)
                    else "KubernetesReviewError"
                )
            raw = response.read(2_000_001)
            if len(raw) > 2_000_000:
                raise CollectionError("KubernetesReviewTooLarge")
            data = json.loads(raw)
            if (
                not isinstance(data, dict)
                or data.get("kind") != kind
                or data.get("apiVersion") != body["apiVersion"]
            ):
                raise CollectionError("InvalidKubernetesReview")
            if kind == "SelfSubjectAccessReview" and data.get("spec") != body["spec"]:
                raise CollectionError("KubernetesReviewScopeMismatch")
            return data
        finally:
            response.close()
            response.release_conn()
    except CollectionError:
        raise
    except Exception:
        raise CollectionError("KubernetesReviewFailed") from None
