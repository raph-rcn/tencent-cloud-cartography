"""Current-context authorization metadata, without reading objects or running exec."""

import json

from .collect import CollectorRunner
from .model import stable_id
from .transport import CollectionError


def identity(data):
    info = data.get("status", {}).get("userInfo")
    if not isinstance(info, dict):
        raise CollectionError("InvalidKubernetesIdentity")
    username, uid, groups = info.get("username"), info.get("uid", ""), info.get("groups", [])
    if (
        not isinstance(username, str)
        or not username
        or not isinstance(uid, str)
        or not isinstance(groups, list)
        or not all(isinstance(v, str) and v for v in groups)
        or any(ord(c) < 32 for v in [username, uid, *groups] for c in v)
    ):
        raise CollectionError("InvalidKubernetesIdentity")
    return dict(username=username, uid=uid, groups=sorted(set(groups)))


def collect(graph, cluster, context, transport):
    runner = CollectorRunner(graph, None, cluster["account"], [cluster["region"]], lambda _: None)
    expected = None
    pods = [
        n
        for n in graph.nodes.values()
        if n["kind"] == "tke.pod"
        and n["status"] == "enriched"
        and n["account"] == cluster["account"]
        and n["region"] == cluster["region"]
        and n["properties"].get("cluster_id") == cluster["resource_id"]
    ]
    for pod in pods:

        def operation(record, pod=pod):
            nonlocal expected
            before = identity(transport.review("SelfSubjectReview"))
            if expected is not None and expected != before:
                raise CollectionError("KubernetesIdentityChanged")
            namespace = pod["properties"]["namespace"]
            response = transport.review("SelfSubjectAccessReview", namespace, pod["name"])
            after = identity(transport.review("SelfSubjectReview"))
            if before != after:
                raise CollectionError("KubernetesIdentityChanged")
            expected = before
            status = response.get("status")
            if (
                not isinstance(status, dict)
                or type(status.get("allowed")) is not bool
                or type(status.get("denied", False)) is not bool
                or (status["allowed"] and status.get("denied"))
                or status.get("evaluationError")
            ):
                raise CollectionError("IncompleteKubernetesAuthorization")
            actor = graph.add(
                cluster["account"],
                cluster["region"],
                "tke.kubernetesprincipal",
                stable_id(cluster["resource_id"], context, before),
                before["username"],
                source="kubernetes.SelfSubjectReview",
            )
            graph.nodes[actor]["properties"].update(
                before,
                cluster_id=cluster["resource_id"],
                context=context,
                cam_principal_resolved=False,
                uid_available=bool(before["uid"]),
            )
            graph.nodes[actor]["properties"]["groups"] = json.dumps(before["groups"])
            graph.edge(
                cluster["id"], actor, "HAS_REVIEWED_PRINCIPAL", "kubernetes.SelfSubjectReview"
            )
            did = graph.add(
                cluster["account"],
                cluster["region"],
                "tke.authorizationdecision",
                stable_id(actor, pod["id"], "pods/exec:create"),
                "Pod exec authorization: " + ("allowed" if status["allowed"] else "not allowed"),
                source="kubernetes.SelfSubjectAccessReview",
            )
            graph.nodes[did]["properties"].update(
                allowed=status["allowed"],
                denied=status.get("denied", False),
                verb="create",
                resource="pods",
                subresource="exec",
                namespace=namespace,
                pod_name=pod["name"],
                authorization_review_verified=True,
                identity_before_after_matched=True,
                identity_comparison_scope="username_uid_groups",
                session_or_token_identity_verified=False,
                effective_execution_verified=False,
                evaluation_scope="current_authenticated_kubernetes_context",
            )
            graph.edge(
                actor, did, "HAS_AUTHORIZATION_ANALYSIS", "kubernetes.SelfSubjectAccessReview"
            )
            graph.edge(did, pod["id"], "TARGETS_RESOURCE", "kubernetes.SelfSubjectAccessReview")
            record["count"] = 1

        runner.scope(
            "kubernetes",
            "ReviewPodExecAuthorization",
            cluster["region"],
            operation,
            pod["resource_id"],
        )
