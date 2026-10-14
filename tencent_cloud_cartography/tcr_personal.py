"""Owned Personal Edition repositories and tag summaries, never image config."""

import re

from .catalog import Collector
from .tcr import component
from .transport import CollectionError, pages
from .vpc import fields


def hostname(value):
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value)
        or ".." in value
    ):
        raise CollectionError("InvalidPersonalRegistryHost")
    return value


class ScopedTransport:
    def __init__(self, transport, repo=None):
        self.transport, self.repo = transport, repo
        self.server = None

    def call(self, service, action, region=None, **params):
        data = self.transport.call(service, action, region, **params)
        result = data.get("Data")
        if not isinstance(result, dict):
            raise CollectionError("InvalidPersonalRegistryResponse")
        server = hostname(result.get("Server"))
        if self.server is not None and self.server != server:
            raise CollectionError("PersonalRegistryHostChanged")
        if self.repo is not None and result.get("RepoName") != self.repo:
            raise CollectionError("PersonalRepositoryMismatch")
        self.server = server
        return data


def collect(runner, region):
    selected = []
    source = "tcr.DescribeRepositoryOwnerPersonal"
    transport = ScopedTransport(runner.transport)
    spec = Collector(
        "tcr",
        "DescribeRepositoryOwnerPersonal",
        "Data.RepoInfo",
        "tcr.personalrepository",
        ("RepoName",),
        total="Data.TotalCount",
        require_total=True,
    )

    def repositories(record):
        seen = set()
        for batch, request in pages(transport, spec, region):
            if request:
                record["request_ids"].append(request)
            prepared = []
            for raw in batch:
                props = fields(
                    raw,
                    ("RepoName", "RepoType", "Description", "CreationTime", "UpdateTime"),
                    ("IsUserFavor", "IsQcloudOfficial"),
                    ("TagCount", "Public", "FavorCount", "PullCount"),
                )
                name = props.get("RepoName")
                if not isinstance(name, str) or "/" not in name:
                    raise CollectionError("InvalidPersonalRepositoryName")
                name = "/".join(component(part) for part in name.split("/"))
                if name in seen or props.get("Public") not in (None, 0, 1):
                    raise CollectionError("InvalidPersonalRepositoryIdentity")
                seen.add(name)
                prepared.append((name, props))
            for name, props in prepared:
                nid = runner.graph.add(
                    runner.account,
                    region,
                    spec.kind,
                    transport.server + "/" + name,
                    name,
                    source=source,
                )
                runner.graph.nodes[nid]["properties"].update(
                    props,
                    registry_host=transport.server,
                    owned_repository_query=True,
                    anonymous_access_verified=False,
                )
                selected.append(runner.graph.nodes[nid])
                record["count"] += 1

    runner.scope("tcr", spec.action, region, repositories, "owned Personal Edition repositories")
    for repo in selected:
        tags(runner, repo)


def tags(runner, repo):
    name, region = repo["properties"]["RepoName"], repo["region"]
    transport = ScopedTransport(runner.transport, name)
    transport.server = repo["properties"]["registry_host"]
    spec = Collector(
        "tcr",
        "DescribeImagePersonal",
        "Data.TagInfo",
        "tcr.personaltag",
        ("TagName",),
        total="Data.TagCount",
        require_total=True,
    )
    source = "tcr." + spec.action

    def operation(record):
        seen = set()
        for batch, request in pages(transport, spec, region, dict(RepoName=name)):
            if request:
                record["request_ids"].append(request)
            prepared = []
            for raw in batch:
                props = fields(
                    raw,
                    (
                        "TagName",
                        "TagId",
                        "ImageId",
                        "Size",
                        "CreationTime",
                        "Architecture",
                        "DockerVersion",
                        "OS",
                        "UpdateTime",
                        "PushTime",
                        "Kind",
                    ),
                    integers=("SizeByte", "Id"),
                )
                tag = props.get("TagName")
                if (
                    not isinstance(tag, str)
                    or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", tag)
                    or tag in seen
                ):
                    raise CollectionError("InvalidPersonalTagIdentity")
                seen.add(tag)
                prepared.append((tag, props))
            for tag, props in prepared:
                nid = runner.graph.add(
                    runner.account,
                    region,
                    spec.kind,
                    repo["resource_id"] + ":" + tag,
                    name + ":" + tag,
                    source=source,
                )
                runner.graph.nodes[nid]["properties"].update(
                    props,
                    registry_host=transport.server,
                    RepoName=name,
                    content_digest_verified=False,
                )
                runner.graph.edge(repo["id"], nid, "HAS_IMAGE", source)
                record["count"] += 1

    runner.scope("tcr", spec.action, region, operation, repo["resource_id"])
