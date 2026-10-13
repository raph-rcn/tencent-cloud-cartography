from types import SimpleNamespace

import pytest

from tencent_cloud_cartography.catalog import ALLOWED_ACTIONS
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.icons import icon_for
from tencent_cloud_cartography.image_snapshots import SPECS, collect_in_use, collect_owned
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.transport import CollectionError

REGION = "eu-frankfurt"


def image(i="img-test", type="PRIVATE_IMAGE"):
    return dict(
        ImageId=i,
        ImageType=type,
        ImageName="Image",
        Architecture="arm",
        ImageState="NORMAL",
        IsSupportCloudinit=False,
        ImageDeprecated=False,
        SnapshotSet=[dict(SnapshotId="snap-test")],
    )


def snapshot(i="snap-test", type="PRIVATE_SNAPSHOT"):
    return dict(
        SnapshotId=i,
        SnapshotType=type,
        SnapshotName="Snapshot",
        SnapshotState="NORMAL",
        DiskId="disk-test",
        Encrypt=True,
        IsPermanent=False,
        DiskSize=20,
        ShareReference=1,
    )


def setup(images=None, snapshots=None, shares=None, lookup=None, mutate=None):
    graph, calls = Graph(), []
    inventories = {"cvm": images or [], "cbs": snapshots or []}

    def call(service, action, **params):
        calls.append((service, action, params))
        assert params["region"] == REGION
        if action.endswith("SharePermission"):
            assert set(params) == {"region", "ImageId" if service == "cvm" else "SnapshotId"}
            result = (
                shares
                if shares is not None
                else dict(
                    SharePermissionSet=[dict(AccountId="200", CreatedTime="2026-10-13T10:00:00Z")]
                )
            )
        else:
            if "Filters" in params:
                assert params["Filters"] == [
                    dict(
                        Name="image-type" if service == "cvm" else "snapshot-type",
                        Values=["PRIVATE_IMAGE" if service == "cvm" else "PRIVATE_SNAPSHOT"],
                    )
                ]
                rows = inventories[service]
            else:
                field = "ImageIds" if service == "cvm" else "SnapshotIds"
                assert len(params[field]) == 1
                rows = (lookup or {}).get(params[field][0], [])
            if isinstance(rows, Exception):
                raise rows
            result = {
                "ImageSet" if service == "cvm" else "SnapshotSet": rows[
                    params["Offset"] : params["Offset"] + params["Limit"]
                ],
                "TotalCount": len(rows),
            }
        if isinstance(result, Exception):
            raise result
        result = {**result, "RequestId": str(len(calls))}
        return mutate(service, action, params, result) if mutate else result

    runner = CollectorRunner(graph, SimpleNamespace(call=call), "100", [REGION], lambda _: None)
    return graph, runner, calls


def test_owned_image_snapshot_shares_and_explicit_recipient_identity():
    g, r, calls = setup([image()], [snapshot()])
    for spec in SPECS.values():
        collect_owned(r, spec, REGION)
    im = next(n for n in g.nodes.values() if n["kind"] == "cvm.image")
    snap = next(n for n in g.nodes.values() if n["kind"] == "cbs.snapshot")
    assert im["properties"]["owned_by_collected_account"]
    assert im["properties"]["IsSupportCloudinit"] is False
    assert snap["properties"]["Encrypt"] is True and snap["properties"]["IsPermanent"] is False
    assert im["properties"]["share_count"] == snap["properties"]["share_count"] == 1
    assert not snap["properties"]["public_access_evaluated"]
    shares = [n for n in g.nodes.values() if n["kind"].endswith("share")]
    assert len(shares) == 2 and all(n["account"] == "100" and n["region"] == REGION for n in shares)
    recipient = next(n for n in g.nodes.values() if n["kind"] == "cam.rootprincipal")
    assert (
        recipient["account"] == recipient["resource_id"] == "200"
        and recipient["region"] == "global"
    )
    assert all(n["properties"]["access_verified"] is False for n in shares)
    assert {e["relationship"] for e in g.edges.values()} == {
        "USES_SNAPSHOT",
        "SNAPSHOT_OF",
        "HAS_SHARE",
        "SHARE_RECIPIENT",
    }
    assert all(icon_for(n["kind"]) for n in g.nodes.values())
    assert len(calls) == 4


def test_in_use_public_and_shared_resources_never_get_owner_disk_or_share_edges():
    g, r, calls = setup(
        lookup={
            "img-public": [image("img-public", "PUBLIC_IMAGE")],
            "snap-shared": [snapshot("snap-shared", "SHARED_SNAPSHOT")],
        }
    )
    for kind, rid in [("cvm.image", "img-public"), ("cbs.snapshot", "snap-shared")]:
        g.add("100", REGION, kind, rid, status="reference")
    collect_in_use(r)
    assert len(g.nodes) == 2 and not g.edges
    assert all(
        n["status"] == "enriched" and not n["properties"]["owned_by_collected_account"]
        for n in g.nodes.values()
    )
    assert all(not a.endswith("SharePermission") for _, a, _ in calls)
    assert all("Filters" not in p for _, _, p in calls)


def test_owned_in_use_image_resolves_its_backing_snapshot_in_second_pass():
    g, r, calls = setup(
        lookup={"img-test": [image()], "snap-test": [snapshot()]}, shares={"SharePermissionSet": []}
    )
    g.add("100", REGION, "cvm.image", "img-test", status="reference")
    collect_in_use(r)
    assert [n["status"] for n in g.nodes.values() if n["kind"] == "cbs.snapshot"] == ["enriched"]
    assert len(calls) == 4


def test_in_use_failures_are_isolated_and_empty_is_not_enriched():
    g, r, _ = setup(
        lookup={
            "img-denied": CollectionError("UnauthorizedOperation"),
            "img-ok": [image("img-ok", "PUBLIC_IMAGE")],
        }
    )
    for rid in ["img-denied", "img-missing", "img-ok"]:
        g.add("100", REGION, "cvm.image", rid, status="reference")
    collect_in_use(r)
    assert [c["status"] for c in g.coverage] == ["denied", "error", "complete"]
    assert [n["status"] for n in g.nodes.values()] == ["reference", "reference", "enriched"]


def test_in_use_scope_excludes_other_account_region_and_service():
    g, r, calls = setup()
    g.add("200", REGION, "cvm.image", "img-other", status="reference")
    g.add("100", "ap-guangzhou", "cvm.image", "img-away", status="reference")
    g.add("100", REGION, "cbs.snapshot", "snap-excluded", status="reference")
    collect_in_use(r, {"cvm"})
    assert not calls


@pytest.mark.parametrize(
    "shares,error",
    [
        ({}, "InvalidSharePermissions"),
        ({"SharePermissionSet": None}, "InvalidSharePermissions"),
        ({"SharePermissionSet": [{"AccountId": 200}]}, "InvalidShareRecipient"),
        ({"SharePermissionSet": [{"AccountId": "*"}]}, "InvalidShareRecipient"),
        (
            {"SharePermissionSet": [{"AccountId": "200"}, {"AccountId": "200"}]},
            "DuplicateShareRecipient",
        ),
        ({"SharePermissionSet": [{"AccountId": "200", "CreatedTime": 42}]}, "InvalidShareTime"),
        ({"ImageId": "img-wrong", "SharePermissionSet": []}, "ShareResourceMismatch"),
    ],
)
def test_bad_sharing_response_preserves_image_but_adds_no_share_nodes(shares, error):
    g, r, _ = setup([image()], shares=shares)
    collect_owned(r, SPECS["cvm.image"], REGION)
    assert g.coverage[-1]["error"] == error
    assert not any(n["kind"].endswith("share") for n in g.nodes.values())
    im = next(n for n in g.nodes.values() if n["kind"] == "cvm.image")
    assert "share_count" not in im["properties"]


def test_empty_share_list_is_not_public_access_evidence():
    g, r, _ = setup([image()], shares={"SharePermissionSet": []})
    collect_owned(r, SPECS["cvm.image"], REGION)
    p = next(n["properties"] for n in g.nodes.values() if n["kind"] == "cvm.image")
    assert p["share_count"] == 0 and p["sharing_metadata_collected"]
    assert p["public_access_evaluated"] is False and "Public" not in p


@pytest.mark.parametrize(
    "field,value",
    [
        ("ImageId", "bad"),
        ("ImageType", "SHARED_IMAGE"),
        ("ImageDeprecated", 0),
        ("ImageSize", True),
        ("SnapshotSet", [{"SnapshotId": "bad"}]),
    ],
)
def test_invalid_owned_page_has_no_nodes(field, value):
    item = image()
    item[field] = value
    g, r, _ = setup([item])
    collect_owned(r, SPECS["cvm.image"], REGION)
    assert not g.nodes and g.coverage[0]["status"] == "error"


def test_duplicate_inventory_and_missing_total_fail():
    for mutate, rows in [
        (None, [image(), image()]),
        (lambda s, a, p, r: {**r, "TotalCount": None}, [image()]),
    ]:
        g, r, _ = setup(rows, mutate=mutate)
        collect_owned(r, SPECS["cvm.image"], REGION)
        assert not g.nodes and g.coverage[0]["status"] == "error"


def test_lookup_rejects_different_image_id():
    g, r, _ = setup(lookup={"img-requested": [image("img-wrong")]})
    g.add("100", REGION, "cvm.image", "img-requested", status="reference")
    collect_in_use(r)
    assert g.coverage[0]["error"] == "InUseResourceUnavailable"
    assert len(g.nodes) == 1 and next(iter(g.nodes.values()))["status"] == "reference"


def test_inventory_pagination_and_no_mutations_in_allowlist():
    g, r, calls = setup([image(f"img-{i}") for i in range(101)], shares={"SharePermissionSet": []})
    collect_owned(r, SPECS["cvm.image"], REGION)
    assert [p["Offset"] for _, a, p in calls if a == "DescribeImages"] == [0, 100]
    assert g.coverage[0]["count"] == 101
    assert ("cvm", "DescribeImageSharePermission") in ALLOWED_ACTIONS
    assert ("cbs", "DescribeSnapshotSharePermission") in ALLOWED_ACTIONS
    assert ("cvm", "ModifyImageSharePermission") not in ALLOWED_ACTIONS
    assert ("cbs", "ModifySnapshotsSharePermission") not in ALLOWED_ACTIONS


def test_in_use_inventory_only_resource_is_resolved_without_scanning_unreferenced_inventory():
    g, r, calls = setup(lookup={"img-test": [image("img-test", "PUBLIC_IMAGE")]})
    source = g.add("100", REGION, "cvm.instance", "ins-test")
    target = g.add("100", REGION, "cvm.image", "img-test", status="inventory-only")
    unused = g.add("100", REGION, "cvm.image", "img-unused", status="inventory-only")
    g.edge(source, target, "USES_IMAGE", "cvm.DescribeInstances")
    collect_in_use(r)
    assert len(calls) == 1 and g.nodes[target]["status"] == "enriched"
    assert g.nodes[unused]["status"] == "inventory-only"
