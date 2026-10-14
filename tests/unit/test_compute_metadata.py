import json

from tencent_cloud_cartography.catalog import COLLECTORS
from tencent_cloud_cartography.model import Graph


def spec(service, action):
    return next(s for s in COLLECTORS if s.service == service and s.action == action)


def test_typed_cvm_network_and_disk_configuration_without_credential_fields():
    g = Graph()
    nid = g.native(
        "100",
        "eu-frankfurt",
        spec("cvm", "DescribeInstances"),
        dict(
            InstanceId="ins-one",
            CPU=4,
            Memory=8,
            InstanceChargeType="PREPAID",
            DisableApiTermination=True,
            PublicIpAddresses=["203.0.113.1"],
            PrivateIpAddresses=["10.0.0.2"],
            InternetAccessible=dict(
                PublicIpAssigned=True,
                InternetMaxBandwidthOut=10,
                InternetChargeType="TRAFFIC_POSTPAID_BY_HOUR",
            ),
            SystemDisk=dict(DiskId="disk-one", DiskSize=50, DiskType="CLOUD_SSD"),
            LoginSettings=dict(Password="OMIT"),
            UserData="OMIT",
        ),
        "cvm.DescribeInstances",
    )
    assert "OMIT" not in g.dump()
    props = g.nodes[nid]["properties"]
    assert props["CPU"] == 4 and props["Memory"] == 8 and props["DisableApiTermination"]
    assert json.loads(props["internet_configuration"])["PublicIpAssigned"]
    disk = next(n for n in g.nodes.values() if n["kind"] == "cbs.disk")
    assert disk["status"] == "reference" and disk["properties"]["disk_role"] == "system"


def test_shared_cbs_attachments_current_members_distinct_from_last_attachment():
    g = Graph()
    nid = g.native(
        "100",
        "eu-frankfurt",
        spec("cbs", "DescribeDisks"),
        dict(
            DiskId="disk-one",
            DiskSize=50,
            Encrypt=True,
            Shareable=True,
            InstanceIdList=["ins-one", "ins-two"],
            LastAttachInsId="ins-old",
            DeleteWithInstance=False,
            DiskBackupCount=0,
        ),
        "cbs.DescribeDisks",
    )
    assert g.nodes[nid]["properties"]["DeleteWithInstance"] is False
    targets = [
        g.nodes[e["target"]]["resource_id"]
        for e in g.edges.values()
        if e["relationship"] == "ATTACHED_TO"
    ]
    assert sorted(targets) == ["ins-one", "ins-two"]
    assert not any(n["resource_id"] == "ins-old" for n in g.nodes.values())
