import json

import pytest

from tencent_cloud_cartography.catalog import COLLECTORS
from tencent_cloud_cartography.collect import CollectorRunner
from tencent_cloud_cartography.databases import collect, details, prepare
from tencent_cloud_cartography.model import Graph
from tencent_cloud_cartography.permissions import identities
from tencent_cloud_cartography.transport import CollectionError


def spec(service):
    return next(s for s in COLLECTORS if s.service == service)


def test_mysql_replica_region_security_groups_tls_and_kms():
    class Transport:
        def call(self, service, action, region=None, **params):
            if action == "DescribeDBInstances":
                return dict(
                    TotalCount=1,
                    Items=[
                        dict(
                            InstanceId="cdb-one",
                            InstanceName="one",
                            Region=region,
                            Vip="10.0.0.2",
                            Vport=3306,
                            UniqVpcId="vpc-one",
                            UniqSubnetId="subnet-one",
                            MasterInfo=dict(InstanceId="cdb-master", Region="ap-guangzhou"),
                            Password="OMIT",
                        )
                    ],
                )
            if action == "DescribeSSLStatus":
                return dict(Status="ON", Url="https://cert.invalid?key=OMIT")
            if action == "DescribeDBInstanceInfo":
                return dict(
                    InstanceId="cdb-one",
                    Encryption="YES",
                    KeyId="11111111-1111-1111-1111-111111111111",
                    KeyRegion="ap-guangzhou",
                )
            if action == "DescribeDBSecurityGroups":
                return dict(Groups=[dict(SecurityGroupId="sg-one")])
            raise AssertionError(action)

    g = Graph()
    collect(
        CollectorRunner(g, Transport(), "100", ["eu-frankfurt"], lambda _: None),
        spec("cdb"),
        "eu-frankfurt",
    )
    assert "OMIT" not in g.dump()
    assert all(r["status"] == "complete" for r in g.coverage)
    assert any(n["kind"] == "kms.key" and n["region"] == "ap-guangzhou" for n in g.nodes.values())
    assert any(
        e["relationship"] == "REPLICA_OF" and g.nodes[e["target"]]["region"] == "ap-guangzhou"
        for e in g.edges.values()
    )
    db = next(n for n in g.nodes.values() if n["resource_id"] == "cdb-one")
    assert identities(db) == ["qcs::cdb:eu-frankfurt:uin/100:instanceId/cdb-one"]


def test_postgres_public_network_config_no_query_or_tls_cert_download():
    raw = dict(
        DBInstanceId="postgres-one",
        DBInstanceName="one",
        VpcId="vpc-one",
        MasterDBInstanceId="postgres-master",
        DBInstanceNetInfo=[
            dict(
                Address="db.example.test",
                Ip="203.0.113.2",
                Port=5432,
                NetType="public",
                Status="opened",
            )
        ],
        DBEngineConfig="OMIT",
    )
    rid, props, links = prepare(raw, spec("postgres"), "eu-frankfurt")
    assert rid == "postgres-one" and "OMIT" not in json.dumps(props)
    assert "public" in props["configured_endpoints"]
    assert ("eu-frankfurt", "postgres.dbinstanceid", "postgres-master", "REPLICA_OF") in links


@pytest.mark.parametrize(
    "raw",
    [
        dict(InstanceId="cdb-one", Region="ap-guangzhou"),
        dict(InstanceId="cdb-one", Vip="bad"),
        dict(InstanceId="../oops"),
        dict(InstanceId="cdb-one", DBInstanceNetInfo={}),
    ],
)
def test_bad_database_metadata_is_rejected(raw):
    with pytest.raises(CollectionError if raw.get("Vip") != "bad" else ValueError):
        prepare(raw, spec("cdb"), "eu-frankfurt")


def test_redis_topology_and_independent_ssl_denial():
    g = Graph()
    nid = g.add("100", "eu-frankfurt", "redis.instance", "crs-one")

    class Transport:
        def call(self, service, action, region=None, **params):
            if action == "DescribeSSLStatus":
                raise CollectionError("UnauthorizedOperation")
            if action == "DescribeInstanceZoneInfo":
                return dict(
                    TotalCount=1,
                    ReplicaGroups=[
                        dict(
                            GroupId=1,
                            GroupName="replica",
                            Role="replica",
                            ZoneId="eu-frankfurt-1",
                            RedisNodes=[dict(NodeId="node-one", Role="replica", Status="on")],
                        )
                    ],
                )
            if action == "DescribeInstanceShards":
                assert params["FilterSlave"] is False
                return dict(
                    TotalCount=1,
                    InstanceShards=[
                        dict(
                            ShardId="0",
                            Role=0,
                            RunId="runtime-one",
                            Slots="0-16383",
                            ReplicasNodeId=1,
                        )
                    ],
                )
            if action == "DescribeInstanceSecurityGroup":
                return dict(
                    InstanceSecurityGroupsDetail=[
                        dict(
                            InstanceId="crs-one",
                            SecurityGroupDetails=[dict(SecurityGroupId="sg-one")],
                        )
                    ]
                )
            raise AssertionError(action)

    details(
        CollectorRunner(g, Transport(), "100", ["eu-frankfurt"], lambda _: None),
        g.nodes[nid],
        "redis",
    )
    assert [r["status"] for r in g.coverage] == ["denied", "complete", "complete", "complete"]
    assert {"redis.replicagroup", "redis.node", "redis.shard"} <= {
        n["kind"] for n in g.nodes.values()
    }


def test_wrong_security_group_instance_cannot_create_edges():
    g = Graph()
    nid = g.add("100", "eu-frankfurt", "redis.instance", "crs-one")

    class Transport:
        def call(self, service, action, region=None, **params):
            if action == "DescribeInstanceSecurityGroup":
                return dict(
                    InstanceSecurityGroupsDetail=[
                        dict(
                            InstanceId="crs-other",
                            SecurityGroupDetails=[dict(SecurityGroupId="sg-one")],
                        )
                    ]
                )
            raise CollectionError("UnauthorizedOperation")

    details(
        CollectorRunner(g, Transport(), "100", ["eu-frankfurt"], lambda _: None),
        g.nodes[nid],
        "redis",
    )
    assert not g.edges
    assert g.coverage[-1]["error"] == "DatabaseSecurityGroupIdentityMismatch"


@pytest.mark.parametrize(
    "service,key,rid",
    [
        ("sqlserver", "InstanceId", "mssql-one"),
        ("mariadb", "InstanceId", "tdsql-one"),
        ("cdwpg", "InstanceID", "cdwpg-one"),
    ],
)
def test_new_engine_native_inventory_and_scoped_resource_identity(service, key, rid):
    class Transport:
        def call(self, s, a, region=None, **params):
            assert s == service
            return {
                spec(service).result: [
                    {key: rid, "InstanceName": "db", "VpcId": "vpc-one", "Memory": 8}
                ],
                "TotalCount": 1,
            }

    g = Graph()
    collect(
        CollectorRunner(g, Transport(), "100", ["eu-frankfurt"], lambda _: None),
        spec(service),
        "eu-frankfurt",
    )
    node = next(n for n in g.nodes.values() if n["kind"] == service + ".instance")
    assert node["properties"]["Memory"] == 8
    assert identities(node)[0].endswith("/" + rid)
