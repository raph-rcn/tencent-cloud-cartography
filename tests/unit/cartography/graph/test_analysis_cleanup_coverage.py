import pytest

from cartography.graph.analysis import PropertyEffect
from cartography.graph.analysis import RelationshipEffect
from cartography.graph.analysis import ScopeById
from cartography.graph.analysisbuilder import cleanup_query

AWS = ScopeById("AWSAccount", "AWS_ID")


@pytest.mark.parametrize(  # type: ignore[misc]
    ("effect", "scope", "expected"),
    [
        (
            PropertyEffect(
                "AWSEC2Instance",
                ("exposed_internet", "exposed_internet_type"),
            ),
            None,
            "MATCH (node:AWSEC2Instance)\n"
            "WHERE node.exposed_internet IS NOT NULL OR "
            "node.exposed_internet_type IS NOT NULL\n"
            "WITH node LIMIT $LIMIT_SIZE\n"
            "REMOVE node.exposed_internet, node.exposed_internet_type",
        ),
        (
            RelationshipEffect(
                "AWSEC2Instance",
                "STS_ASSUMEROLE_ALLOW",
                "AWSRole",
                scoped_to="source",
            ),
            AWS,
            "MATCH (scope:AWSAccount {id: $AWS_ID})-[:RESOURCE]->(source)\n"
            "MATCH (source:AWSEC2Instance)-[r:STS_ASSUMEROLE_ALLOW]->"
            "(target:AWSRole)\n"
            "WHERE r.lastupdated <> $UPDATE_TAG\n"
            "WITH r LIMIT $LIMIT_SIZE\n"
            "DELETE r",
        ),
        (
            RelationshipEffect(
                "AWSLoadBalancerV2",
                "EXPOSE",
                "AWSECSContainer",
            ),
            None,
            "MATCH (source:AWSLoadBalancerV2)-[r:EXPOSE]->"
            "(target:AWSECSContainer)\n"
            "WHERE r.lastupdated <> $UPDATE_TAG\n"
            "WITH r LIMIT $LIMIT_SIZE\n"
            "DELETE r",
        ),
    ],
)
def test_cleanup_query_for_aws_effects(
    effect: PropertyEffect | RelationshipEffect,
    scope: ScopeById | None,
    expected: str,
) -> None:
    assert cleanup_query(effect, scope) == expected
