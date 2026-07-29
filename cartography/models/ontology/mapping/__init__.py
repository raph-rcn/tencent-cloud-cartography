from __future__ import annotations

from cartography.models.core.nodes import CartographyNodeSchema
from cartography.models.ontology.mapping.aws import AWS_SEMANTIC_MAPPINGS
from cartography.models.ontology.mapping.specs import OntologyNodeMapping


def get_semantic_label_mapping_from_node_schema(
    node_schema: CartographyNodeSchema,
) -> OntologyNodeMapping | None:
    """Return the AWS-only semantic normalization for a node schema."""
    return AWS_SEMANTIC_MAPPINGS.get(node_schema.label)
