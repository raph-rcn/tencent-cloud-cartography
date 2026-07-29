"""AWS-only semantic property mappings used during graph ingestion."""

from cartography.models.ontology.mapping.specs import OntologyFieldMapping
from cartography.models.ontology.mapping.specs import OntologyNodeMapping

_AWS_ACCOUNT_STATUS = {
    "ACTIVE": "active",
    "PENDING_ACTIVATION": "unknown",
    "SUSPENDED": "suspended",
    "PENDING_CLOSURE": "pending_deletion",
    "CLOSED": "closed",
}

_AWS_BEDROCK_CUSTOM_STATUS = {
    "Active": "active",
    "Creating": "creating",
    "Failed": "failed",
}

_AWS_BEDROCK_FOUNDATION_STATUS = {
    "ACTIVE": "active",
    "LEGACY": "legacy",
}


def field(
    ontology_field: str,
    node_field: str,
    *,
    required: bool = False,
    special_handling: str | None = None,
    extra: dict | None = None,
) -> OntologyFieldMapping:
    return OntologyFieldMapping(
        ontology_field=ontology_field,
        node_field=node_field,
        required=required,
        special_handling=special_handling,
        extra=extra or {},
    )


AWS_SEMANTIC_MAPPINGS = {
    "AWSAccount": OntologyNodeMapping(
        node_label="AWSAccount",
        fields=[
            field("name", "name", required=True),
            field(
                "status",
                "state",
                special_handling="mapping",
                extra={"map": _AWS_ACCOUNT_STATUS},
            ),
        ],
    ),
    "AWSOrganization": OntologyNodeMapping(
        node_label="AWSOrganization",
        fields=[field("name", "id", required=True)],
    ),
    "AWSBedrockFoundationModel": OntologyNodeMapping(
        node_label="AWSBedrockFoundationModel",
        fields=[
            field("name", "model_name", required=True),
            field("provider", "provider_name"),
            field(
                "status",
                "model_lifecycle_status",
                special_handling="mapping",
                extra={"map": _AWS_BEDROCK_FOUNDATION_STATUS},
            ),
            field(
                "type",
                "",
                special_handling="static_value",
                extra={"value": "foundation"},
            ),
        ],
    ),
    "AWSBedrockCustomModel": OntologyNodeMapping(
        node_label="AWSBedrockCustomModel",
        fields=[
            field("name", "model_name", required=True),
            field(
                "provider",
                "",
                special_handling="static_value",
                extra={"value": "aws"},
            ),
            field(
                "status",
                "status",
                special_handling="mapping",
                extra={"map": _AWS_BEDROCK_CUSTOM_STATUS},
            ),
            field(
                "type",
                "customization_type",
                special_handling="mapping",
                extra={
                    "map": {
                        "FINE_TUNING": "fine-tuned",
                        "CONTINUED_PRE_TRAINING": "custom",
                        "DISTILLATION": "custom",
                        "IMPORTED": "custom",
                    },
                },
            ),
        ],
    ),
    "AWSSageMakerModel": OntologyNodeMapping(
        node_label="AWSSageMakerModel",
        fields=[
            field("name", "model_name", required=True),
            field(
                "provider",
                "",
                special_handling="static_value",
                extra={"value": "aws"},
            ),
            field(
                "type",
                "",
                special_handling="static_value",
                extra={"value": "custom"},
            ),
        ],
    ),
    "AWSEBSSnapshot": OntologyNodeMapping(
        node_label="AWSEBSSnapshot",
        fields=[
            field("name", "id", required=True),
            field("encrypted", "encrypted"),
            field("public", "ispublic"),
            field("source_id", "volumeid"),
            field("created_at", "starttime"),
            field("region", "region"),
        ],
    ),
    "AWSRDSSnapshot": OntologyNodeMapping(
        node_label="AWSRDSSnapshot",
        fields=[
            field("name", "db_snapshot_identifier", required=True),
            field("encrypted", "encrypted"),
            field("public", "ispublic"),
            field("source_id", "db_instance_identifier"),
            field("created_at", "snapshot_create_time"),
            field("region", "region"),
        ],
    ),
    "AWSEC2Subnet": OntologyNodeMapping(
        node_label="AWSEC2Subnet",
        fields=[
            field("name", "id", required=True),
            field("cidr_block", "cidr_block"),
            field("availability_zone", "availability_zone"),
            field("region", "region"),
        ],
    ),
    "AWSVpc": OntologyNodeMapping(
        node_label="AWSVpc",
        fields=[
            field("name", "id", required=True),
            field("cidr", "primary_cidr_block"),
            field("region", "region"),
        ],
    ),
    "AWSTag": OntologyNodeMapping(node_label="AWSTag", fields=[]),
}
