from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class AwsServiceFamily:
    key: str
    icon: str
    component: str


SERVICE_FAMILIES = {
    "acm": AwsServiceFamily(
        "acm",
        "aws-certificate-manager",
        "Security component",
    ),
    "api-gateway": AwsServiceFamily(
        "api-gateway",
        "amazon-api-gateway",
        "API component",
    ),
    "autoscaling": AwsServiceFamily(
        "autoscaling",
        "amazon-ec2-auto-scaling",
        "Compute component",
    ),
    "bedrock": AwsServiceFamily(
        "bedrock",
        "amazon-bedrock",
        "AI component",
    ),
    "cloudformation": AwsServiceFamily(
        "cloudformation",
        "aws-cloudformation",
        "Deployment component",
    ),
    "cloudfront": AwsServiceFamily(
        "cloudfront",
        "amazon-cloudfront",
        "Edge component",
    ),
    "cloudtrail": AwsServiceFamily(
        "cloudtrail",
        "aws-cloudtrail",
        "Management component",
    ),
    "cloudwatch": AwsServiceFamily(
        "cloudwatch",
        "amazon-cloudwatch",
        "Observability component",
    ),
    "codebuild": AwsServiceFamily(
        "codebuild",
        "aws-codebuild",
        "Deployment component",
    ),
    "cognito": AwsServiceFamily(
        "cognito",
        "amazon-cognito",
        "Identity component",
    ),
    "config": AwsServiceFamily(
        "config",
        "aws-config",
        "Management component",
    ),
    "dynamodb": AwsServiceFamily(
        "dynamodb",
        "amazon-dynamodb",
        "Data component",
    ),
    "ebs": AwsServiceFamily(
        "ebs",
        "amazon-elastic-block-store",
        "Storage component",
    ),
    "ec2": AwsServiceFamily(
        "ec2",
        "amazon-ec2",
        "Compute component",
    ),
    "ecr": AwsServiceFamily(
        "ecr",
        "amazon-elastic-container-registry",
        "Image deployment component",
    ),
    "ecs": AwsServiceFamily(
        "ecs",
        "amazon-elastic-container-service",
        "Container component",
    ),
    "efs": AwsServiceFamily(
        "efs",
        "amazon-efs",
        "Storage component",
    ),
    "eks": AwsServiceFamily(
        "eks",
        "amazon-elastic-kubernetes-service",
        "Container component",
    ),
    "elasticache": AwsServiceFamily(
        "elasticache",
        "amazon-elasticache",
        "Data component",
    ),
    "elb": AwsServiceFamily(
        "elb",
        "elastic-load-balancing",
        "Network component",
    ),
    "emr": AwsServiceFamily(
        "emr",
        "amazon-emr",
        "Analytics component",
    ),
    "eventbridge": AwsServiceFamily(
        "eventbridge",
        "amazon-eventbridge",
        "Integration component",
    ),
    "glue": AwsServiceFamily(
        "glue",
        "aws-glue",
        "Analytics component",
    ),
    "guardduty": AwsServiceFamily(
        "guardduty",
        "amazon-guardduty",
        "Security component",
    ),
    "iam": AwsServiceFamily(
        "iam",
        "aws-identity-and-access-management",
        "Identity component",
    ),
    "identity-center": AwsServiceFamily(
        "identity-center",
        "aws-iam-identity-center",
        "Identity component",
    ),
    "inspector": AwsServiceFamily(
        "inspector",
        "amazon-inspector",
        "Security component",
    ),
    "kms": AwsServiceFamily(
        "kms",
        "aws-key-management-service",
        "Security component",
    ),
    "lambda": AwsServiceFamily(
        "lambda",
        "aws-lambda",
        "Compute component",
    ),
    "opensearch": AwsServiceFamily(
        "opensearch",
        "amazon-opensearch-service",
        "Data component",
    ),
    "organizations": AwsServiceFamily(
        "organizations",
        "aws-organizations",
        "Management component",
    ),
    "rds": AwsServiceFamily(
        "rds",
        "amazon-rds",
        "Data component",
    ),
    "redshift": AwsServiceFamily(
        "redshift",
        "amazon-redshift",
        "Analytics component",
    ),
    "resource": AwsServiceFamily(
        "resource",
        "aws-resource-explorer",
        "Supporting services component",
    ),
    "route53": AwsServiceFamily(
        "route53",
        "amazon-route-53",
        "Network component",
    ),
    "s3": AwsServiceFamily(
        "s3",
        "amazon-simple-storage-service",
        "Storage component",
    ),
    "sagemaker": AwsServiceFamily(
        "sagemaker",
        "amazon-sagemaker-ai",
        "AI component",
    ),
    "secrets-manager": AwsServiceFamily(
        "secrets-manager",
        "aws-secrets-manager",
        "Security component",
    ),
    "security-hub": AwsServiceFamily(
        "security-hub",
        "aws-security-hub",
        "Security component",
    ),
    "ses": AwsServiceFamily(
        "ses",
        "amazon-simple-email-service",
        "Integration component",
    ),
    "sns": AwsServiceFamily(
        "sns",
        "amazon-simple-notification-service",
        "Integration component",
    ),
    "sqs": AwsServiceFamily(
        "sqs",
        "amazon-simple-queue-service",
        "Integration component",
    ),
    "systems-manager": AwsServiceFamily(
        "systems-manager",
        "aws-systems-manager",
        "Management component",
    ),
    "tagging": AwsServiceFamily(
        "tagging",
        "aws-resource-explorer",
        "Management component",
    ),
    "transit-gateway": AwsServiceFamily(
        "transit-gateway",
        "aws-transit-gateway",
        "Network component",
    ),
    "vpc": AwsServiceFamily(
        "vpc",
        "amazon-virtual-private-cloud",
        "Network component",
    ),
}


# Ordered from the most specific family to broad infrastructure families.
LABEL_FAMILY_RULES = (
    (re.compile(r"^AWSACM"), "acm"),
    (re.compile(r"^AWSAPIGateway"), "api-gateway"),
    (re.compile(r"^AWSAutoScalingGroup$"), "autoscaling"),
    (re.compile(r"^AWSBedrock"), "bedrock"),
    (re.compile(r"^AWSCloudFormation"), "cloudformation"),
    (re.compile(r"^AWSCloudFront"), "cloudfront"),
    (re.compile(r"^AWSCloudTrail"), "cloudtrail"),
    (re.compile(r"^AWSCloudWatch"), "cloudwatch"),
    (re.compile(r"^AWSCodeBuild"), "codebuild"),
    (re.compile(r"^AWSCognito"), "cognito"),
    (
        re.compile(
            r"^AWS(?:Config|ConfigurationRecorder)",
        ),
        "config",
    ),
    (re.compile(r"^AWSDynamoDB"), "dynamodb"),
    (re.compile(r"^AWSEBS"), "ebs"),
    (re.compile(r"^AWSECR"), "ecr"),
    (re.compile(r"^AWSECS"), "ecs"),
    (re.compile(r"^AWSEfs"), "efs"),
    (re.compile(r"^AWSEKS"), "eks"),
    (re.compile(r"^AWSElasticache"), "elasticache"),
    (re.compile(r"^AWS(?:ELB|LoadBalancer)"), "elb"),
    (re.compile(r"^AWSEMR"), "emr"),
    (re.compile(r"^AWSESDomain$"), "opensearch"),
    (re.compile(r"^AWSEventBridge"), "eventbridge"),
    (re.compile(r"^AWSGlue"), "glue"),
    (re.compile(r"^AWSGuardDuty"), "guardduty"),
    (re.compile(r"^AWSInspector"), "inspector"),
    (re.compile(r"^AWSKMS"), "kms"),
    (re.compile(r"^AWSLambda"), "lambda"),
    (re.compile(r"^AWSOrganization"), "organizations"),
    (re.compile(r"^AWSRDS"), "rds"),
    (re.compile(r"^AWSDBSubnetGroup$"), "rds"),
    (re.compile(r"^AWSRedshift"), "redshift"),
    (re.compile(r"^AWSS3"), "s3"),
    (re.compile(r"^AWSSageMaker"), "sagemaker"),
    (re.compile(r"^AWSSecretsManager"), "secrets-manager"),
    (re.compile(r"^AWSSecurityHub"), "security-hub"),
    (re.compile(r"^AWSSES"), "ses"),
    (re.compile(r"^AWSSNS"), "sns"),
    (re.compile(r"^AWSSQS"), "sqs"),
    (re.compile(r"^AWSSSM"), "systems-manager"),
    (re.compile(r"^AWSPublicSSM"), "systems-manager"),
    (re.compile(r"^AWSTag$"), "tagging"),
    (re.compile(r"^AWSTransitGateway"), "transit-gateway"),
    (
        re.compile(
            r"^AWS(?:DNS|NameServer)",
        ),
        "route53",
    ),
    (
        re.compile(
            r"^AWS(?:IdentityCenter|PermissionSet|SSO)",
        ),
        "identity-center",
    ),
    (
        re.compile(
            r"^AWS(AccountAccessKey|FederatedPrincipal|Group|InlinePolicy|"
            r"InstanceProfile|ManagedPolicy|MfaDevice|Policy|PolicyStatement|Principal|"
            r"Role|RootPrincipal|SAMLProvider|ServerCertificate|ServicePrincipal|"
            r"User)$",
        ),
        "iam",
    ),
    (
        re.compile(
            r"^AWS(?:CidrBlock|Ipv[46]CidrBlock|InternetGateway|IpPermission.*|IpRange|IpRule|"
            r"NetworkInterface|NatGateway|PeeringConnection|RouteTable|Vpc|"
            r"VpcEndpoint|VpnGateway|ElasticIPAddress)$",
        ),
        "vpc",
    ),
    (
        re.compile(
            r"^AWSEC2(?:Ipv6Address|NetworkAcl|NetworkAclRule|PrivateIp|Route|"
            r"RouteTable|RouteTableAssociation|SecurityGroup|Subnet)$",
        ),
        "vpc",
    ),
    (
        re.compile(
            r"^AWSEC2(?:Image|Instance|KeyPair|Reservation|ReservedInstance)$",
        ),
        "ec2",
    ),
    (re.compile(r"^AWSLaunch(?:Configuration|Template|TemplateVersion)$"), "ec2"),
)


DISPLAY_NAME_OVERRIDES = {
    "AWSCloudFormationStack": "CloudFormation stack",
    "AWSEventBridgeRule": "EventBridge rule",
    "AWSInternetGateway": "Internet gateway",
    "AWSACMCertificate": "ACM certificate",
    "AWSAPIGatewayRestAPI": "API Gateway REST API",
    "AWSAPIGatewayV2API": "API Gateway HTTP/WebSocket API",
    "AWSAutoScalingGroup": "EC2 Auto Scaling group",
    "AWSCloudFrontDistribution": "CloudFront distribution",
    "AWSDNSRecord": "Route 53 DNS record",
    "AWSDNSZone": "Route 53 hosted zone",
    "AWSDynamoDBTable": "DynamoDB table",
    "AWSEBSSnapshot": "EBS snapshot",
    "AWSEBSVolume": "EBS volume",
    "AWSEC2Instance": "EC2 instance",
    "AWSEC2NetworkAcl": "Network ACL",
    "AWSEC2PrivateIp": "Private IP address",
    "AWSEC2RouteTable": "Route table",
    "AWSEC2SecurityGroup": "Security group",
    "AWSEC2Subnet": "Subnet",
    "AWSECRRepository": "ECR repository",
    "AWSECSCluster": "ECS cluster",
    "AWSEKSCluster": "EKS cluster",
    "AWSELBListener": "Classic ELB listener",
    "AWSELBV2Listener": "ALB/NLB listener",
    "AWSELBV2TargetGroup": "ELB target group",
    "AWSESDomain": "OpenSearch domain",
    "AWSEfsFileSystem": "EFS file system",
    "AWSElasticacheCluster": "ElastiCache cluster",
    "AWSKMSKey": "KMS key",
    "AWSLambda": "Lambda function",
    "AWSLoadBalancer": "Classic load balancer",
    "AWSLoadBalancerV2": "Application/network load balancer",
    "AWSRDSCluster": "RDS cluster",
    "AWSRDSInstance": "RDS instance",
    "AWSRedshiftCluster": "Redshift cluster",
    "AWSRouteTable": "Route table",
    "AWSS3Bucket": "S3 bucket",
    "AWSSNSTopic": "SNS topic",
    "AWSSQSQueue": "SQS queue",
    "AWSTransitGateway": "Transit Gateway",
    "AWSVpc": "VPC",
    "AWSVpcEndpoint": "VPC endpoint",
}


def service_family_for_label(label: str) -> AwsServiceFamily:
    for pattern, family_key in LABEL_FAMILY_RULES:
        if pattern.search(label):
            return SERVICE_FAMILIES[family_key]
    return SERVICE_FAMILIES["resource"]


def service_family_for_labels(labels: list[str]) -> tuple[str, AwsServiceFamily]:
    aws_labels = [
        label
        for label in labels
        if label.startswith("AWS") and label not in {"AWSAccount", "AWSPrincipal"}
    ]
    if not aws_labels:
        label = labels[0]
        return label, service_family_for_label(label)

    for label in aws_labels:
        family = service_family_for_label(label)
        if family.key != "resource":
            return label, family
    label = aws_labels[0]
    return label, SERVICE_FAMILIES["resource"]


def display_name_for_label(label: str) -> str:
    if label in DISPLAY_NAME_OVERRIDES:
        return DISPLAY_NAME_OVERRIDES[label]
    value = label.removeprefix("AWS")
    value = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", value)
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value)
    value = re.sub(r"([A-Za-z])(\d)", r"\1 \2", value)
    value = value.replace("Ipv 6", "IPv6")
    return value.strip() or label
