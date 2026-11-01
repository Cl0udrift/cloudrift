package models

type AssetType string

const (
	AssetDNSRecord                AssetType = "dns_record"
	AssetS3Bucket                 AssetType = "s3_bucket"
	AssetS3Object                 AssetType = "s3_object"
	AssetCloudFrontDist           AssetType = "cloudfront_dist"
	AssetAPIGatewayDomain         AssetType = "apigateway_domain"
	AssetACMCert                  AssetType = "acm_cert"
	AssetIAMRole                  AssetType = "iam_role"
	AssetIAMUser                  AssetType = "iam_user"
	AssetIAMGroup                 AssetType = "iam_group"
	AssetIAMPolicy                AssetType = "iam_policy"
	AssetIAMPolicyStatement       AssetType = "iam_policy_statement"
	AssetIAMAuthorizationDecision AssetType = "iam_authorization_decision"
	AssetExternalPrincipal        AssetType = "external_principal"
	AssetOrganizationAccount      AssetType = "organization_account"
	AssetEC2Instance              AssetType = "ec2_instance"
	AssetInstanceProfile          AssetType = "instance_profile"
	AssetLambdaFunction           AssetType = "lambda_function"
	AssetECSCluster               AssetType = "ecs_cluster"
	AssetECSService               AssetType = "ecs_service"
	AssetECSTask                  AssetType = "ecs_task"
	AssetECSTaskDefinition        AssetType = "ecs_task_definition"
	AssetEKSCluster               AssetType = "eks_cluster"
	AssetEKSPodIdentity           AssetType = "eks_pod_identity_association"
	AssetEKSServiceAccountRef     AssetType = "eks_service_account_ref"
	AssetSecret                   AssetType = "secret"
	AssetRDSInstance              AssetType = "rds_instance"
	AssetKMSKey                   AssetType = "kms_key"
	AssetVPCEndpoint              AssetType = "vpc_endpoint"
	AssetIRSATrust                AssetType = "irsa_trust"
)

type AssetNode struct {
	ARN        string         `json:"arn"`
	AssetType  AssetType      `json:"asset_type"`
	Name       string         `json:"name"`
	AccountID  string         `json:"account_id"`
	Region     string         `json:"region"`
	Properties map[string]any `json:"properties"`
	ScanID     string         `json:"scan_id"`
}
