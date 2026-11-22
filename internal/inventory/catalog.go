package inventory

import "github.com/Zero0x00/cloudrift/internal/models"

const (
	coverageCollected     = "COLLECTED"
	coveragePartial       = "PARTIAL"
	coverageNotCollected  = "NOT_COLLECTED"
	coverageUnsupported   = "UNSUPPORTED"
	coverageNotApplicable = "NOT_APPLICABLE"
	coverageFailed        = "FAILED"
	coverageNotRecorded   = "NOT_RECORDED"
	coverageUnknown       = "UNKNOWN"

	serviceOther = "other"

	categoryCompute       = "compute"
	categoryStorage       = "storage"
	categoryIdentity      = "identity"
	categoryConfiguration = "configuration"
	categoryNetwork       = "networking_edge"
	categoryOther         = "other"
)

type serviceDef struct {
	ID    string
	Name  string
	Types []string
}

// catalog is the service order used by summary cards. A service is listed even
// when the selected scan has no counted assets for it.
var catalog = []serviceDef{
	{ID: "ec2", Name: "EC2", Types: []string{"ec2_instance"}},
	{ID: "lambda", Name: "Lambda", Types: []string{"lambda_function"}},
	{ID: "s3", Name: "S3", Types: []string{"s3_bucket", "s3_object"}},
	{ID: "iam", Name: "IAM", Types: []string{"iam_role", "iam_user", "iam_group", "iam_policy", "instance_profile"}},
	{ID: "ecs", Name: "ECS", Types: []string{"ecs_cluster", "ecs_service", "ecs_task", "ecs_task_definition"}},
	{ID: "eks", Name: "EKS", Types: []string{"eks_cluster", "eks_pod_identity_association"}},
	{ID: "cloudformation", Name: "CloudFormation", Types: []string{"cloudformation_stack"}},
	{ID: "codebuild", Name: "CodeBuild", Types: []string{"codebuild_project"}},
	{ID: "stepfunctions", Name: "Step Functions", Types: []string{"state_machine"}},
	{ID: "glue", Name: "Glue", Types: []string{"glue_dev_endpoint"}},
	{ID: "batch", Name: "Batch", Types: []string{"batch_job_definition"}},
	{ID: "apprunner", Name: "App Runner", Types: []string{"apprunner_service"}},
	{ID: "sagemaker", Name: "SageMaker", Types: []string{"sagemaker_notebook"}},
	{ID: "agentcore", Name: "Bedrock AgentCore", Types: []string{"agentcore_runtime", "agentcore_code_interpreter", "agentcore_browser"}},
	{ID: "launch_templates", Name: "Launch templates", Types: []string{"ec2_launch_template"}},
	{ID: "codedeploy", Name: "CodeDeploy", Types: []string{"codedeploy_deployment_group"}},
	{ID: "secrets", Name: "Secrets Manager", Types: []string{"secret"}},
	{ID: "kms", Name: "KMS keys", Types: []string{"kms_key"}},
	{ID: "rds", Name: "RDS instances", Types: []string{"rds_instance"}},
	{ID: "elbv2", Name: "Load balancers", Types: []string{"load_balancer"}},
	{ID: "security_groups", Name: "Security groups", Types: []string{"ec2_security_group"}},
	{ID: "vpc_endpoints", Name: "VPC endpoints", Types: []string{"vpc_endpoint"}},
	{ID: "identity_center", Name: "IAM Identity Center", Types: []string{"identity_center_instance", "identity_center_permission_set", "identity_center_user", "identity_center_group"}},
	{ID: "route53", Name: "Route 53", Types: []string{"dns_record"}},
	{ID: "cloudfront", Name: "CloudFront", Types: []string{"cloudfront_dist"}},
	{ID: "apigateway", Name: "API Gateway", Types: []string{"apigateway_domain"}},
	{ID: "acm", Name: "ACM", Types: []string{"acm_cert"}},
}

var typeService = map[models.AssetType]string{}
var typeName = map[string]string{
	"ec2_instance": "EC2 instance", "lambda_function": "Lambda function",
	"s3_bucket": "S3 bucket", "s3_object": "S3 object",
	"iam_role": "IAM role", "iam_user": "IAM user", "iam_group": "IAM group", "iam_policy": "IAM managed policy", "instance_profile": "IAM instance profile",
	"ecs_cluster": "ECS cluster", "ecs_service": "ECS service", "ecs_task": "ECS task", "ecs_task_definition": "ECS task definition",
	"glue_dev_endpoint": "Glue development endpoint", "batch_job_definition": "Batch job definition", "apprunner_service": "App Runner service",
	"sagemaker_notebook": "SageMaker notebook instance", "agentcore_runtime": "AgentCore agent runtime", "agentcore_code_interpreter": "AgentCore code interpreter",
	"agentcore_browser": "AgentCore browser", "ec2_launch_template": "EC2 launch template", "codedeploy_deployment_group": "CodeDeploy deployment group",
	"identity_center_instance": "Identity Center instance", "identity_center_permission_set": "Identity Center permission set", "identity_center_user": "Identity Center user", "identity_center_group": "Identity Center group",
	"secret": "Secret", "kms_key": "KMS key", "rds_instance": "RDS instance", "vpc_endpoint": "VPC endpoint", "load_balancer": "Load balancer", "ec2_security_group": "Security group",
	"cloudformation_stack": "CloudFormation stack", "codebuild_project": "CodeBuild project", "state_machine": "Step Functions state machine",
	"eks_cluster": "EKS cluster", "eks_pod_identity_association": "EKS Pod Identity association",
	"dns_record": "DNS record", "cloudfront_dist": "CloudFront distribution",
	"apigateway_domain": "API Gateway domain", "acm_cert": "ACM certificate",
}

// excludedAssetTypes are scan evidence and metadata. They are not AWS infrastructure totals.
var excludedAssetTypes = map[models.AssetType]bool{
	models.AssetIAMPolicyStatement:       true,
	models.AssetIAMAuthorizationDecision: true,
	models.AssetExternalPrincipal:        true,
	models.AssetOrganizationAccount:      true,
	models.AssetEKSServiceAccountRef:     true,
	models.AssetIRSATrust:                true,
	"workload_collection_status":         true,
	"collection_status":                  true,
}

var typeCategory = map[string]string{
	"ec2_instance": categoryCompute, "lambda_function": categoryCompute,
	"glue_dev_endpoint": categoryCompute, "batch_job_definition": categoryConfiguration, "apprunner_service": categoryCompute, "sagemaker_notebook": categoryCompute,
	"agentcore_runtime": categoryCompute, "agentcore_code_interpreter": categoryCompute, "agentcore_browser": categoryCompute, "ec2_launch_template": categoryConfiguration, "codedeploy_deployment_group": categoryConfiguration,
	"identity_center_instance": categoryIdentity, "identity_center_permission_set": categoryIdentity, "identity_center_user": categoryIdentity, "identity_center_group": categoryIdentity,
	"secret": categoryStorage, "kms_key": categoryStorage, "rds_instance": categoryStorage, "vpc_endpoint": categoryNetwork, "load_balancer": categoryNetwork, "ec2_security_group": categoryNetwork,
	"cloudformation_stack": categoryConfiguration, "codebuild_project": categoryCompute, "state_machine": categoryCompute,
	"ecs_cluster": categoryCompute, "ecs_service": categoryCompute, "ecs_task": categoryCompute, "eks_cluster": categoryCompute,
	"s3_bucket": categoryStorage, "s3_object": categoryStorage,
	"iam_role": categoryIdentity, "iam_user": categoryIdentity, "iam_group": categoryIdentity, "iam_policy": categoryIdentity, "instance_profile": categoryIdentity,
	"ecs_task_definition": categoryConfiguration, "eks_pod_identity_association": categoryConfiguration,
	"dns_record": categoryNetwork, "cloudfront_dist": categoryNetwork, "apigateway_domain": categoryNetwork, "acm_cert": categoryNetwork,
}

var categoryOrder = []struct{ ID, Name string }{
	{categoryCompute, "Compute"},
	{categoryStorage, "Storage"},
	{categoryIdentity, "Identity"},
	{categoryConfiguration, "Configuration"},
	{categoryNetwork, "Networking/Edge"},
	{categoryOther, "Other"},
}

// noCollector are listed services that Cloudrift has no collector for at all. They are reported as not inventoried, not as a
// collector whose result was not recorded.
// optInSetting names the setting that turns on the collectors behind a service card. A card with no assets and no collection record
// for one of these is reported as off, with the setting to turn on, not as a gap.
var optInSetting = map[string]string{"identity_center": "scan.identity_center", "secrets": "scan.resource_policies", "kms": "scan.resource_policies", "rds": "scan.network_resources", "elbv2": "scan.network_resources", "security_groups": "scan.network_resources", "vpc_endpoints": "scan.resource_policies"}

var noCollector = map[string]bool{"apigateway": true, "acm": true}

var serviceScope = map[string]string{
	"ec2": "regional", "elbv2": "regional", "security_groups": "regional", "rds": "regional", "lambda": "regional", "ecs": "regional", "eks": "regional",
	"apigateway": "regional", "acm": "regional",
	"iam": "global", "s3": "global", "route53": "global", "cloudfront": "global",
}

func categoryOf(typ string) string {
	if category, ok := typeCategory[typ]; ok {
		return category
	}
	return categoryOther
}

func categoryName(id string) string {
	for _, category := range categoryOrder {
		if category.ID == id {
			return category.Name
		}
	}
	return "Other"
}

func recordKind(typ string) string {
	switch typ {
	case "ecs_task_definition", "eks_pod_identity_association", "iam_policy":
		return "configuration"
	default:
		return "infrastructure"
	}
}

func init() {
	for _, svc := range catalog {
		for _, typ := range svc.Types {
			typeService[models.AssetType(typ)] = svc.ID
		}
	}
}

// notInventoried are services the collectors do not cover. The coverage note below names the same ones.
var notInventoried = []string{}

const coverageNote = "Accounts and regions are those present on discovered inventory assets. They are not the full organization and they are not proof that every intended account or region was scanned. COLLECTED is used only when collection-status evidence says the recorded scope succeeded. Assets without that evidence stay UNKNOWN: the count is real, and completeness is not. NOT_RECORDED means the scan has no assets and no collection record. A region filter does not make a global collector regional. IAM policy statements, authorization decisions, external principal references, organization membership records, IRSA trust derivations, Kubernetes service-account references, and collection-status records are not inventory assets."
