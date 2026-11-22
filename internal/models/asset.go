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
	AssetSecurityGroup            AssetType = "ec2_security_group"
	AssetLoadBalancer             AssetType = "load_balancer"
	AssetIRSATrust                AssetType = "irsa_trust"
	// Existing resources that run as an IAM role (the role is on a WORKLOAD_RUNS_AS_ROLE edge).
	AssetCloudFormationStack AssetType = "cloudformation_stack"
	AssetCodeBuildProject    AssetType = "codebuild_project"
	AssetStateMachine        AssetType = "state_machine"
	// IAM Identity Center. A user or group is named by a synthetic ARN, arn:aws:identitystore:::<store id>/user/<id>.
	AssetIdentityCenterInstance      AssetType = "identity_center_instance"
	AssetIdentityCenterPermissionSet AssetType = "identity_center_permission_set"
	AssetIdentityCenterUser          AssetType = "identity_center_user"
	AssetIdentityCenterGroup         AssetType = "identity_center_group"
	AssetGlueDevEndpoint             AssetType = "glue_dev_endpoint"
	AssetBatchJobDefinition          AssetType = "batch_job_definition"
	AssetAppRunnerService            AssetType = "apprunner_service"
	AssetSageMakerNotebook           AssetType = "sagemaker_notebook"
	AssetLaunchTemplate              AssetType = "ec2_launch_template"
	AssetCodeDeployGroup             AssetType = "codedeploy_deployment_group"
	AssetAgentCoreRuntime            AssetType = "agentcore_runtime"
	AssetAgentCoreCodeInterpreter    AssetType = "agentcore_code_interpreter"
	AssetAgentCoreBrowser            AssetType = "agentcore_browser"
)

// WorkloadResourceTypes are the existing resources that record the role they run as on a WORKLOAD_RUNS_AS_ROLE edge.
var WorkloadResourceTypes = []AssetType{
	AssetCloudFormationStack, AssetCodeBuildProject, AssetStateMachine, AssetGlueDevEndpoint, AssetBatchJobDefinition, AssetAppRunnerService,
	AssetSageMakerNotebook, AssetLaunchTemplate, AssetCodeDeployGroup, AssetAgentCoreRuntime, AssetAgentCoreCodeInterpreter, AssetAgentCoreBrowser,
}

type AssetNode struct {
	ARN        string         `json:"arn"`
	AssetType  AssetType      `json:"asset_type"`
	Name       string         `json:"name"`
	AccountID  string         `json:"account_id"`
	Region     string         `json:"region"`
	Properties map[string]any `json:"properties"`
	ScanID     string         `json:"scan_id"`
}
