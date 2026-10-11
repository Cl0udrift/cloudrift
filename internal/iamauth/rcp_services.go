package iamauth

// RCPServices lists service prefixes that AWS documents as supporting resource
// control policies. It is the Organizations service list, not the smaller set
// of actions Cloudrift evaluates.
//
// Source: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html
// Retrieved 2026-10-11.
//
// An action whose service is outside this list is not subject to RCPs.
// An action inside this list is still UNKNOWN unless Catalog marks it SupportEvaluated.
// kms:RetireGrant and AWS managed KMS keys are documented RCP exceptions.
var RCPServices = map[string]struct{}{
	"aoss": {}, "appconfig": {}, "appstream": {}, "autoscaling": {}, "autoscaling-plans": {},
	"budgets": {}, "cloudfront": {}, "clouddirectory": {}, "cloudsearch": {}, "cloudtrail-data": {},
	"codeartifact": {}, "codebuild": {}, "codecommit": {}, "codepipeline": {}, "cognito-identity": {},
	"cognito-idp": {}, "comprehend": {}, "comprehendmedical": {}, "compute-optimizer": {},
	"cost-optimization-hub": {}, "dax": {}, "dsql": {}, "dynamodb": {}, "ecr": {}, "ecr-public": {},
	"events": {}, "firehose": {}, "fis": {}, "fms": {}, "gamelift": {}, "health": {},
	"inspector-scan": {}, "kendra": {}, "kinesisvideo": {}, "kms": {}, "logs": {}, "memorydb": {},
	"networkmonitor": {}, "notifications": {}, "opensearch": {}, "pca-connector-ad": {},
	"personalize": {}, "polly": {}, "pricing": {}, "resource-groups": {}, "rolesanywhere": {},
	"s3": {}, "secretsmanager": {}, "servicediscovery": {}, "signin": {}, "sqs": {}, "sts": {},
	"support": {}, "swf": {}, "textract": {}, "timestream-influxdb": {}, "transcribe": {},
	"transfer": {}, "translate": {}, "wafv2": {}, "workspaces": {}, "xray": {},
}

// RCPServiceSupported reports whether AWS documents RCPs for the service prefix.
func RCPServiceSupported(service string) bool {
	_, ok := RCPServices[service]
	return ok
}
