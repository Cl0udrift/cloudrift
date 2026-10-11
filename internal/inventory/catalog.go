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
	{ID: "iam", Name: "IAM", Types: []string{"iam_role", "iam_policy", "instance_profile"}},
	{ID: "ecs", Name: "ECS", Types: []string{"ecs_cluster", "ecs_service", "ecs_task", "ecs_task_definition"}},
	{ID: "eks", Name: "EKS", Types: []string{"eks_cluster", "eks_pod_identity_association"}},
	{ID: "route53", Name: "Route 53", Types: []string{"dns_record"}},
	{ID: "cloudfront", Name: "CloudFront", Types: []string{"cloudfront_dist"}},
	{ID: "apigateway", Name: "API Gateway", Types: []string{"apigateway_domain"}},
	{ID: "acm", Name: "ACM", Types: []string{"acm_cert"}},
}

var typeService = map[models.AssetType]string{}
var typeName = map[string]string{
	"ec2_instance": "EC2 instance", "lambda_function": "Lambda function",
	"s3_bucket": "S3 bucket", "s3_object": "S3 object",
	"iam_role": "IAM role", "iam_policy": "IAM managed policy", "instance_profile": "IAM instance profile",
	"ecs_cluster": "ECS cluster", "ecs_service": "ECS service", "ecs_task": "ECS task", "ecs_task_definition": "ECS task definition",
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
	"ecs_cluster": categoryCompute, "ecs_service": categoryCompute, "ecs_task": categoryCompute, "eks_cluster": categoryCompute,
	"s3_bucket": categoryStorage, "s3_object": categoryStorage,
	"iam_role": categoryIdentity, "iam_policy": categoryIdentity, "instance_profile": categoryIdentity,
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

var serviceScope = map[string]string{
	"ec2": "regional", "lambda": "regional", "ecs": "regional", "eks": "regional",
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

const coverageNote = "Accounts and regions are those present on discovered inventory assets. They are not the full organization and they are not proof that every intended account or region was scanned. COLLECTED is used only when collection-status evidence says the recorded scope succeeded. Assets without that evidence stay UNKNOWN: the count is real, and completeness is not. NOT_RECORDED means the scan has no assets and no collection record. A region filter does not make a global collector regional. IAM policy statements, authorization decisions, external principal references, organization membership records, IRSA trust derivations, Kubernetes service-account references, and collection-status records are not inventory assets. RDS, VPC, and IAM Identity Center are not inventoried."
