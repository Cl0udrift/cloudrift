package iamauth

import "strings"

const (
	CategoryDataRead              = "DATA_READ"
	CategoryDataModify            = "DATA_MODIFY"
	CategoryInfrastructureControl = "INFRASTRUCTURE_CONTROL"
	CategoryIdentityControl       = "IDENTITY_CONTROL"
	CategoryLateralMovement       = "LATERAL_MOVEMENT"

	SupportEvaluated   = "evaluated"
	SupportCatalogOnly = "catalog_only"

	EvalS3Object     = "s3_object_policy"
	EvalAssumeRole   = "assume_role"
	EvalIdentityOnly = "identity_only"
	EvalUnsupported  = "unsupported"
)

// Capability is the authoritative action registry.
// A row classifies an action. It becomes an authorization result only when Evaluate runs.
// SupportCatalogOnly means the action is known and is not scored as validated access.
type Capability struct {
	Action               string
	Service              string
	Category             string
	Support              string
	Evaluation           string
	ResourceShape        string
	RequiredPolicy       []string
	RequiredContext      []string
	Prerequisites        []string
	UnsupportedSemantics []string
	Consequence          string
	InventorySupported   bool
	PermissionImpact     bool
	AttackTechnique      string
	SupportVersion       string
}

// Catalog is the authoritative capability registry. A row is not an authorization result.
func Catalog() []Capability {
	rows := []Capability{
		{
			Action: ActionGetObject, Service: "s3", Category: CategoryDataRead, Support: SupportEvaluated, Evaluation: EvalS3Object,
			ResourceShape:   "object ARN arn:aws:s3:::bucket/key",
			RequiredPolicy:  []string{"identity policy", "bucket policy or confirmed absence for same-account grants", "boundary", "session policy", "SCP", "RCP"},
			RequiredContext: []string{"s3 object ACL declared not applicable", "s3 block public access declared not applicable"},
			Prerequisites:   []string{"concrete object ARN in the scan", "bucket ARN is not an object"},
			Consequence:     "Read object bytes if the evaluated request is allowed.",
		},
		{
			Action: "secretsmanager:GetSecretValue", Service: "secretsmanager", Category: CategoryDataRead, Support: SupportCatalogOnly, Evaluation: EvalUnsupported,
			ResourceShape:  "secret ARN",
			RequiredPolicy: []string{"identity policy", "secret resource policy", "KMS key policy when a customer key encrypts the secret"},
			Consequence:    "Read a secret value. Not scored until KMS and secret resource-policy rules are implemented.",
		},
		{
			Action: "s3:PutObject", Service: "s3", Category: CategoryDataModify, Support: SupportEvaluated, Evaluation: EvalS3Object,
			ResourceShape:   "object ARN arn:aws:s3:::bucket/key",
			RequiredPolicy:  []string{"identity policy", "bucket policy or confirmed absence for same-account grants", "boundary", "session policy", "SCP", "RCP"},
			RequiredContext: []string{"s3 object ACL declared not applicable", "s3 block public access declared not applicable"},
			Prerequisites:   []string{"concrete object ARN in the scan"},
			Consequence:     "Overwrite an object if the evaluated request is allowed.",
		},
		{
			Action: "s3:DeleteObject", Service: "s3", Category: CategoryDataModify, Support: SupportEvaluated, Evaluation: EvalS3Object,
			ResourceShape:   "object ARN arn:aws:s3:::bucket/key",
			RequiredPolicy:  []string{"identity policy", "bucket policy or confirmed absence for same-account grants", "boundary", "session policy", "SCP", "RCP"},
			RequiredContext: []string{"s3 object ACL declared not applicable", "s3 block public access declared not applicable"},
			Prerequisites:   []string{"concrete object ARN in the scan"},
			Consequence:     "Delete an object if the evaluated request is allowed.",
		},
		{
			Action: "ec2:StopInstances", Service: "ec2", Category: CategoryInfrastructureControl, Support: SupportCatalogOnly, Evaluation: EvalUnsupported,
			ResourceShape: "instance ARN",
			Consequence:   "Stop an instance. Not scored; EC2 authorization and instance state are not evaluated.",
		},
		{
			Action: "ec2:TerminateInstances", Service: "ec2", Category: CategoryInfrastructureControl, Support: SupportCatalogOnly, Evaluation: EvalUnsupported,
			ResourceShape: "instance ARN",
			Consequence:   "Terminate an instance. Not scored.",
		},
		{
			Action: "lambda:UpdateFunctionCode", Service: "lambda", Category: CategoryInfrastructureControl, Support: SupportCatalogOnly, Evaluation: EvalUnsupported,
			ResourceShape: "function ARN",
			Consequence:   "Replace function code. Not scored.",
		},
		{
			Action: "rds:DeleteDBInstance", Service: "rds", Category: CategoryInfrastructureControl, Support: SupportCatalogOnly, Evaluation: EvalUnsupported,
			ResourceShape: "DB instance ARN",
			Consequence:   "Delete a database. Not scored.",
		},
		{
			Action: "iam:AttachRolePolicy", Service: "iam", Category: CategoryIdentityControl, Support: SupportEvaluated, Evaluation: EvalIdentityOnly,
			ResourceShape:  "role ARN",
			RequiredPolicy: []string{"identity policy", "boundary", "session policy", "SCP", "RCP"},
			Prerequisites:  []string{"role trust policy does not grant iam:AttachRolePolicy"},
			Consequence:    "Attach a managed policy to a role if the evaluated request is allowed.",
		},
		{
			Action: "iam:PutRolePolicy", Service: "iam", Category: CategoryIdentityControl, Support: SupportEvaluated, Evaluation: EvalIdentityOnly,
			ResourceShape:  "role ARN",
			RequiredPolicy: []string{"identity policy", "boundary", "session policy", "SCP", "RCP"},
			Consequence:    "Write an inline policy on a role if the evaluated request is allowed.",
		},
		{
			Action: "iam:PassRole", Service: "iam", Category: CategoryIdentityControl, Support: SupportEvaluated, Evaluation: EvalIdentityOnly,
			ResourceShape:   "role ARN being passed",
			RequiredPolicy:  []string{"identity policy", "boundary", "session policy", "SCP", "RCP"},
			RequiredContext: []string{"iam:PassedToService when the statement conditions on it"},
			Consequence:     "Pass a role to a service if the evaluated request is allowed. This is not service-side acceptance.",
		},
		{
			Action: ActionAssumeRole, Service: "sts", Category: CategoryLateralMovement, Support: SupportEvaluated, Evaluation: EvalAssumeRole,
			ResourceShape:  "role ARN",
			RequiredPolicy: []string{"caller identity policy", "target trust policy", "boundary", "session policy", "SCP", "RCP"},
			Consequence:    "Obtain credentials for the target role if both identity and trust policies allow the request.",
		},
	}
	for i := range rows {
		detail := registryDetail[rows[i].Action]
		rows[i].UnsupportedSemantics = detail.unsupported
		rows[i].InventorySupported = detail.inventory
		rows[i].PermissionImpact = rows[i].Support == SupportEvaluated
		rows[i].AttackTechnique = detail.technique
		rows[i].SupportVersion = EvaluatorVersion
	}
	return rows
}

type registryFacts struct {
	unsupported []string
	inventory   bool
	technique   string
}

var s3Limits = []string{
	"object ACLs when bucket owner enforced is not known",
	"S3 Block Public Access settings",
	"S3 Access Points, Object Lambda, and Multi-Region Access Points",
	"bucket owner enforced versus ACL-enabled object ownership, unless declared",
	"KMS decrypt required to read an encrypted object",
	"VPC endpoint policies and resource control beyond a supplied RCP",
	"policy variables such as ${aws:username}",
	"condition operators other than StringEquals, StringNotEquals, ArnEquals, ArnLike, Bool, and Null",
}

var registryDetail = map[string]registryFacts{
	ActionGetObject: {
		unsupported: s3Limits,
		inventory:   true,
		technique:   "READ_S3_OBJECT",
	},
	"s3:PutObject":    {unsupported: s3Limits, inventory: true},
	"s3:DeleteObject": {unsupported: s3Limits, inventory: true},
	ActionAssumeRole: {
		unsupported: []string{
			"sts:AssumeRoleWithSAML and sts:AssumeRoleWithWebIdentity",
			"session tags and transitive tag conditions",
			"ExternalId and MFA unless the supplied context satisfies a supported operator",
			"role session duration and MFA serial enforcement beyond a supported condition key",
			"confused-deputy controls that use unsupported operators",
			"copying MFA, ExternalId, or session tags onto the resulting role session",
		},
		inventory: true,
		technique: "ASSUME_ROLE",
	},
	"iam:AttachRolePolicy": {
		unsupported: []string{"authorization to attach a policy is not proof of privilege escalation"},
		inventory:   true,
	},
	"iam:PutRolePolicy": {
		unsupported: []string{"authorization to write an inline policy is not proof of privilege escalation"},
		inventory:   true,
	},
	"iam:PassRole": {
		unsupported: []string{"permission to pass a role is not permission to assume or use that role", "service-side acceptance of the passed role"},
		inventory:   true,
	},
	"secretsmanager:GetSecretValue": {
		unsupported: []string{"secret resource policy", "KMS key policy", "validated secret read"},
	},
	"ec2:StopInstances": {
		unsupported: []string{"EC2 authorization", "instance state"},
	},
	"ec2:TerminateInstances": {
		unsupported: []string{"EC2 authorization", "instance state"},
	},
	"lambda:UpdateFunctionCode": {
		unsupported: []string{"Lambda resource policy", "function code replacement"},
	},
	"rds:DeleteDBInstance": {
		unsupported: []string{"RDS authorization", "database deletion"},
	},
}

// CapabilityFor returns the catalog row for an action.
func CapabilityFor(action string) (Capability, bool) {
	for _, entry := range Catalog() {
		if strings.EqualFold(entry.Action, strings.TrimSpace(action)) {
			return entry, true
		}
	}
	return Capability{}, false
}

// EvaluatedActions are the only actions that can become VALIDATED_ALLOWED or VALIDATED_DENIED.
func EvaluatedActions() []string {
	var out []string
	for _, entry := range Catalog() {
		if entry.Support == SupportEvaluated {
			out = append(out, entry.Action)
		}
	}
	return out
}
