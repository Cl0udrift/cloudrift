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
	// EvalIdentityResource is an identity-policy-only decision on a same-account resource the caller would create or edit.
	EvalIdentityResource = "identity_resource"
	EvalEC2Instance      = "ec2_instance_identity"
	EvalLambda           = "lambda_function_policy"
	EvalRDSInstance      = "rds_instance_identity"
	EvalSecret           = "secret_resource_policy"
	EvalKMSKey           = "kms_key_policy"
	EvalUnsupported      = "unsupported"
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
	// ProbeOnly rows are evaluated against a hypothetical resource the caller would create, never against collected ones.
	ProbeOnly       bool
	AttackTechnique string
	SupportVersion  string
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
			Action: "secretsmanager:GetSecretValue", Service: "secretsmanager", Category: CategoryDataRead, Support: SupportEvaluated, Evaluation: EvalSecret,
			ResourceShape:  "secret ARN arn:aws:secretsmanager:region:account:secret:name",
			RequiredPolicy: []string{"identity policy", "secret resource policy or confirmed absence", "kms:Decrypt on the customer managed key when one encrypts the secret", "boundary", "session policy", "SCP", "RCP"},
			Prerequisites:  []string{"concrete secret ARN in the scan", "secret encryption key resolved to aws/secretsmanager or a collected customer managed key"},
			Consequence:    "Read a secret value if the evaluated request is allowed, including the key decrypt leg.",
		},
		{
			Action: "kms:Decrypt", Service: "kms", Category: CategoryDataRead, Support: SupportEvaluated, Evaluation: EvalKMSKey,
			ResourceShape:  "key ARN arn:aws:kms:region:account:key/id",
			RequiredPolicy: []string{"identity policy", "key policy", "boundary", "session policy", "SCP", "RCP"},
			Prerequisites:  []string{"customer managed key in the scan with a collected default key policy"},
			Consequence:    "Decrypt data under the key if the evaluated request is allowed. Grants and encryption context are not evaluated.",
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
			Action: "ec2:StopInstances", Service: "ec2", Category: CategoryInfrastructureControl, Support: SupportEvaluated, Evaluation: EvalEC2Instance,
			ResourceShape:  "instance ARN arn:aws:ec2:region:account:instance/id",
			RequiredPolicy: []string{"identity policy", "boundary", "session policy", "SCP"},
			Prerequisites:  []string{"concrete instance ARN in the scan", "same account as the caller: EC2 instances have no resource policy"},
			Consequence:    "Stop an instance if the evaluated request is allowed. Instance state and tag conditions are not assumed.",
		},
		{
			Action: "ec2:TerminateInstances", Service: "ec2", Category: CategoryInfrastructureControl, Support: SupportEvaluated, Evaluation: EvalEC2Instance,
			ResourceShape:  "instance ARN arn:aws:ec2:region:account:instance/id",
			RequiredPolicy: []string{"identity policy", "boundary", "session policy", "SCP"},
			Prerequisites:  []string{"concrete instance ARN in the scan", "same account as the caller: EC2 instances have no resource policy"},
			Consequence:    "Terminate an instance if the evaluated request is allowed. Termination protection is an API-level check and is not evaluated.",
		},
		{
			Action: "lambda:UpdateFunctionCode", Service: "lambda", Category: CategoryInfrastructureControl, Support: SupportEvaluated, Evaluation: EvalLambda,
			ResourceShape:  "function ARN arn:aws:lambda:region:account:function:name",
			RequiredPolicy: []string{"identity policy", "function resource policy or confirmed absence", "boundary", "session policy", "SCP"},
			Prerequisites:  []string{"concrete function ARN in the scan", "function policy collected with lambda:GetPolicy"},
			Consequence:    "Replace function code if the evaluated request is allowed. Code signing and function state are not evaluated.",
		},
		{
			Action: "lambda:CreateFunction", Service: "lambda", Category: CategoryInfrastructureControl, Support: SupportEvaluated, Evaluation: EvalLambda, ProbeOnly: true,
			ResourceShape:  "hypothetical function ARN the caller would create",
			RequiredPolicy: []string{"identity policy", "boundary", "session policy", "SCP"},
			Consequence:    "Create a function that runs with a passed role if the evaluated request is allowed.",
		},
		{
			Action: "lambda:InvokeFunction", Service: "lambda", Category: CategoryInfrastructureControl, Support: SupportEvaluated, Evaluation: EvalLambda, ProbeOnly: true,
			ResourceShape:  "hypothetical function ARN the caller would create",
			RequiredPolicy: []string{"identity policy", "boundary", "session policy", "SCP"},
			Consequence:    "Run a function the caller created if the evaluated request is allowed.",
		},
		{
			Action: "lambda:AddPermission", Service: "lambda", Category: CategoryInfrastructureControl, Support: SupportEvaluated, Evaluation: EvalIdentityResource, ProbeOnly: true,
			ResourceShape:  "hypothetical function ARN the caller would create",
			RequiredPolicy: []string{"identity policy", "boundary", "session policy", "SCP"},
			Consequence:    "Let another account invoke a function the caller created, if the evaluated request is allowed.",
		},
		{
			Action: "cloudformation:CreateStack", Service: "cloudformation", Category: CategoryInfrastructureControl, Support: SupportEvaluated, Evaluation: EvalIdentityResource, ProbeOnly: true,
			ResourceShape:  "hypothetical stack ARN the caller would create",
			RequiredPolicy: []string{"identity policy", "boundary", "session policy", "SCP"},
			Consequence:    "Create a stack that runs with a passed role if the evaluated request is allowed.",
		},
		{
			Action: "glue:CreateDevEndpoint", Service: "glue", Category: CategoryInfrastructureControl, Support: SupportEvaluated, Evaluation: EvalIdentityResource, ProbeOnly: true,
			ResourceShape:  "hypothetical dev endpoint ARN the caller would create",
			RequiredPolicy: []string{"identity policy", "boundary", "session policy", "SCP"},
			Consequence:    "Create a Glue dev endpoint that runs with a passed role if the evaluated request is allowed.",
		},
		{
			Action: "glue:GetDevEndpoint", Service: "glue", Category: CategoryInfrastructureControl, Support: SupportEvaluated, Evaluation: EvalIdentityResource, ProbeOnly: true,
			ResourceShape:  "hypothetical dev endpoint ARN the caller would create",
			RequiredPolicy: []string{"identity policy", "boundary", "session policy", "SCP"},
			Consequence:    "Read the address of a dev endpoint the caller created if the evaluated request is allowed.",
		},
		{
			Action: "datapipeline:CreatePipeline", Service: "datapipeline", Category: CategoryInfrastructureControl, Support: SupportEvaluated, Evaluation: EvalIdentityResource, ProbeOnly: true,
			ResourceShape:  "hypothetical pipeline ARN the caller would create",
			RequiredPolicy: []string{"identity policy", "boundary", "session policy", "SCP"},
			Consequence:    "Create a pipeline if the evaluated request is allowed.",
		},
		{
			Action: "datapipeline:PutPipelineDefinition", Service: "datapipeline", Category: CategoryInfrastructureControl, Support: SupportEvaluated, Evaluation: EvalIdentityResource, ProbeOnly: true,
			ResourceShape:  "hypothetical pipeline ARN the caller would create",
			RequiredPolicy: []string{"identity policy", "boundary", "session policy", "SCP"},
			Consequence:    "Define a pipeline that runs with a passed role if the evaluated request is allowed.",
		},
		{
			Action: "iam:CreatePolicyVersion", Service: "iam", Category: CategoryIdentityControl, Support: SupportEvaluated, Evaluation: EvalIdentityResource, ProbeOnly: true,
			ResourceShape:  "customer managed policy ARN attached to a reachable role",
			RequiredPolicy: []string{"identity policy", "boundary", "session policy", "SCP"},
			Consequence:    "Publish a new default version of a managed policy if the evaluated request is allowed.",
		},
		{
			Action: "rds:DeleteDBInstance", Service: "rds", Category: CategoryInfrastructureControl, Support: SupportEvaluated, Evaluation: EvalRDSInstance,
			ResourceShape:  "DB instance ARN arn:aws:rds:region:account:db:name",
			RequiredPolicy: []string{"identity policy", "boundary", "session policy", "SCP"},
			Prerequisites:  []string{"concrete DB instance ARN in the scan", "same account as the caller: RDS instances have no resource policy"},
			Consequence:    "Delete a DB instance if the evaluated request is allowed. Deletion protection is an API-level check and is not evaluated.",
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
			Action: "iam:UpdateAssumeRolePolicy", Service: "iam", Category: CategoryIdentityControl, Support: SupportEvaluated, Evaluation: EvalIdentityOnly,
			ResourceShape:  "role ARN whose trust policy is rewritten",
			RequiredPolicy: []string{"identity policy", "boundary", "session policy", "SCP", "RCP"},
			Consequence:    "Rewrite a role trust policy if the evaluated request is allowed. The caller can then name itself as a trusted principal.",
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
		rows[i].PermissionImpact = rows[i].Support == SupportEvaluated && !rows[i].ProbeOnly
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
	"Date conditions and ForAnyValue/ForAllValues set operators",
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
		unsupported: []string{"the policy to attach is not chosen; the attack search assumes an administrative policy"},
		inventory:   true,
		technique:   "GRANT_ROLE_POLICY",
	},
	"iam:PutRolePolicy": {
		unsupported: []string{"the policy to write is not chosen; the attack search assumes an administrative policy"},
		inventory:   true,
		technique:   "GRANT_ROLE_POLICY",
	},
	"lambda:CreateFunction": {
		unsupported: []string{"the probe uses a fixed function name and Region, so a policy scoped to other names or Regions is UNKNOWN", "code signing configuration", "VPC and layer permissions the call may also need"},
	},
	"lambda:InvokeFunction": {
		unsupported: []string{"the probe uses a fixed function name and Region", "invocation through event sources instead of a direct call"},
	},
	"lambda:AddPermission": {
		unsupported: []string{"the probe uses a fixed function name and Region"},
	},
	"cloudformation:CreateStack": {
		unsupported: []string{"the probe uses a fixed stack name and Region; template contents and stack policy are not evaluated"},
	},
	"glue:CreateDevEndpoint": {
		unsupported: []string{"the probe uses a fixed endpoint name and Region; network and security configuration requirements"},
	},
	"glue:GetDevEndpoint": {
		unsupported: []string{"the probe uses a fixed endpoint name and Region"},
	},
	"datapipeline:CreatePipeline": {
		unsupported: []string{"the probe uses a fixed pipeline name and Region"},
	},
	"datapipeline:PutPipelineDefinition": {
		unsupported: []string{"the probe uses a fixed pipeline name and Region"},
	},
	"iam:CreatePolicyVersion": {
		unsupported: []string{"the five-version limit per policy; policies attached to groups or users, which are not collected"},
	},
	"iam:UpdateAssumeRolePolicy": {
		unsupported: []string{"conditions the rewritten trust policy would carry", "service-side propagation delay"},
		inventory:   true,
		technique:   "REWRITE_TRUST",
	},
	"iam:PassRole": {
		unsupported: []string{"permission to pass a role is not permission to assume or use that role", "service-side acceptance of the passed role"},
		inventory:   true,
	},
	"secretsmanager:GetSecretValue": {
		unsupported: []string{"grants with constraints", "kms:EncryptionContext conditions unless supplied as request context", "VPC endpoint policies", "secret replicas in other Regions"},
		inventory:   true,
		technique:   "READ_SECRET",
	},
	"kms:Decrypt": {
		unsupported: []string{"grants with constraints or retiring-principal semantics", "kms:EncryptionContext conditions unless supplied as request context", "VPC endpoint policies", "key state beyond Enabled"},
		inventory:   true,
	},
	"ec2:StopInstances": {
		unsupported: []string{"instance state", "ec2:ResourceTag conditions unless tags are supplied as request context"},
	},
	"ec2:TerminateInstances": {
		unsupported: []string{"instance state", "termination protection (DisableApiTermination)", "ec2:ResourceTag conditions unless tags are supplied as request context"},
	},
	"lambda:UpdateFunctionCode": {
		unsupported: []string{"code signing configuration", "function state", "lambda:FunctionUrlAuthType and qualifier-specific policies"},
	},
	"rds:DeleteDBInstance": {
		unsupported: []string{"deletion protection", "DB instance status", "rds:db-tag conditions unless tags are supplied as request context"},
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
