package iamauth

import "time"

const EvaluatorVersion = "iam-authz-4.5.0"

const (
	StatusAllowed     = "VALIDATED_ALLOWED"
	StatusDenied      = "VALIDATED_DENIED"
	StatusConditional = "CONDITIONAL"
	StatusUnknown     = "UNKNOWN"
)

const (
	EvidencePresent = "evaluated_present"
	EvidenceAbsent  = "evaluated_absent"
	EvidenceMissing = "missing"
)

const (
	ConstraintNotApplicable = "not_applicable"
)

const (
	ActionGetObject    = "s3:GetObject"
	ActionPutObject    = "s3:PutObject"
	ActionDeleteObject = "s3:DeleteObject"
	ActionAssumeRole   = "sts:AssumeRole"
)

const (
	ReasonAllowed              = "allowed_under_evaluated_scope"
	ReasonExplicitDeny         = "explicit_deny"
	ReasonNoAllow              = "no_applicable_allow"
	ReasonMissingContext       = "missing_request_context"
	ReasonUnsupportedCondition = "unsupported_condition"
	ReasonUndecidableDeny      = "cannot_rule_out_explicit_deny"
	ReasonMissingBoundary      = "missing_permissions_boundary"
	ReasonMissingSCP           = "missing_organizations_scp"
	ReasonMissingRCP           = "missing_organizations_rcp"
	ReasonMissingSession       = "missing_session_policy"
	ReasonMissingIdentity      = "missing_identity_policy"
	ReasonMissingResource      = "missing_resource_policy"
	ReasonMissingTrust         = "missing_trust_policy"
	ReasonBoundaryNoAllow      = "permissions_boundary_does_not_allow"
	ReasonSCPNoAllow           = "scp_does_not_allow"
	ReasonRCPNoAllow           = "rcp_does_not_allow"
	ReasonSCPHierarchy         = "scp_attachment_level_missing"
	ReasonRCPHierarchy         = "rcp_attachment_level_missing"
	ReasonSessionNoAllow       = "session_policy_does_not_allow"
	ReasonUnsupportedAction    = "unsupported_action"
	ReasonInvalidRequest       = "invalid_request"
	ReasonInvalidResource      = "invalid_resource"
	ReasonS3Scope              = "s3_resource_scope"
	ReasonRoleResource         = "iam_role_resource_required"
	ReasonMalformed            = "malformed_policy"
	ReasonMissingACL           = "missing_s3_object_acl_evidence"
	ReasonMissingBPA           = "missing_s3_block_public_access_evidence"
	ReasonCrossAccountResource = "cross_account_requires_resource_policy"
	ReasonMissingKMS           = "missing_kms_key_policy"
	ReasonKMSNotAllowed        = "kms_decrypt_not_allowed"
	ReasonKMSCrossAccountAWS   = "aws_managed_key_is_not_shareable"
	ReasonResourceShape        = "resource_arn_shape_not_supported"
	ReasonSimulator            = "simulator_disagreement"
)

// AuthorizationRequest is one concrete principal, action, and resource.
// A resource wildcard is not a valid request target.
type AuthorizationRequest struct {
	ScanID            string
	PrincipalARN      string
	Action            string
	ResourceARN       string
	ResourceAccountID string
	RequestContext    map[string]string
	EvaluatedAt       time.Time

	Identity            PolicySlot
	ResourcePolicy      PolicySlot
	TrustPolicy         PolicySlot
	PermissionsBoundary PolicySlot
	SessionPolicies     PolicySlot
	SCPs                PolicySlot
	RCPs                PolicySlot
	S3ObjectACL         string
	S3BlockPublicAccess string
	// S3KMSKeyPolicy is not_applicable when the collected encryption configuration
	// does not use a customer-managed key. Any other non-empty value means the
	// key policy was not evaluated.
	S3KMSKeyPolicy string
	Simulator      *SimulatorObservation
	// SecretKMS describes the key that encrypts the secret for secretsmanager:GetSecretValue.
	// Nil means the key was not collected, which keeps the decision UNKNOWN.
	SecretKMS *SecretKMSEvidence
	// KMSGrants are the collected grants on the key for kms:Decrypt requests.
	KMSGrants []KMSGrant
}

// KMSGrant is one collected key grant. Constrained is true when the grant carries any
// encryption-context constraint, which the evaluator does not resolve.
type KMSGrant struct {
	GranteePrincipal string
	Operations       []string
	Constrained      bool
}

// Secret key modes for SecretKMSEvidence.Mode.
const (
	SecretKeyAWSManaged      = "aws_managed"
	SecretKeyCustomerManaged = "customer_managed"
)

// SecretKMSEvidence is the key leg of a secret read. For a customer managed key the evaluator
// also runs kms:Decrypt on KeyARN with the same caller controls.
type SecretKMSEvidence struct {
	Mode      string
	KeyARN    string
	KeyPolicy PolicySlot
	// RCPs are the resource control policies of the key owner account. Empty falls back to the
	// request RCPs, which belong to the secret owner account.
	RCPs PolicySlot
	// Grants are the collected grants on the customer managed key.
	Grants []KMSGrant
}

// PolicySlot is one class of policy evidence.
// EvidenceAbsent means the scan established that this control is not present.
// EvidenceMissing means the scan cannot tell, which must not be treated as allow.
type PolicySlot struct {
	State string
	// Evidence is the observation that supports State. Confirmed absence is not
	// valid without it.
	Evidence string
	// HierarchyComplete is set only when every applicable organization node was
	// discovered. Older flat document lists leave this false and cannot become
	// VALIDATED_ALLOWED.
	HierarchyComplete bool
	// RequiredTargets are the account, ancestor OUs, and root. A target with no
	// attached Allow does not grant the action.
	RequiredTargets []string
	Documents       []PolicyDocument
}

// PolicyDocument is a raw IAM document, a normalized statement list, or both.
// AttachmentLevel and AttachmentTarget preserve the organization node a policy
// is attached to. They are required before an SCP or RCP Allow is trusted.
type PolicyDocument struct {
	ID               string
	PolicyType       string
	Raw              string
	Statements       []StatementView
	AttachmentLevel  string
	AttachmentTarget string
	RetrievedAt      string
}

// StatementView is the evaluator's view of one statement.
// It is filled from models.IAMPolicyStatement when Raw is set.
type StatementView struct {
	PolicyID     string
	StatementID  string
	Effect       string
	Action       []string
	NotAction    []string
	Resource     []string
	NotResource  []string
	Condition    map[string]any
	Principal    map[string]any
	NotPrincipal map[string]any
}

// SimulatorObservation is optional evidence from iam:SimulatePrincipalPolicy.
// It never fills a missing SCP, boundary, session policy, or resource policy.
type SimulatorObservation struct {
	Invoked bool
	Result  string
	Note    string
}

// StatementRef identifies one statement that contributed to the decision.
type StatementRef struct {
	PolicyID    string `json:"policy_id"`
	StatementID string `json:"statement_id"`
	Effect      string `json:"effect"`
	PolicyType  string `json:"policy_type"`
}

// AuthorizationDecision is the result for one request.
// VALIDATED_ALLOWED means the request is allowed under the evaluated scope.
// It does not mean an attack succeeded. UNKNOWN is not a deny.
type AuthorizationDecision struct {
	ID                    string
	ScanID                string
	PrincipalARN          string
	Action                string
	ResourceARN           string
	ResourceAccountID     string
	Status                string
	Reason                string
	SameAccount           bool
	ApplicableStatements  []StatementRef
	ExplicitDeny          []StatementRef
	UnsatisfiedConditions []string
	MissingContext        []string
	MissingEvidence       []string
	Unsupported           []string
	Provenance            []string
	EvaluatedAt           time.Time
	EvaluatorVersion      string
	EvidenceFingerprint   string
	SimulatorNote         string
}
