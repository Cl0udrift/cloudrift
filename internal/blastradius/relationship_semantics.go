package blastradius

// RelationshipClass is the security meaning of a stored graph relationship.
// A class describes evidence, not confirmed attacker reachability.
type RelationshipClass string

const (
	ClassStructural                RelationshipClass = "STRUCTURAL"
	ClassTrustConfiguration        RelationshipClass = "TRUST_CONFIGURATION"
	ClassPolicyPermissionCandidate RelationshipClass = "POLICY_PERMISSION_CANDIDATE"
	ClassNetworkConnectivity       RelationshipClass = "NETWORK_CONNECTIVITY"
	ClassValidatedAttackTransition RelationshipClass = "VALIDATED_ATTACK_TRANSITION"
	ClassFindingMetadata           RelationshipClass = "FINDING_METADATA"
	ClassOwnershipMetadata         RelationshipClass = "OWNERSHIP_METADATA"
	ClassAuthorizationEvidence     RelationshipClass = "AUTHORIZATION_EVIDENCE"
)

// RelationshipSemantics is the registry entry for one stored relationship type.
type RelationshipSemantics struct {
	Type                string
	Class               RelationshipClass
	SourceSemantics     string
	TargetSemantics     string
	Direction           string
	TopologyTraversable bool
	IdentityTraversable bool
	AttackTraversable   bool
	NetworkRequired     bool
	RequiredEvidence    []string
	Limitations         string
}

// relationshipRegistry is the single classification of relationships the graph stores today.
// NETWORK_CONNECTIVITY has no stored type yet. VALIDATED_ATTACK_TRANSITION is written
// only after the evaluator allows a supported technique. Collectors do not emit it.
var relationshipRegistry = []RelationshipSemantics{
	{
		Type:                "POINTS_TO",
		Class:               ClassStructural,
		SourceSemantics:     "Resource that names another resource, typically a DNS record or alias.",
		TargetSemantics:     "Resource named by that dependency.",
		Direction:           "Source depends on target. The edge is not control of the target.",
		TopologyTraversable: true,
		NetworkRequired:     true,
		RequiredEvidence:    []string{"network_reachability", "validated_attack_transition"},
		Limitations:         "A DNS or alias dependency is not compromise and is not an attacker transition.",
	},
	{
		Type:                "FRONTS",
		Class:               ClassStructural,
		SourceSemantics:     "Edge or CDN distribution.",
		TargetSemantics:     "Origin or backend the distribution is configured to reference.",
		Direction:           "Front toward origin. Architectural dependency only.",
		TopologyTraversable: true,
		NetworkRequired:     true,
		RequiredEvidence:    []string{"network_reachability", "validated_attack_transition"},
		Limitations:         "Fronting configuration is not proof that an attacker controls the origin or the viewer path.",
	},
	{
		Type:                "USES_CERT",
		Class:               ClassStructural,
		SourceSemantics:     "Endpoint or distribution that references a certificate.",
		TargetSemantics:     "Certificate resource.",
		Direction:           "Consumer toward certificate.",
		TopologyTraversable: true,
		RequiredEvidence:    []string{"validated_attack_transition"},
		Limitations:         "Certificate association is structural. It is not attacker movement.",
	},
	{
		Type:                "TRUSTS",
		Class:               ClassTrustConfiguration,
		SourceSemantics:     "Role or resource whose trust or resource policy names a principal.",
		TargetSemantics:     "Principal named by that policy.",
		Direction:           "Trusting resource toward the named principal. This is not what the trusting resource can access, and it is not a completed AssumeRole.",
		TopologyTraversable: true,
		IdentityTraversable: true,
		RequiredEvidence:    []string{"iam_authorization", "trust_policy_conditions"},
		Limitations:         "TRUSTS records configuration. It does not evaluate Allow, explicit deny, conditions, session policy, permission boundary, or SCP, so it is not successful AssumeRole.",
	},
	{
		Type:                "OWNED_BY",
		Class:               ClassOwnershipMetadata,
		SourceSemantics:     "Asset placed in an account by the scan.",
		TargetSemantics:     "AwsAccount that owns the asset.",
		Direction:           "Asset toward its account. The account is a leaf in topology traversal.",
		TopologyTraversable: true,
		RequiredEvidence:    []string{"validated_attack_transition"},
		Limitations:         "Ownership is not access. Traversal must not continue through the account into other assets.",
	},
	{
		Type:            "AFFECTS",
		Class:           ClassFindingMetadata,
		SourceSemantics: "Finding.",
		TargetSemantics: "Asset the finding names.",
		Direction:       "Finding toward asset.",
		Limitations:     "A finding link is metadata. It is not an attacker transition.",
	},
	{
		Type:            "CAPTURED",
		Class:           ClassFindingMetadata,
		SourceSemantics: "Scan snapshot.",
		TargetSemantics: "Finding recorded by that scan.",
		Direction:       "Scan toward finding.",
		Limitations:     "Scan membership is metadata. It is not traversable for topology or attack analysis.",
	},
	{
		Type:                "POLICY_ATTACHED_TO",
		Class:               ClassPolicyPermissionCandidate,
		SourceSemantics:     "IAM role the policy is attached to.",
		TargetSemantics:     "Inline or managed policy document collected for that role.",
		Direction:           "Role toward policy. Attachment is not authorization.",
		IdentityTraversable: true,
		RequiredEvidence:    []string{"effective_iam_authorization"},
		Limitations:         "A policy attachment shows which document was collected. It does not grant effective access.",
	},
	{
		Type:                "POLICY_CONTAINS_STATEMENT",
		Class:               ClassPolicyPermissionCandidate,
		SourceSemantics:     "Policy document.",
		TargetSemantics:     "Normalized statement inside that document.",
		Direction:           "Policy toward statement.",
		IdentityTraversable: true,
		RequiredEvidence:    []string{"effective_iam_authorization"},
		Limitations:         "A statement is policy text. Effect Allow is not effective permission.",
	},
	{
		Type:                "POLICY_PERMISSION_CANDIDATE",
		Class:               ClassPolicyPermissionCandidate,
		SourceSemantics:     "IAM role that carries the identity policy.",
		TargetSemantics:     "Normalized policy statement. The resource field is an expression, not a confirmed asset.",
		Direction:           "Role toward the statement that names the action and resource expression.",
		IdentityTraversable: true,
		RequiredEvidence:    []string{"effective_iam_authorization"},
		Limitations:         "Candidate permission only. An explicit Deny, SCP, RCP, permission boundary, resource policy, session policy, or condition may block the action. This is not a validated attack transition.",
	},
	{
		Type:            "HAS_AUTHORIZATION_DECISION",
		Class:           ClassAuthorizationEvidence,
		SourceSemantics: "IAM principal the decision was evaluated for.",
		TargetSemantics: "One authorization decision for one action, one concrete resource, and one request context.",
		Direction:       "Principal toward the decision record. The decision is evidence, not an access edge and not an attacker transition.",
		RequiredEvidence: []string{
			"attacker_principal_control",
			"attack_technique_preconditions",
		},
		Limitations: "A validated allow means the modeled request is allowed under the evaluated scope. It does not mean the principal is compromised or that an attack path exists.",
	},
	{
		Type:            "AUTHORIZATION_TARGETS",
		Class:           ClassAuthorizationEvidence,
		SourceSemantics: "One authorization decision for one action, one concrete resource, and one request context.",
		TargetSemantics: "Collected asset the decision names. The asset must already exist in the scan.",
		Direction:       "Decision toward the collected target. This is not an access edge and not an attacker transition.",
		RequiredEvidence: []string{
			"attacker_principal_control",
			"attack_technique_preconditions",
		},
		Limitations: "The Go evaluator produced this fact. The relationship does not grant permission, and denied, conditional, and unknown decisions are not attack transitions.",
	},
	{
		Type:                "EC2_INSTANCE_USES_INSTANCE_PROFILE",
		Class:               ClassStructural,
		SourceSemantics:     "EC2 instance.",
		TargetSemantics:     "IAM instance profile associated with that instance.",
		Direction:           "Instance toward the associated profile.",
		TopologyTraversable: true,
		RequiredEvidence:    []string{"ec2:DescribeIamInstanceProfileAssociations"},
		Limitations:         "CONFIGURED_ROLE_ATTACHMENT. The association is not stolen metadata credentials and is not an attacker transition.",
	},
	{
		Type:                "INSTANCE_PROFILE_CONTAINS_ROLE",
		Class:               ClassStructural,
		SourceSemantics:     "IAM instance profile.",
		TargetSemantics:     "IAM role returned by iam:GetInstanceProfile.",
		Direction:           "Profile toward the role it contains.",
		TopologyTraversable: true,
		RequiredEvidence:    []string{"iam:GetInstanceProfile"},
		Limitations:         "The role is not inferred from the profile name. This edge is not an attacker transition.",
	},
	{
		Type:                "LAMBDA_USES_EXECUTION_ROLE",
		Class:               ClassStructural,
		SourceSemantics:     "Lambda function configuration.",
		TargetSemantics:     "Execution role ARN on that function configuration.",
		Direction:           "Function toward its configured execution role.",
		TopologyTraversable: true,
		RequiredEvidence:    []string{"lambda:ListFunctions"},
		Limitations:         "Function configuration is not a version-specific role and is not proof the function is invokable or compromised.",
	},
	{
		Type:                "ECS_TASK_DEFINITION_USES_TASK_ROLE",
		Class:               ClassStructural,
		SourceSemantics:     "ECS task definition revision.",
		TargetSemantics:     "IAM task role named by that revision.",
		Direction:           "Task definition toward the application task role.",
		TopologyTraversable: true,
		RequiredEvidence:    []string{"ecs:DescribeTaskDefinition"},
		Limitations:         "TASK_DEFINITION_CONFIGURATION. This is not a running task and not an attacker transition. Permissions are not attributed to the execution role.",
	},
	{
		Type:                "ECS_TASK_DEFINITION_USES_EXECUTION_ROLE",
		Class:               ClassStructural,
		SourceSemantics:     "ECS task definition revision.",
		TargetSemantics:     "IAM execution role named by that revision.",
		Direction:           "Task definition toward the execution role.",
		TopologyTraversable: true,
		RequiredEvidence:    []string{"ecs:DescribeTaskDefinition"},
		Limitations:         "The execution role is used by ECS infrastructure. It is not the application task identity and not an attacker transition.",
	},
	{
		Type:                "ECS_TASK_USES_TASK_DEFINITION",
		Class:               ClassStructural,
		SourceSemantics:     "Collected ECS task.",
		TargetSemantics:     "The task-definition revision that task reports.",
		Direction:           "Task toward the revision it reports.",
		TopologyTraversable: true,
		RequiredEvidence:    []string{"ecs:DescribeTasks"},
		Limitations:         "OBSERVED_TASK_CONFIGURATION for that revision. A newer task-definition revision is not substituted. This is not an attacker transition.",
	},
	{
		Type:                "ECS_SERVICE_REFERENCES_TASK_DEFINITION",
		Class:               ClassStructural,
		SourceSemantics:     "ECS service.",
		TargetSemantics:     "Task definition referenced by the service or one of its deployments.",
		Direction:           "Service toward the referenced revision.",
		TopologyTraversable: true,
		RequiredEvidence:    []string{"ecs:DescribeServices"},
		Limitations:         "SERVICE_CONFIGURATION. A reference does not prove a task is running. This is not an attacker transition.",
	},
	{
		Type:                "EKS_POD_IDENTITY_USES_ROLE",
		Class:               ClassStructural,
		SourceSemantics:     "EKS Pod Identity association.",
		TargetSemantics:     "IAM role returned by eks:DescribePodIdentityAssociation.",
		Direction:           "Association toward the configured role.",
		TopologyTraversable: true,
		RequiredEvidence:    []string{"eks:DescribePodIdentityAssociation"},
		Limitations:         "The association can name a service account that is not present in the cluster. It is not proof a running Pod uses the role and not an attacker transition.",
	},
	{
		Type:                "EKS_POD_IDENTITY_REFERENCES_SERVICE_ACCOUNT",
		Class:               ClassStructural,
		SourceSemantics:     "EKS Pod Identity association.",
		TargetSemantics:     "Namespace and service account named by the association. This is not a collected Kubernetes object.",
		Direction:           "Association toward the named service account reference.",
		TopologyTraversable: true,
		RequiredEvidence:    []string{"eks:ListPodIdentityAssociations"},
		Limitations:         "No Pod is invented from this reference. Kubernetes attachment is NOT_COLLECTED.",
	},
	{
		Type:                "IRSA_TRUST_CONFIGURATION",
		Class:               ClassStructural,
		SourceSemantics:     "IRSA trust configuration derived from a collected role trust policy and a cluster OIDC issuer.",
		TargetSemantics:     "IAM role that trusts the cluster OIDC provider for AssumeRoleWithWebIdentity.",
		Direction:           "Trust configuration toward the role.",
		TopologyTraversable: true,
		RequiredEvidence:    []string{"eks:DescribeCluster", "iam trust policy"},
		Limitations:         "IRSA_TRUST_CONFIGURATION is not IRSA_SERVICE_ACCOUNT_ATTACHMENT and not IRSA_POD_USAGE. AssumeRoleWithWebIdentity is not sts:AssumeRole. This edge is not an attacker transition.",
	},
	{
		Type:              "VALIDATED_ATTACK_TRANSITION",
		Class:             ClassValidatedAttackTransition,
		SourceSemantics:   "Controlled role session that the search started from or acquired through a validated AssumeRole hop.",
		TargetSemantics:   "Collected role or S3 object named by one evaluated technique.",
		Direction:         "Current session toward the target of sts:AssumeRole or s3:GetObject. The edge is hypothetical capability, not a security event.",
		AttackTraversable: true,
		RequiredEvidence: []string{
			"validated_iam_authorization",
			"technique_preconditions",
			"distinct_target_session_for_assume_role",
		},
		Limitations: "Present only when the evaluator returned VALIDATED_ALLOWED for that session, action, and target. TRUSTS, policy candidates, and authorization-decision edges are not this relationship. It does not mean an attack occurred.",
	},
}

// unrepresentedClasses are security classes this phase can name and cannot yet traverse,
// because no collector writes a relationship of that class.
var unrepresentedClasses = []RelationshipClass{
	ClassNetworkConnectivity,
}

// RelationshipSemanticsFor returns the registry entry for a stored relationship type.
func RelationshipSemanticsFor(relType string) (RelationshipSemantics, bool) {
	for _, entry := range relationshipRegistry {
		if entry.Type == relType {
			return entry, true
		}
	}
	return RelationshipSemantics{}, false
}

// AllRelationshipSemantics returns the stored-type registry in stable order.
func AllRelationshipSemantics() []RelationshipSemantics {
	out := make([]RelationshipSemantics, len(relationshipRegistry))
	copy(out, relationshipRegistry)
	return out
}

// UnrepresentedRelationshipClasses returns classes with no stored relationship yet.
func UnrepresentedRelationshipClasses() []RelationshipClass {
	out := make([]RelationshipClass, len(unrepresentedClasses))
	copy(out, unrepresentedClasses)
	return out
}

// TopologyTraversalRels are relationship types a topology walk may follow.
// OWNED_BY is included only as an account leaf; variable-length queries must not
// use an AwsAccount as an intermediate node.
func TopologyTraversalRels() []string {
	return relsWhere(func(s RelationshipSemantics) bool { return s.TopologyTraversable })
}

// IdentityExposureRels are trust-configuration edges. They are unevaluated access candidates.
func IdentityExposureRels() []string {
	return relsWhere(func(s RelationshipSemantics) bool { return s.IdentityTraversable })
}

// AttackTraversalRels are validated attacker transitions. TRUSTS and policy candidates stay out.
func AttackTraversalRels() []string {
	return relsWhere(func(s RelationshipSemantics) bool { return s.AttackTraversable })
}

func relsWhere(pred func(RelationshipSemantics) bool) []string {
	var out []string
	for _, entry := range relationshipRegistry {
		if pred(entry) {
			out = append(out, entry.Type)
		}
	}
	return out
}

func traversalRels(mode BlastMode) []string {
	switch mode {
	case ModeAttackPath:
		return AttackTraversalRels()
	case ModeIdentityExposure:
		return IdentityExposureRels()
	default:
		return TopologyTraversalRels()
	}
}
