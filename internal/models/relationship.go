package models

type RelType string

const (
	RelPointsTo         RelType = "POINTS_TO"
	RelOwnedBy          RelType = "OWNED_BY"
	RelUsesCert         RelType = "USES_CERT"
	RelFronts           RelType = "FRONTS"
	RelTrusts           RelType = "TRUSTS"
	RelPolicyAttachedTo RelType = "POLICY_ATTACHED_TO"
	// RelMemberOf links an IAM user (source) to a group (target). The user inherits the group policies.
	RelMemberOf                  RelType = "MEMBER_OF"
	RelPolicyContainsStatement   RelType = "POLICY_CONTAINS_STATEMENT"
	RelPolicyPermissionCandidate RelType = "POLICY_PERMISSION_CANDIDATE"
	RelHasAuthorizationDecision  RelType = "HAS_AUTHORIZATION_DECISION"
	// RelAuthorizationTargets links one decision to the collected target asset.
	// It is evidence for one action and one resource. It is not an access edge.
	RelAuthorizationTargets RelType = "AUTHORIZATION_TARGETS"
	// RelValidatedAttackTransition is a hypothetical hop whose authorization
	// prerequisites were evaluated and allowed. It is not a recorded incident.
	RelValidatedAttackTransition RelType = "VALIDATED_ATTACK_TRANSITION"
	// Workload attachment edges are configuration. They are not attacker transitions.
	RelEC2UsesInstanceProfile  RelType = "EC2_INSTANCE_USES_INSTANCE_PROFILE"
	RelInstanceProfileContains RelType = "INSTANCE_PROFILE_CONTAINS_ROLE"
	RelLambdaUsesExecutionRole RelType = "LAMBDA_USES_EXECUTION_ROLE"
	// Container identity edges are configuration. They are not attacker transitions.
	RelECSTaskDefUsesTaskRole      RelType = "ECS_TASK_DEFINITION_USES_TASK_ROLE"
	RelECSTaskDefUsesExecutionRole RelType = "ECS_TASK_DEFINITION_USES_EXECUTION_ROLE"
	RelECSTaskUsesTaskDef          RelType = "ECS_TASK_USES_TASK_DEFINITION"
	RelECSServiceRefsTaskDef       RelType = "ECS_SERVICE_REFERENCES_TASK_DEFINITION"
	RelEKSPodIdentityUsesRole      RelType = "EKS_POD_IDENTITY_USES_ROLE"
	RelEKSPodIdentityRefsSA        RelType = "EKS_POD_IDENTITY_REFERENCES_SERVICE_ACCOUNT"
	RelIRSATrustConfiguration      RelType = "IRSA_TRUST_CONFIGURATION"
)

type Relationship struct {
	SourceARN  string         `json:"source_arn"`
	TargetARN  string         `json:"target_arn"`
	RelType    RelType        `json:"rel_type"`
	Properties map[string]any `json:"properties"`
	ScanID     string         `json:"scan_id"`
}
