package schema

// BlastRootKind identifies what the analysis is centered on.
type BlastRootKind string

const (
	BlastRootFinding        BlastRootKind = "finding"
	BlastRootExternalEntity BlastRootKind = "external_entity"
	BlastRootPrincipal      BlastRootKind = "principal"
)

// BlastRadiusSummary is a lightweight, card-friendly view for findings / entities / high-signal.
type BlastRadiusSummary struct {
	RootType               BlastRootKind `json:"root_type"`
	RootID                 string        `json:"root_id"`
	ScanID                 string        `json:"scan_id"`
	Mode                   string        `json:"mode"`
	ReachableResourceCount int           `json:"reachable_resource_count"`
	ReachableAccountsCount int           `json:"reachable_accounts_count"`
	TopResourceTypes       []string      `json:"top_resource_types"`
	TopImpactedAccounts    []string      `json:"top_impacted_accounts"`
	TopImpactedResources   []string      `json:"top_impacted_resources"`
	// DominantMotif is a stable semantic motif for downstream consumers (alerts/UI), not inferred prose.
	DominantMotif          string `json:"dominant_motif,omitempty"`
	EscalationPossible     bool   `json:"escalation_possible"`
	SummaryText            string `json:"summary_text"`
	RecommendedActionLabel string `json:"recommended_action_label"`
	GraphAvailable         bool   `json:"graph_available"`
	// GraphUnavailableReason is empty when graphAvailable is true; otherwise a stable machine string.
	GraphUnavailableReason string `json:"graph_unavailable_reason,omitempty"`
	// AffectedARN is set for finding-root summaries when a focal resource exists in scan JSON.
	FocalResourceARN string `json:"focal_resource_arn,omitempty"`
	// SourceFindingID for finding-root responses.
	SourceFindingID string `json:"source_finding_id,omitempty"`
	// SourcePrincipalARN for principal-root responses.
	SourcePrincipalARN string `json:"source_principal_arn,omitempty"`
	// SourcePrincipalID is the encoded principal id for principal-root responses.
	SourcePrincipalID string `json:"source_principal_id,omitempty"`
	// SourceEntityID is the encoded id for external-entity roots.
	SourceEntityID string `json:"source_entity_id,omitempty"`
	// AnalysisKind is TOPOLOGY, IDENTITY_EXPOSURE, or ATTACK_PATH.
	// Mode keeps the existing API value (blast_radius, identity_exposure, attack_path).
	AnalysisKind string `json:"analysis_kind,omitempty"`
	// PathValidity is VALIDATED_POSSIBLE, CONDITIONAL, or UNKNOWN.
	// UNKNOWN means required evidence was not evaluated. It is not confirmed compromise.
	PathValidity string `json:"path_validity,omitempty"`
	// MissingPrerequisites names evidence this result still needs.
	MissingPrerequisites []string `json:"missing_prerequisites,omitempty"`
	// ConfirmedResourceCount is unique collected assets in this scan's result.
	// Unresolved references are excluded.
	ConfirmedResourceCount int `json:"confirmed_resource_count"`
	// UnresolvedReferenceCount is unique unresolved endpoints. They are not confirmed inventory.
	UnresolvedReferenceCount int `json:"unresolved_reference_count"`
	// AttackPathCount is the number of complete resource-impact paths for an identity-attack
	// result: a path that ends at a supported impacted resource. A role-assumption hop
	// alone is not a complete path. Graph modes still report the number of returned
	// path variants. Zero is an honest empty result, including a truncated search
	// that returned nothing.
	AttackPathCount int `json:"attack_path_count"`
	// ValidatedTransitionCount is distinct validated technique hops. A hop that
	// appears in several paths is counted once. Identity is source session,
	// technique, target, and authorization context.
	ValidatedTransitionCount int `json:"validated_transition_count"`
	// ReachableIdentityCount is additional IAM roles with a validated usable
	// session. The initial assumed role is excluded.
	ReachableIdentityCount int `json:"reachable_identity_count"`
	// AnalysisComplete is false when the selected question cannot be fully answered from stored evidence.
	AnalysisComplete bool `json:"analysis_complete"`
	// StartingAssumption states the attacker premise this result uses.
	StartingAssumption string `json:"starting_assumption,omitempty"`
	// PermissionBlast is set for permission_blast_radius. It is a hypothetical
	// impact assessment, not evidence the role was compromised.
	PermissionBlast *PermissionBlastReport `json:"permission_blast,omitempty"`
	// IdentityAttack is set for attack_path when the root is a collected IAM role.
	// Each hop is modeled authorization, not evidence that an attack occurred.
	IdentityAttack *IdentityAttackReport `json:"identity_attack,omitempty"`
}

// AttackTransition is one evaluated technique from one role session.
type AttackTransition struct {
	Technique            string   `json:"technique"`
	SourcePrincipal      string   `json:"source_principal"`
	TargetARN            string   `json:"target_arn"`
	Status               string   `json:"status"`
	Reason               string   `json:"reason"`
	DecisionID           string   `json:"decision_id,omitempty"`
	EvidenceFingerprint  string   `json:"evidence_fingerprint,omitempty"`
	ContextFingerprint   string   `json:"context_fingerprint,omitempty"`
	Evidence             []string `json:"evidence,omitempty"`
	MissingPrerequisites []string `json:"missing_prerequisites,omitempty"`
	SameAccount          bool     `json:"same_account"`
	Feasibility          string   `json:"feasibility"`
	Cycle                bool     `json:"cycle,omitempty"`
	Depth                int      `json:"depth"`
	SessionPolicyState   string   `json:"session_policy_state,omitempty"`
	// SessionOrigin is hypothetical_initial or modeled_assume_role.
	SessionOrigin string `json:"session_origin,omitempty"`
	// SessionEvidenceClass is scenario_assumption, verified_observation, or missing.
	// A role property named session_policy_status is a scenario assumption unless
	// its provenance says verified_observation.
	SessionEvidenceClass string `json:"session_evidence_class,omitempty"`
	// TransitionID identifies one attacker-state hop. It is not the authorization decision.
	// Paths that share a hop share this ID. A different session or technique does not.
	TransitionID string `json:"transition_id,omitempty"`
}

// AttackEscalation is a validated hop that gives a session more privilege than it started with.
// It is modeled capability from collected policy, not evidence that anyone did it.
type AttackEscalation struct {
	// Kind is SELF_POLICY_GRANT, TRUST_REWRITE or GRANT_ON_REACHABLE_ROLE.
	Kind            string `json:"kind"`
	SourcePrincipal string `json:"source_principal"`
	TargetARN       string `json:"target_arn"`
	Technique       string `json:"technique"`
	TransitionID    string `json:"transition_id,omitempty"`
	Depth           int    `json:"depth"`
	Explanation     string `json:"explanation"`
}

// IdentityAttackReport is a bounded search from one assumed role session.
type IdentityAttackReport struct {
	Assumption                 string             `json:"assumption"`
	InitialPrincipal           string             `json:"initial_principal"`
	SessionContextSource       string             `json:"session_context_source"`
	Transitions                []AttackTransition `json:"transitions,omitempty"`
	ValidatedRoleTransitions   int                `json:"validated_role_transitions"`
	ConditionalRoleTransitions int                `json:"conditional_role_transitions"`
	UnknownTransitions         int                `json:"unknown_transitions"`
	DeniedTransitions          int                `json:"denied_transitions"`
	ImpactedResources          []string           `json:"impacted_resources,omitempty"`
	// ValidatedTransitionCount counts distinct validated hops once.
	ValidatedTransitionCount int `json:"validated_transition_count"`
	// ResourceImpactPathCount is complete paths that end at a readable object.
	// AttackPathCount on the blast summary uses this value.
	ResourceImpactPathCount int `json:"resource_impact_path_count"`
	// ResourceImpactPathsDiscovered counts complete paths found, including ones
	// omitted after the path limit. When it exceeds ResourceImpactPathCount the
	// result is truncated.
	ResourceImpactPathsDiscovered int `json:"resource_impact_paths_discovered"`
	// ReachableIdentityCount excludes the initial role.
	ReachableIdentityCount  int                `json:"reachable_identity_count"`
	CrossAccountTransitions int                `json:"cross_account_transitions"`
	MissingPrerequisites    []string           `json:"missing_prerequisites,omitempty"`
	UnsupportedTechniques   []string           `json:"unsupported_techniques,omitempty"`
	Truncated               bool               `json:"truncated"`
	CoverageNotes           []string           `json:"coverage_notes,omitempty"`
	StatesExplored          int                `json:"states_explored"`
	Paths                   []BlastPathVariant `json:"paths,omitempty"`
	// PrivilegeEscalation is VALIDATED_POSSIBLE, NONE_FOUND_IN_MODELED_TECHNIQUES or NOT_ASSESSED.
	// NONE_FOUND covers only the modeled techniques. It is not a claim that no escalation exists.
	PrivilegeEscalation       string             `json:"privilege_escalation,omitempty"`
	Escalations               []AttackEscalation `json:"escalations,omitempty"`
	ValidatedIdentityMovement bool               `json:"validated_identity_movement"`
	ValidatedResourceAccess   bool               `json:"validated_resource_access"`
}

// PermissionDecision is one evaluated action against one concrete resource.
type PermissionDecision struct {
	Action              string   `json:"action"`
	Category            string   `json:"category"`
	ResourceARN         string   `json:"resource_arn"`
	AccountID           string   `json:"account_id,omitempty"`
	Status              string   `json:"status"`
	Reason              string   `json:"reason"`
	Evidence            []string `json:"evidence,omitempty"`
	SameAccount         bool     `json:"same_account"`
	Classification      string   `json:"classification,omitempty"`
	DecisionID          string   `json:"decision_id,omitempty"`
	EvidenceFingerprint string   `json:"evidence_fingerprint,omitempty"`
	// Explanation is a plain-language reason. The fields below are the raw facts behind it.
	Explanation          string   `json:"explanation,omitempty"`
	MissingEvidence      []string `json:"missing_evidence,omitempty"`
	MissingContext       []string `json:"missing_context,omitempty"`
	UnsatisfiedCondition []string `json:"unsatisfied_conditions,omitempty"`
	ExplicitDeny         []string `json:"explicit_deny,omitempty"`
	AppliedStatements    []string `json:"applied_statements,omitempty"`
}

// PermissionBucketScope records a bucket whose objects were not in the scan.
type PermissionBucketScope struct {
	BucketARN string `json:"bucket_arn"`
	AccountID string `json:"account_id,omitempty"`
	Note      string `json:"note"`
}

// PrivescChain is a set of calls that together give the caller another identity's privileges, such as
// iam:PassRole plus the service calls that return the passed role's credentials. Kind names the technique.
// Status is VALIDATED_ALLOWED only when every step is allowed.
type PrivescChain struct {
	Kind    string               `json:"kind"`
	Service string               `json:"service"`
	RoleARN string               `json:"role_arn"`
	Status  string               `json:"status"`
	Steps   []PermissionDecision `json:"steps"`
}

// PermissionBlastReport is the assumed-compromise permission impact for one role.
type PermissionBlastReport struct {
	AssumedCompromise              bool                    `json:"assumed_compromise"`
	Assumption                     string                  `json:"assumption"`
	RoleARN                        string                  `json:"role_arn"`
	AccountID                      string                  `json:"account_id,omitempty"`
	SessionContextSource           string                  `json:"session_context_source"`
	ResourcesEvaluated             int                     `json:"resources_evaluated"`
	AllowedResourceCount           int                     `json:"allowed_resource_count"`
	DeniedResourceCount            int                     `json:"denied_resource_count"`
	ConditionalResourceCount       int                     `json:"conditional_resource_count"`
	UnknownResourceCount           int                     `json:"unknown_resource_count"`
	UnresolvedReferenceCount       int                     `json:"unresolved_reference_count"`
	Decisions                      []PermissionDecision    `json:"decisions,omitempty"`
	PrivescChains                  []PrivescChain          `json:"privesc_chains,omitempty"`
	BucketScopes                   []PermissionBucketScope `json:"bucket_scopes,omitempty"`
	BroadPrivilegeCandidates       []string                `json:"broad_privilege_candidates,omitempty"`
	CrossAccountResourceARNs       []string                `json:"cross_account_resource_arns,omitempty"`
	SensitiveResourceARNs          []string                `json:"sensitive_resource_arns,omitempty"`
	UnsupportedActions             []string                `json:"unsupported_actions,omitempty"`
	CoverageNotes                  []string                `json:"coverage_notes,omitempty"`
	Truncated                      bool                    `json:"truncated"`
	AnalysisComplete               bool                    `json:"analysis_complete"`
	ImpactSummary                  string                  `json:"impact_summary"`
	PermissionBreadth              string                  `json:"permission_breadth"`
	ValidatedResourceImpact        int                     `json:"validated_resource_impact"`
	PotentialAdministrativeControl bool                    `json:"potential_administrative_control"`
	EvaluationCoverage             string                  `json:"evaluation_coverage"`
	EvidenceConfidence             string                  `json:"evidence_confidence"`
}

// BlastExplorerResponse is the visual explorer payload; still curated, not a raw Neo4j dump.
type BlastExplorerResponse struct {
	Focus          BlastFocus         `json:"focus"`
	Summary        BlastRadiusSummary `json:"summary"`
	Nodes          []BlastGraphNode   `json:"nodes"`
	Edges          []BlastGraphEdge   `json:"edges"`
	PathVariants   []BlastPathVariant `json:"path_variants,omitempty"`
	SelectedPathID string             `json:"selected_path_id,omitempty"`
	Display        BlastDisplayHints  `json:"display"`
}

// BlastFocus ties the visualization to one operational story.
type BlastFocus struct {
	RootID      string        `json:"root_id"`
	RootType    BlastRootKind `json:"root_type"`
	FindingID   string        `json:"finding_id,omitempty"`
	EntityID    string        `json:"entity_id,omitempty"`
	PrincipalID string        `json:"principal_id,omitempty"`
	Mode        string        `json:"mode,omitempty"`
	BlastMode   string        `json:"blast_mode,omitempty"`
}

// BlastGraphNode is a UI-scoped view of a graph row.
type BlastGraphNode struct {
	ID              string  `json:"id"`
	Label           string  `json:"label"`
	Type            string  `json:"type"`
	Subtype         string  `json:"subtype,omitempty"`
	AccountID       string  `json:"account_id,omitempty"`
	SeverityOrTier  string  `json:"severity_or_tier,omitempty"`
	IsFocus         bool    `json:"is_focus"`
	IsCriticalPath  bool    `json:"is_critical_path"`
	IsReachable     bool    `json:"is_reachable"`
	IsExternal      bool    `json:"is_external"`
	ImpactScore     float64 `json:"impact_score,omitempty"`
	DisplayNameHint string  `json:"display_name_hint,omitempty"`
	// ResolutionStatus is "collected" or "unresolved". Unresolved means the ARN was
	// referenced but not present in the scan asset set.
	ResolutionStatus string `json:"resolution_status,omitempty"`
	// OwnershipStatus is set for external principals: "known" or "unknown".
	OwnershipStatus string `json:"ownership_status,omitempty"`
	// Community and Centrality come from the GDS-written node properties (Louvain
	// community id, PageRank centrality) when the graph was clustered. Nil when GDS
	// analytics were not run, so the UI falls back to semantic coloring.
	Community  *int     `json:"community,omitempty"`
	Centrality *float64 `json:"centrality,omitempty"`
}

// BlastGraphEdge is a single directed relationship in the UI graph.
type BlastGraphEdge struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Target string `json:"target"`
	Type   string `json:"type"`
	Label  string `json:"label"`
	// GraphRelationship is the stored relationship type (TRUSTS, POINTS_TO, ...).
	// Type remains the existing semantic label for current dashboard clients.
	GraphRelationship string         `json:"graph_relationship,omitempty"`
	Properties        map[string]any `json:"properties,omitempty"`
	// RelationshipClass is the registry class (STRUCTURAL, TRUST_CONFIGURATION, ...).
	RelationshipClass string `json:"relationship_class,omitempty"`
	// PathValidity is the evidence state for treating this edge as attacker movement.
	PathValidity string `json:"path_validity,omitempty"`
	// MissingPrerequisites lists evidence required before this edge can be an attack transition.
	MissingPrerequisites []string `json:"missing_prerequisites,omitempty"`
	// Evidence lists facts the relationship actually records.
	Evidence       []string `json:"evidence,omitempty"`
	IsCriticalPath bool     `json:"is_critical_path"`
	Explanation    string   `json:"explanation,omitempty"`
}

// BlastDisplayHints nudges the camera and selection without exposing raw Cypher.
type BlastDisplayHints struct {
	DefaultFocusID   string   `json:"default_focus_id,omitempty"`
	HighlightNodeIDs []string `json:"highlight_node_ids,omitempty"`
	HighlightEdgeIDs []string `json:"highlight_edge_ids,omitempty"`
	HighlightPathIDs []string `json:"highlight_path_ids,omitempty"`
}

// BlastPathVariant is a compact path candidate for attack_path mode.
type BlastPathVariant struct {
	ID                string   `json:"id"`
	Label             string   `json:"label"`
	Kind              string   `json:"kind"` // "primary" | "alternate"
	Summary           string   `json:"summary"`
	NodeIDs           []string `json:"node_ids"`
	EdgeIDs           []string `json:"edge_ids"`
	DominantSemantics []string `json:"dominant_semantics,omitempty"`
	RiskHint          string   `json:"risk_hint,omitempty"`
	// Validity is the path feasibility state. Empty on older payloads.
	Validity string `json:"validity,omitempty"`
	// MissingPrerequisites lists evidence this chain still needs.
	MissingPrerequisites []string `json:"missing_prerequisites,omitempty"`
	// Evidence lists facts supporting the chain.
	Evidence []string `json:"evidence,omitempty"`
}

// BlastExplorerExpansionResponse returns a bounded one-hop delta for a selected node.
type BlastExplorerExpansionResponse struct {
	ExpandedFromNodeID     string            `json:"expanded_from_node_id"`
	ExpansionApplied       bool              `json:"expansion_applied"`
	ExpansionReason        string            `json:"expansion_reason,omitempty"`
	GraphUnavailable       bool              `json:"graph_unavailable"`
	GraphUnavailableReason string            `json:"graph_unavailable_reason,omitempty"`
	Nodes                  []BlastGraphNode  `json:"nodes,omitempty"`
	Edges                  []BlastGraphEdge  `json:"edges,omitempty"`
	Display                BlastDisplayHints `json:"display,omitempty"`
}
