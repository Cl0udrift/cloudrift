package blastradius

// BlastMode selects which question the explorer answers.
// blast_radius is topology. identity_exposure is unevaluated trust configuration.
// attack_path contains only evidence-backed attacker transitions.
type BlastMode string

const (
	ModeBlastRadius      BlastMode = "blast_radius"
	ModeIdentityExposure BlastMode = "identity_exposure"
	ModeAttackPath       BlastMode = "attack_path"
	// ModePermissionBlast is a hypothetical permission impact assessment.
	// It does not replace topology, identity exposure, or attack path.
	ModePermissionBlast BlastMode = "permission_blast_radius"
)

// UnavailableReason is returned when Neo4j is not configured, connectivity fails, or
// the scan projection does not include the start node.
type UnavailableReason string

const (
	ReasonNone              UnavailableReason = ""
	ReasonNeo4jDisabled     UnavailableReason = "neo4j_unconfigured"
	ReasonNeo4jConnectError UnavailableReason = "neo4j_unavailable"
	ReasonNoGraphProjection UnavailableReason = "no_graph_projection"
	ReasonUnknownRoot       UnavailableReason = "unknown_root"
)
