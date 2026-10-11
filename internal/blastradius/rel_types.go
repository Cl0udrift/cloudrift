// Package blastradius implements Neo4j-backed blast-radius and attack-path analysis (v1).
// Traversal is limited to a fixed allowlist of relationship types; see [V1TraversalRels] and comments.
package blastradius

// V1TraversalRels is the topology allowlist. It is not an attack-path allowlist.
// Attack traversal uses AttackTraversalRels, which stays empty until a relationship is
// classified as a validated attacker transition. Identity exposure also walks unevaluated policy candidates.
//
// CAPTURED and AFFECTS stay out of every traversal: they bind findings to a scan.
// OWNED_BY may appear in topology as an account leaf. Variable-length walks reject paths
// that use an AwsAccount as an intermediate node, so ownership is not lateral movement.
var V1TraversalRels = []string{
	"TRUSTS",    // cross-principal / cross-account trust (privilege-escalation-relevant)
	"POINTS_TO", // directed infrastructure edges (e.g. DNS to target)
	"FRONTS",    // edge / CDN / fronting
	"USES_CERT", // certificate linkage
	"OWNED_BY",  // Asset → AwsAccount
}

// V1MaxHops is the default maximum length for variable-length graph patterns in Neo4j queries.
// Keep it small: blast radius is an explanation surface, not exhaustive graph discovery.
const V1MaxHops = 4

// V1ExplorerNodeCap is the default upper bound on distinct nodes in an explorer payload.
const V1ExplorerNodeCap = 80

// V1ExplorerEdgeCap bounds distinct relationships returned to the UI.
const V1ExplorerEdgeCap = 120
