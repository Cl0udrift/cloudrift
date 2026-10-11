package blastradius

import (
	"strings"
	"testing"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
)

func TestRelationshipRegistry_ClassifiesStoredTypes(t *testing.T) {
	want := map[string]RelationshipClass{
		"POINTS_TO":                   ClassStructural,
		"FRONTS":                      ClassStructural,
		"USES_CERT":                   ClassStructural,
		"TRUSTS":                      ClassTrustConfiguration,
		"OWNED_BY":                    ClassOwnershipMetadata,
		"AFFECTS":                     ClassFindingMetadata,
		"CAPTURED":                    ClassFindingMetadata,
		"POLICY_ATTACHED_TO":          ClassPolicyPermissionCandidate,
		"POLICY_CONTAINS_STATEMENT":   ClassPolicyPermissionCandidate,
		"POLICY_PERMISSION_CANDIDATE": ClassPolicyPermissionCandidate,
		"HAS_AUTHORIZATION_DECISION":  ClassAuthorizationEvidence,
		"AUTHORIZATION_TARGETS":       ClassAuthorizationEvidence,
	}
	for typ, class := range want {
		got, ok := RelationshipSemanticsFor(typ)
		if !ok {
			t.Fatalf("missing registry entry %s", typ)
		}
		if got.Class != class {
			t.Fatalf("%s class %s", typ, got.Class)
		}
		if got.AttackTraversable {
			t.Fatalf("%s must not be an attacker transition", typ)
		}
		if got.Direction == "" || got.Limitations == "" {
			t.Fatalf("%s missing direction or limitations", typ)
		}
	}
	for _, class := range UnrepresentedRelationshipClasses() {
		switch class {
		case ClassNetworkConnectivity:
		default:
			t.Fatalf("unexpected unrepresented class %s", class)
		}
	}
	attackRels := AttackTraversalRels()
	if len(attackRels) != 1 || attackRels[0] != "VALIDATED_ATTACK_TRANSITION" {
		t.Fatalf("attack allowlist: %v", attackRels)
	}
	validated, ok := RelationshipSemanticsFor("VALIDATED_ATTACK_TRANSITION")
	if !ok || !validated.AttackTraversable || validated.TopologyTraversable || validated.IdentityTraversable {
		t.Fatalf("validated transition flags: %+v", validated)
	}
	got := IdentityExposureRels()
	wantIdentity := []string{"TRUSTS", "POLICY_ATTACHED_TO", "POLICY_CONTAINS_STATEMENT", "POLICY_PERMISSION_CANDIDATE"}
	if strings.Join(got, ",") != strings.Join(wantIdentity, ",") {
		t.Fatalf("identity exposure rels: %v", got)
	}
	for _, typ := range []string{"POLICY_ATTACHED_TO", "POLICY_CONTAINS_STATEMENT", "POLICY_PERMISSION_CANDIDATE"} {
		sem, _ := RelationshipSemanticsFor(typ)
		if sem.TopologyTraversable || sem.AttackTraversable || !sem.IdentityTraversable {
			t.Fatalf("%s traversal flags: %+v", typ, sem)
		}
	}
}

func TestTrustsAloneIsNotAssumeRole(t *testing.T) {
	const role = "arn:aws:iam::111111111111:role/A"
	const other = "arn:aws:iam::111111111111:role/B"
	g := trustsGraph(role, other)
	sum := BuildSummaryPayload(schema.BlastRootPrincipal, role, "scan-a", ModeAttackPath, g, role, "", PrivilegeSignals{}, true, ReasonNone)
	if sum.EscalationPossible || sum.AttackPathCount != 0 || sum.PathValidity != string(ValidityUnknown) {
		t.Fatalf("TRUSTS became an attack path: %+v", sum)
	}
	if !containsAll(sum.MissingPrerequisites, prereqIAMAuthorization, prereqTrustConditions) {
		t.Fatalf("missing IAM prerequisites: %v", sum.MissingPrerequisites)
	}
	variants, _, _ := buildPathVariants(role, g, ModeAttackPath)
	if len(variants) != 0 {
		t.Fatalf("variants: %#v", variants)
	}
	ex := BuildExplorerPayload(sum, role, ModeBlastRadius, "", g)
	for _, e := range ex.Edges {
		if e.GraphRelationship != "TRUSTS" {
			continue
		}
		if e.Type != "ASSUME_ROLE" || e.RelationshipClass != string(ClassTrustConfiguration) || e.PathValidity != string(ValidityUnknown) {
			t.Fatalf("edge semantics: %#v", e)
		}
	}
}

func TestOwnedByAloneIsNotLateralMovement(t *testing.T) {
	const role = "arn:aws:iam::111111111111:role/A"
	g := newWorkingGraph()
	g.addTriples([]PathTriple{{Src: role, Dst: "account:111111111111", Type: "OWNED_BY"}})
	sum := BuildSummaryPayload(schema.BlastRootPrincipal, role, "scan-a", ModeAttackPath, g, role, "", PrivilegeSignals{}, true, ReasonNone)
	if sum.AttackPathCount != 0 || sum.EscalationPossible || sum.ReachableResourceCount != 0 {
		t.Fatalf("ownership counted as movement: %+v", sum)
	}
	topo := BuildSummaryPayload(schema.BlastRootPrincipal, role, "scan-a", ModeBlastRadius, g, role, "", PrivilegeSignals{}, true, ReasonNone)
	if topo.ConfirmedResourceCount != 1 {
		t.Fatalf("topology should keep the one collected asset, got %+v", topo)
	}
}

func TestPointsToAloneIsNotCompromise(t *testing.T) {
	const src = "arn:aws:route53:::record/a"
	const dst = "arn:aws:s3:::bucket"
	g := newWorkingGraph()
	g.addEdge(src, dst, "POINTS_TO")
	sum := BuildSummaryPayload(schema.BlastRootFinding, "f1", "scan-a", ModeAttackPath, g, src, "f1", PrivilegeSignals{}, true, ReasonNone)
	if sum.AttackPathCount != 0 || sum.PathValidity != string(ValidityUnknown) {
		t.Fatalf("POINTS_TO counted as compromise: %+v", sum)
	}
	if !containsAll(sum.MissingPrerequisites, prereqNetworkReachability) {
		t.Fatalf("network prerequisite missing: %v", sum.MissingPrerequisites)
	}
}

func TestUsesCertIsNotReachability(t *testing.T) {
	g := newWorkingGraph()
	g.addEdge("arn:aws:cloudfront::111:distribution/E", "arn:aws:acm::111:certificate/C", "USES_CERT")
	sum := BuildSummaryPayload(schema.BlastRootFinding, "f1", "scan-a", ModeAttackPath, g, "arn:aws:cloudfront::111:distribution/E", "f1", PrivilegeSignals{}, true, ReasonNone)
	if sum.AttackPathCount != 0 || sum.EscalationPossible {
		t.Fatalf("USES_CERT counted as reachability: %+v", sum)
	}
	a := assessRelationship(g, rawEdge{Src: "arn:aws:cloudfront::111:distribution/E", Tgt: "arn:aws:acm::111:certificate/C", Type: "USES_CERT"})
	if a.Class != ClassStructural || a.Validity != ValidityUnknown {
		t.Fatalf("assessment: %+v", a)
	}
}

func TestMissingIAMAuthorizationIsUnknown(t *testing.T) {
	validity, missing := validityFromEvidence(TransitionEvidence{
		Class:             ClassTrustConfiguration,
		InventoryResolved: true,
	})
	if validity != ValidityUnknown || !containsAll(missing, prereqIAMAuthorization) {
		t.Fatalf("got %s %v", validity, missing)
	}
}

func TestMissingNetworkValidationIsUnknown(t *testing.T) {
	validity, missing := validityFromEvidence(TransitionEvidence{
		Class:             ClassStructural,
		InventoryResolved: true,
		NetworkRequired:   true,
	})
	if validity != ValidityUnknown || !containsAll(missing, prereqNetworkReachability) {
		t.Fatalf("got %s %v", validity, missing)
	}
}

func TestValidatedPossibleRequiresEveryPrerequisite(t *testing.T) {
	ok, missing := validityFromEvidence(TransitionEvidence{
		Class:                     ClassValidatedAttackTransition,
		InventoryResolved:         true,
		IAMAuthorizationEvaluated: true,
		IAMAllowed:                true,
		ConditionsEvaluated:       true,
		ConditionsSatisfied:       true,
		NetworkRequired:           true,
		NetworkEvaluated:          true,
		NetworkReachable:          true,
	})
	if ok != ValidityValidatedPossible || len(missing) != 0 {
		t.Fatalf("fully evaluated transition: %s %v", ok, missing)
	}
	partial, missing := validityFromEvidence(TransitionEvidence{
		Class:                     ClassValidatedAttackTransition,
		InventoryResolved:         true,
		IAMAuthorizationEvaluated: true,
		IAMAllowed:                true,
		NetworkRequired:           true,
	})
	if partial != ValidityConditional || !containsAll(missing, prereqTrustConditions, prereqNetworkReachability) {
		t.Fatalf("partial evidence should stay conditional: %s %v", partial, missing)
	}
	unknown, _ := validityFromEvidence(TransitionEvidence{
		Class:             ClassValidatedAttackTransition,
		InventoryResolved: false,
		IAMAllowed:        true,
	})
	if unknown != ValidityUnknown {
		t.Fatalf("unresolved inventory became %s", unknown)
	}
}

func TestUnresolvedAssetsAreNotConfirmedImpact(t *testing.T) {
	const role = "arn:aws:iam::111111111111:role/A"
	const missing = "arn:aws:acm::111:certificate/missing"
	g := newWorkingGraph()
	g.AddAssetNode(role, "111111111111", "iam_role", "A", "global", "scan-a")
	g.addNode(missing, missing, "asset", map[string]any{
		"asset_type":        "unresolved_reference",
		"resolution_status": "unresolved",
	})
	g.addEdge(role, missing, "USES_CERT")
	sum := BuildSummaryPayload(schema.BlastRootFinding, "f1", "scan-a", ModeBlastRadius, g, role, "f1", PrivilegeSignals{}, true, ReasonNone)
	if sum.UnresolvedReferenceCount != 1 || sum.ConfirmedResourceCount != 1 {
		t.Fatalf("census: %+v", sum)
	}
	if sum.AnalysisComplete {
		t.Fatalf("unresolved inventory should keep topology analysis incomplete")
	}
	for _, arn := range sum.TopImpactedResources {
		if arn == missing {
			t.Fatalf("unresolved asset listed as impacted: %v", sum.TopImpactedResources)
		}
	}
	ex := BuildExplorerPayload(sum, role, ModeBlastRadius, "f1", g)
	for _, n := range ex.Nodes {
		if n.ID == missing && (n.IsReachable || n.ResolutionStatus != "unresolved") {
			t.Fatalf("unresolved node presented as reachable: %#v", n)
		}
	}
}

func TestMultiplePathsDoNotDoubleCount(t *testing.T) {
	const root = "arn:aws:iam::111111111111:role/Root"
	const mid = "arn:aws:iam::111111111111:role/Mid"
	const bucket = "arn:aws:s3:::once"
	g := newWorkingGraph()
	g.AddAssetNode(root, "111111111111", "iam_role", "Root", "global", "scan-a")
	g.AddAssetNode(mid, "111111111111", "iam_role", "Mid", "global", "scan-a")
	g.AddAssetNode(bucket, "111111111111", "s3_bucket", "once", "global", "scan-a")
	g.addEdge(root, bucket, "POINTS_TO")
	g.addEdge(root, mid, "FRONTS")
	g.addEdge(mid, bucket, "POINTS_TO")
	sum := BuildSummaryPayload(schema.BlastRootPrincipal, root, "scan-a", ModeBlastRadius, g, root, "", PrivilegeSignals{}, true, ReasonNone)
	if sum.ConfirmedResourceCount != 3 || sum.ReachableResourceCount != 3 {
		t.Fatalf("unique census: %+v", sum)
	}
	seen := map[string]int{}
	for _, arn := range sum.TopImpactedResources {
		seen[arn]++
		if seen[arn] > 1 {
			t.Fatalf("resource repeated: %v", sum.TopImpactedResources)
		}
	}
}

func TestCrossAccountTrustStaysConfiguration(t *testing.T) {
	const role = "arn:aws:iam::111111111111:role/Vendor"
	const ext = "arn:cloudrift:external-principal:::aws_account/vendor"
	g := newWorkingGraph()
	g.AddAssetNode(role, "111111111111", "iam_role", "Vendor", "global", "s1")
	g.AddAssetNode(ext, "222222222222", "external_principal", "arn:aws:iam::222222222222:root", "global", "s1")
	g.addEdgeWithProps(role, ext, "TRUSTS", map[string]any{"external_account_id": "222222222222"})
	e := g.Edges[edgeKey(role, "TRUSTS", ext)]
	if semanticEdgeType(g, e) != "EXTERNAL_TRUST" || !isCrossAccountEdge(g, e) {
		t.Fatal("cross-account external trust classification changed")
	}
	a := assessRelationship(g, e)
	if a.Validity != ValidityUnknown || a.Class != ClassTrustConfiguration {
		t.Fatalf("assessment: %+v", a)
	}
	sum := BuildSummaryPayload(schema.BlastRootPrincipal, role, "s1", ModeAttackPath, g, role, "", PrivilegeSignals{}, true, ReasonNone)
	if sum.AttackPathCount != 0 || sum.DominantMotif != "" {
		t.Fatalf("cross-account trust became a motif: %+v", sum)
	}
}

func TestTopologyExplorerStillReturnsRelationships(t *testing.T) {
	const role = "arn:aws:iam::111111111111:role/A"
	g := trustsGraph(role, "arn:aws:iam::111111111111:role/B")
	g.addEdge(role, "arn:aws:s3:::logs", "POINTS_TO")
	sum := BuildSummaryPayload(schema.BlastRootFinding, "f1", "scan-a", ModeBlastRadius, g, role, "f1", PrivilegeSignals{}, true, ReasonNone)
	ex := BuildExplorerPayload(sum, role, ModeBlastRadius, "f1", g)
	if len(ex.Edges) < 2 || len(ex.Nodes) < 2 {
		t.Fatalf("topology payload dropped relationships: nodes=%d edges=%d", len(ex.Nodes), len(ex.Edges))
	}
	if ex.Summary.Mode != "blast_radius" || ex.Focus.BlastMode != "blast_radius" {
		t.Fatalf("existing mode field changed: %+v", ex.Focus)
	}
}

func TestExpandQueriesKeepScanIsolation(t *testing.T) {
	for _, q := range []string{cypherExpandBlastRadius, cypherExpandAttackPath, cypherExpandOneHop} {
		if strings.Count(q, "$scan_id") < 2 {
			t.Fatalf("scan scope missing:\n%s", q)
		}
	}
}

func trustsGraph(src, dst string) *workingGraph {
	g := newWorkingGraph()
	g.AddAssetNode(src, "111111111111", "iam_role", "src", "global", "scan-a")
	g.AddAssetNode(dst, "111111111111", "iam_role", "dst", "global", "scan-a")
	g.addEdge(src, dst, "TRUSTS")
	return g
}

func containsAll(got []string, want ...string) bool {
	set := map[string]struct{}{}
	for _, g := range got {
		set[g] = struct{}{}
	}
	for _, w := range want {
		if _, ok := set[w]; !ok {
			return false
		}
	}
	return true
}
