package blastradius

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestEncodeDecodeExternalEntityID(t *testing.T) {
	id := EncodeExternalEntityID("arn:aws:iam::1:root", "oidc", "ext-9")
	ep, pt, ea, ok := DecodeExternalEntityID(id)
	if !ok || ep != "arn:aws:iam::1:root" || pt != "oidc" || ea != "ext-9" {
		t.Fatalf("decode: ok=%v ep=%q pt=%q ea=%q", ok, ep, pt, ea)
	}
	matched := MatchExternalEntityFindings([]models.Finding{
		{
			Module: models.ModuleExternalAccess,
			Evidence: map[string]any{
				"external_principal":  "arn:aws:iam::1:root",
				"principal_type":      "OIDC",
				"external_account_id": "ext-9",
				"role_arn":            "arn:aws:iam::2:role/R",
			},
			AffectedARN: "arn:aws:iam::2:role/R",
		},
	}, ep, pt, ea)
	if len(matched) != 1 {
		t.Fatalf("match count %d", len(matched))
	}
}

func TestBuildSummaryPayload_unavailableGraph(t *testing.T) {
	s := BuildSummaryPayload(
		schema.BlastRootFinding,
		"f1",
		"scan-a",
		ModeBlastRadius,
		nil,
		"",
		"f1",
		PrivilegeSignals{AdminLike: true},
		false,
		ReasonNeo4jDisabled,
	)
	if s.GraphAvailable || s.ReachableResourceCount != 0 {
		t.Fatalf("graph off: %+v", s)
	}
	if s.GraphUnavailableReason != string(ReasonNeo4jDisabled) {
		t.Fatalf("reason: %q", s.GraphUnavailableReason)
	}
	if s.EscalationPossible != true {
		t.Fatalf("escalation from evidence should pass through when graph nil")
	}
}

func TestBuildSummaryPayload_withGraph(t *testing.T) {
	g := newWorkingGraph()
	g.addTriples([]PathTriple{
		{Src: "arn:a:role/A", Dst: "arn:a:role/B", Type: "TRUSTS"},
		{Src: "arn:a:role/B", Dst: "account:222", Type: "OWNED_BY"},
	})
	s := BuildSummaryPayload(
		schema.BlastRootFinding,
		"f1",
		"scan-a",
		ModeBlastRadius,
		g,
		"arn:a:role/A",
		"f1",
		PrivilegeSignals{},
		true,
		ReasonNone,
	)
	if !s.GraphAvailable || s.EscalationPossible {
		t.Fatalf("TRUSTS is configuration, not escalation: %+v", s)
	}
	if s.ReachableResourceCount < 1 || s.ReachableAccountsCount < 1 {
		t.Fatalf("counts: %+v", s)
	}
	if s.DominantMotif != "" || s.PathValidity != string(ValidityUnknown) || s.AnalysisKind != "TOPOLOGY" {
		t.Fatalf("topology must stay unevaluated: %+v", s)
	}
	if s.AttackPathCount != 0 {
		t.Fatalf("topology must not invent attack paths: %+v", s)
	}
}

func TestBuildExplorerPayload_criticalHighlights(t *testing.T) {
	g := newWorkingGraph()
	g.addTriples([]PathTriple{
		{Src: "arn:x:role/F", Dst: "arn:x:role/Y", Type: "TRUSTS"},
	})
	sum := BuildSummaryPayload(schema.BlastRootFinding, "f1", "s", ModeBlastRadius, g, "arn:x:role/F", "f1", PrivilegeSignals{AdminLike: true}, true, ReasonNone)
	ex := BuildExplorerPayload(sum, "arn:x:role/F", ModeBlastRadius, "f1", g)
	if len(ex.Nodes) == 0 || len(ex.Edges) == 0 {
		t.Fatalf("expected nodes/edges, got %d %d", len(ex.Nodes), len(ex.Edges))
	}
	var trustEdge bool
	for _, e := range ex.Edges {
		if e.Type == "ASSUME_ROLE" && e.IsCriticalPath {
			trustEdge = true
		}
	}
	if !trustEdge {
		t.Fatalf("ASSUME_ROLE should be critical path: %#v", ex.Edges)
	}
}

func TestPrincipalIDEncodeDecodeRoundTrip(t *testing.T) {
	arn := "arn:aws:iam::123456789012:role/SecurityAudit"
	pid := EncodePrincipalID(arn, "role", "123456789012")
	gotARN, gotType, gotAcct, ok := DecodePrincipalID(pid)
	if !ok {
		t.Fatalf("expected decode success")
	}
	if gotARN != arn || gotType != "role" || gotAcct != "123456789012" {
		t.Fatalf("unexpected decode values %q %q %q", gotARN, gotType, gotAcct)
	}
}

func TestSemanticEdgeType_TrustVariants(t *testing.T) {
	g := newWorkingGraph()
	g.addNode("arn:aws:iam::111111111111:role/A", "A", "asset", map[string]any{"asset_type": "iam_role", "account_id": "111111111111"})
	g.addNode("arn:aws:iam::222222222222:role/B", "B", "asset", map[string]any{"asset_type": "iam_role", "account_id": "222222222222"})
	g.addNode("arn:aws:iam::333333333333:root", "Root", "asset", map[string]any{"asset_type": "external_principal", "account_id": "333333333333"})
	if got := semanticEdgeType(g, rawEdge{Src: "arn:aws:iam::111111111111:role/A", Tgt: "arn:aws:iam::222222222222:role/B", Type: "TRUSTS"}); got != "CROSS_ACCOUNT_ASSUME_ROLE" {
		t.Fatalf("want CROSS_ACCOUNT_ASSUME_ROLE got %s", got)
	}
	if got := semanticEdgeType(g, rawEdge{Src: "arn:aws:iam::333333333333:root", Tgt: "arn:aws:iam::111111111111:role/A", Type: "TRUSTS"}); got != "EXTERNAL_TRUST" {
		t.Fatalf("want EXTERNAL_TRUST got %s", got)
	}
}

func TestIsCrossAccountEdge_UsesOwningAccountAndRelationshipEvidence(t *testing.T) {
	const role = "arn:aws:iam::111111111111:role/Vendor"
	const ext = "arn:cloudrift:external-principal:::aws_account/vendor"
	g := newWorkingGraph()
	g.AddAssetNode(role, "111111111111", "iam_role", "Vendor", "global", "s1")
	g.AddAssetNode(ext, "222222222222", "external_principal", "arn:aws:iam::222222222222:root", "global", "s1")
	g.addEdgeWithProps(role, ext, "TRUSTS", map[string]any{
		"principal_type":      "aws_account",
		"external_account_id": "222222222222",
	})
	e := g.Edges[edgeKey(role, "TRUSTS", ext)]
	if !isCrossAccountEdge(g, e) {
		t.Fatal("expected cross-account when the principal owning account differs from the role account")
	}
	if got := semanticEdgeType(g, e); got != "EXTERNAL_TRUST" {
		t.Fatalf("TRUSTS remains an external configuration relationship, got %s", got)
	}

	g2 := newWorkingGraph()
	g2.AddAssetNode(role, "111111111111", "iam_role", "Vendor", "global", "s1")
	g2.AddAssetNode(ext, "111111111111", "external_principal", "ext", "global", "s1")
	g2.addEdgeWithProps(role, ext, "TRUSTS", map[string]any{"external_account_id": "222222222222"})
	if !isCrossAccountEdge(g2, g2.Edges[edgeKey(role, "TRUSTS", ext)]) {
		t.Fatal("relationship external_account_id classifies the edge when node account_id still says the trusting account")
	}

	oidc := "arn:cloudrift:external-principal:::oidc/x"
	g3 := newWorkingGraph()
	g3.AddAssetNode(role, "111111111111", "iam_role", "Vendor", "global", "s1")
	g3.AddAssetNode(oidc, "", "external_principal", "idp", "global", "s1")
	g3.addEdge(role, oidc, "TRUSTS")
	e3 := g3.Edges[edgeKey(role, "TRUSTS", oidc)]
	if isCrossAccountEdge(g3, e3) {
		t.Fatal("OIDC with unknown ownership is not a cross-account AWS account edge")
	}
	if !isExternalTrustEdge(g3, e3) {
		t.Fatal("OIDC remains an external trust")
	}
}

func TestBuildSummaryPayload_escalationFromPrivilegeSignals(t *testing.T) {
	g := newWorkingGraph()
	g.addTriples([]PathTriple{{Src: "arn:aws:iam::111111111111:role/A", Dst: "arn:aws:iam::111111111111:role/B", Type: "POINTS_TO"}})
	s := BuildSummaryPayload(
		schema.BlastRootPrincipal,
		"arn:aws:iam::111111111111:role/A",
		"scan-a",
		ModeAttackPath,
		g,
		"arn:aws:iam::111111111111:role/A",
		"",
		PrivilegeSignals{IAMWriteAccess: true, Classification: "privileged"},
		true,
		ReasonNone,
	)
	if s.EscalationPossible || s.PathValidity != string(ValidityUnknown) {
		t.Fatalf("IAM write visibility is not a validated transition: %+v", s)
	}
	if !strings.Contains(strings.ToLower(s.SummaryText), "privilege") {
		t.Fatalf("expected privilege narrative, got: %s", s.SummaryText)
	}
	if s.DominantMotif != "" || s.AttackPathCount != 0 {
		t.Fatalf("POINTS_TO must not become an attack motif: %+v", s)
	}
}

func TestFindingBlast_nilDriver(t *testing.T) {
	scanID := "scan-t"
	out := t.TempDir()
	writeMinimalScan(t, out, scanID, []models.Finding{{
		ID:          "f1",
		Title:       "t",
		Severity:    models.SeverityCritical,
		Module:      models.ModuleOrphanedEdge,
		AffectedARN: "arn:aws:iam::1:role/X",
	}})
	svc := NewService(nil, out)
	sum, _, _, re := svc.FindingBlast(context.Background(), scanID, "f1", ModeBlastRadius)
	if re != ReasonNeo4jDisabled {
		t.Fatalf("reason %v", re)
	}
	if sum.GraphAvailable || sum.SourceFindingID != "f1" {
		t.Fatalf("sum %+v", sum)
	}
}

func TestPrincipalBlast_nilDriver_usesEvidenceEnricher(t *testing.T) {
	scanID := "scan-p"
	out := t.TempDir()
	principalARN := "arn:aws:iam::111111111111:role/PivotRole"
	writeMinimalScan(t, out, scanID, []models.Finding{{
		ID:          "f-pivot",
		Title:       "external trust on privileged role",
		Severity:    models.SeverityHigh,
		Module:      models.ModuleExternalAccess,
		AffectedARN: principalARN,
		Evidence: map[string]any{
			"external_principal": "arn:aws:iam::999999999999:root",
			"permission_visibility": map[string]any{
				"classification": "privileged",
				"capabilities": map[string]any{
					"iam_write_access": true,
					"admin_like":       true,
				},
			},
		},
	}})
	svc := NewService(nil, out)
	sum, _, re := svc.PrincipalBlast(context.Background(), scanID, principalARN, ModeAttackPath)
	if re != ReasonNeo4jDisabled {
		t.Fatalf("reason %v", re)
	}
	if sum.GraphAvailable {
		t.Fatalf("expected graph unavailable fallback")
	}
	if !sum.EscalationPossible {
		t.Fatalf("expected escalation true from principal evidence enricher")
	}
	if !strings.Contains(strings.ToLower(sum.SummaryText), "confidence: high") {
		t.Fatalf("expected confidence marker in summary text, got: %s", sum.SummaryText)
	}
}

func TestBuildPathVariants_attackPathPrimaryAndAlternates(t *testing.T) {
	g := newWorkingGraph()
	g.addNode("arn:aws:iam::111111111111:role/Root", "Root", "asset", map[string]any{"asset_type": "iam_role", "account_id": "111111111111"})
	g.addNode("arn:aws:iam::222222222222:role/Cross", "Cross", "asset", map[string]any{"asset_type": "iam_role", "account_id": "222222222222"})
	g.addNode("arn:aws:iam::111111111111:role/LocalA", "LocalA", "asset", map[string]any{"asset_type": "iam_role", "account_id": "111111111111"})
	g.addNode("arn:aws:iam::111111111111:role/LocalB", "LocalB", "asset", map[string]any{"asset_type": "iam_role", "account_id": "111111111111"})
	g.addNode("arn:aws:iam::999999999999:root", "Ext", "asset", map[string]any{"asset_type": "external_principal", "account_id": "999999999999"})
	g.addNode("arn:aws:s3:::sensitive-bucket", "Bucket", "asset", map[string]any{"asset_type": "s3_bucket", "account_id": "111111111111"})
	g.addEdge("arn:aws:iam::111111111111:role/Root", "arn:aws:iam::222222222222:role/Cross", "TRUSTS")
	g.addEdge("arn:aws:iam::111111111111:role/Root", "arn:aws:iam::999999999999:root", "TRUSTS")
	g.addEdge("arn:aws:iam::111111111111:role/Root", "arn:aws:iam::111111111111:role/LocalA", "TRUSTS")
	g.addEdge("arn:aws:iam::111111111111:role/LocalA", "arn:aws:iam::111111111111:role/LocalB", "POINTS_TO")
	g.addEdge("arn:aws:iam::111111111111:role/LocalB", "arn:aws:s3:::sensitive-bucket", "FRONTS")

	variants, selectedID, _ := buildPathVariants("arn:aws:iam::111111111111:role/Root", g, ModeAttackPath)
	if selectedID != "" || len(variants) != 0 {
		t.Fatalf("TRUSTS, POINTS_TO, and FRONTS must not become attack paths: %#v", variants)
	}
	exposure, selectedID, pathIDs := buildPathVariants("arn:aws:iam::111111111111:role/Root", g, ModeIdentityExposure)
	if selectedID != "primary" || len(exposure) < 2 {
		t.Fatalf("expected unevaluated trust candidates, got %#v", exposure)
	}
	if len(pathIDs) != len(exposure) {
		t.Fatalf("path id mismatch %d vs %d", len(pathIDs), len(exposure))
	}
	for _, v := range exposure {
		if v.Validity != string(ValidityUnknown) {
			t.Fatalf("trust candidate validity: %#v", v)
		}
		if v.Kind != "exposure" {
			t.Fatalf("kind: %#v", v)
		}
	}
}

func TestBuildPathVariants_noAlternatesForSingleBranch(t *testing.T) {
	g := newWorkingGraph()
	g.addNode("arn:aws:iam::111111111111:role/Root", "Root", "asset", map[string]any{"asset_type": "iam_role", "account_id": "111111111111"})
	g.addNode("arn:aws:iam::111111111111:role/A", "A", "asset", map[string]any{"asset_type": "iam_role", "account_id": "111111111111"})
	g.addNode("arn:aws:iam::111111111111:role/B", "B", "asset", map[string]any{"asset_type": "iam_role", "account_id": "111111111111"})
	g.addEdge("arn:aws:iam::111111111111:role/Root", "arn:aws:iam::111111111111:role/A", "TRUSTS")
	g.addEdge("arn:aws:iam::111111111111:role/A", "arn:aws:iam::111111111111:role/B", "POINTS_TO")

	variants, _, _ := buildPathVariants("arn:aws:iam::111111111111:role/Root", g, ModeAttackPath)
	if len(variants) != 0 {
		t.Fatalf("a single TRUSTS plus POINTS_TO chain is not an attack path, got %d", len(variants))
	}
	exposure, _, _ := buildPathVariants("arn:aws:iam::111111111111:role/Root", g, ModeIdentityExposure)
	if len(exposure) != 1 || exposure[0].Validity != string(ValidityUnknown) {
		t.Fatalf("expected one unevaluated trust candidate, got %#v", exposure)
	}
}

func TestBuildExplorerPayload_pathVariantsAttackPathOnly(t *testing.T) {
	g := newWorkingGraph()
	g.addNode("arn:aws:iam::111111111111:role/Root", "Root", "asset", map[string]any{"asset_type": "iam_role", "account_id": "111111111111"})
	g.addNode("arn:aws:iam::222222222222:role/Cross", "Cross", "asset", map[string]any{"asset_type": "iam_role", "account_id": "222222222222"})
	g.addNode("arn:aws:iam::999999999999:root", "Ext", "asset", map[string]any{"asset_type": "external_principal", "account_id": "999999999999"})
	g.addEdge("arn:aws:iam::111111111111:role/Root", "arn:aws:iam::222222222222:role/Cross", "TRUSTS")
	g.addEdge("arn:aws:iam::111111111111:role/Root", "arn:aws:iam::999999999999:root", "TRUSTS")
	sum := BuildSummaryPayload(schema.BlastRootPrincipal, "arn:aws:iam::111111111111:role/Root", "s", ModeAttackPath, g, "arn:aws:iam::111111111111:role/Root", "", PrivilegeSignals{}, true, ReasonNone)

	attackPayload := BuildExplorerPayload(sum, "arn:aws:iam::111111111111:role/Root", ModeAttackPath, "", g)
	if len(attackPayload.PathVariants) != 0 || attackPayload.SelectedPathID != "" {
		t.Fatalf("attack_path must not manufacture variants from TRUSTS: %#v", attackPayload.PathVariants)
	}
	if attackPayload.Summary.PathValidity != string(ValidityUnknown) {
		t.Fatalf("attack summary validity: %+v", attackPayload.Summary)
	}

	blastPayload := BuildExplorerPayload(sum, "arn:aws:iam::111111111111:role/Root", ModeBlastRadius, "", g)
	if len(blastPayload.PathVariants) != 0 || blastPayload.SelectedPathID != "" || len(blastPayload.Display.HighlightPathIDs) != 0 {
		t.Fatalf("expected no path variants in blast_radius mode")
	}
	if len(blastPayload.Nodes) == 0 || len(blastPayload.Edges) == 0 {
		t.Fatalf("topology explorer must still return the neighborhood")
	}
}

func TestPrioritizeOneHopTriples_prefersTrustAndCapsNeighbors(t *testing.T) {
	in := []PathTriple{
		{Src: "arn:root", Dst: "arn:cross", Type: "TRUSTS"},
		{Src: "arn:root", Dst: "arn:external", Type: "TRUSTS"},
		{Src: "arn:root", Dst: "arn:local", Type: "POINTS_TO"},
		{Src: "arn:root", Dst: "account:111111111111", Type: "OWNED_BY"},
	}
	got := prioritizeOneHopTriples("arn:root", in, ModeIdentityExposure, 2)
	if len(got) != 2 {
		t.Fatalf("expected 2 trust neighbors, got %d", len(got))
	}
	for _, t3 := range got {
		if t3.Type != "TRUSTS" {
			t.Fatalf("identity exposure keeps TRUSTS candidates, got %#v", got)
		}
	}
	if attack := prioritizeOneHopTriples("arn:root", in, ModeAttackPath, 2); len(attack) != 0 {
		t.Fatalf("attack expansion must not keep topology neighbors, got %#v", attack)
	}
}

func TestBuildExplorerExpansionDelta_returnsOnlyNewElements(t *testing.T) {
	base := newWorkingGraph()
	base.addEdge("arn:root", "arn:a", "TRUSTS")
	base.ensureMinimalNode("arn:root")
	base.ensureMinimalNode("arn:a")

	delta := newWorkingGraph()
	delta.addEdge("arn:root", "arn:a", "TRUSTS") // duplicate edge
	delta.addEdge("arn:root", "arn:b", "TRUSTS") // new edge
	delta.ensureMinimalNode("arn:root")
	delta.ensureMinimalNode("arn:a")
	delta.ensureMinimalNode("arn:b")

	resp := BuildExplorerExpansionDelta("arn:root", base, delta, ModeAttackPath)
	if !resp.ExpansionApplied {
		t.Fatalf("expected applied expansion")
	}
	if len(resp.Edges) != 1 {
		t.Fatalf("expected exactly one new edge, got %d", len(resp.Edges))
	}
	if len(resp.Nodes) != 1 || resp.Nodes[0].ID != "arn:b" {
		t.Fatalf("expected only new node arn:b, got %#v", resp.Nodes)
	}
}

func writeMinimalScan(t *testing.T, outputDir, scanID string, findings []models.Finding) {
	t.Helper()
	d := filepath.Join(outputDir, scanID)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	meta := models.ScanSnapshot{ScanID: scanID, Timestamp: time.Unix(1, 0).UTC(), FindingCount: len(findings)}
	mb, _ := json.Marshal(meta)
	if err := os.WriteFile(filepath.Join(d, "scan-metadata.json"), mb, 0o644); err != nil {
		t.Fatal(err)
	}
	fb, _ := json.Marshal(findings)
	if err := os.WriteFile(filepath.Join(d, "findings.json"), fb, 0o644); err != nil {
		t.Fatal(err)
	}
}
