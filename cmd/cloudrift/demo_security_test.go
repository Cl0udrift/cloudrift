package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/blastradius"
	"github.com/Zero0x00/cloudrift/internal/graph"
	"github.com/Zero0x00/cloudrift/internal/iamauth"
	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/scans"
)

func TestSecurityScenarios_DeterministicAndSynthetic(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_PROFILE", "")
	left := t.TempDir()
	right := t.TempDir()
	when := time.Date(2026, 10, 10, 15, 0, 0, 0, time.UTC)
	opt := demoOptions{Scenario: "iam-01", Profile: "legacy", Seed: 1}
	if _, err := generateDemoScanWithOptions(left, when, "demo-iam-01", opt); err != nil {
		t.Fatal(err)
	}
	if _, err := generateDemoScanWithOptions(right, when, "demo-iam-01", opt); err != nil {
		t.Fatal(err)
	}
	a, err := os.ReadFile(filepath.Join(left, "demo-iam-01", "assets", "security_fixtures.json"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(right, "demo-iam-01", "assets", "security_fixtures.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("repeated scenario generation changed the artifact")
	}
	var meta models.ScanSnapshot
	readJSON(t, filepath.Join(left, "demo-iam-01", "scan-metadata.json"), &meta)
	if !meta.Synthetic || meta.DataOrigin != syntheticDataOrigin || meta.ScenarioID != "iam-01" || meta.DemoSeed != 1 {
		t.Fatalf("metadata: %+v", meta)
	}
}

func TestSecurityScenarios_LegacyFindingIDsStayStable(t *testing.T) {
	when := time.Date(2026, 10, 10, 15, 0, 0, 0, time.UTC)
	legacyPath, err := generateDemoScan(t.TempDir(), when, "demo-legacy-ids", false)
	if err != nil {
		t.Fatal(err)
	}
	mediumPath, err := generateDemoScanWithOptions(t.TempDir(), when, "demo-medium-ids", demoOptions{
		Profile: "medium", Seed: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	var legacy, medium []models.Finding
	readJSON(t, filepath.Join(legacyPath, "findings.json"), &legacy)
	readJSON(t, filepath.Join(mediumPath, "findings.json"), &medium)
	if len(legacy) == 0 || len(legacy) != len(medium) {
		t.Fatalf("finding count legacy=%d medium=%d", len(legacy), len(medium))
	}
	for i := range legacy {
		if legacy[i].ID != medium[i].ID {
			t.Fatalf("finding id changed at %d: %s -> %s", i, legacy[i].ID, medium[i].ID)
		}
	}
	var meta models.ScanSnapshot
	readJSON(t, filepath.Join(legacyPath, "scan-metadata.json"), &meta)
	if !meta.Synthetic || meta.DataOrigin != syntheticDataOrigin {
		t.Fatalf("legacy demo was not labeled synthetic: %+v", meta)
	}
}

func TestSecurityScenarios_ReferencesOwnershipAndNoFabricatedDecision(t *testing.T) {
	dir := t.TempDir()
	when := time.Date(2026, 10, 10, 15, 0, 0, 0, time.UTC)
	if _, err := generateDemoScanWithOptions(dir, when, "demo-refs", demoOptions{Scenario: "iam-07", Profile: "legacy", Seed: 1}); err != nil {
		t.Fatal(err)
	}
	assets, rels := loadDemo(t, dir, "demo-refs")
	known := map[string]models.AssetNode{}
	for _, asset := range assets {
		known[asset.ARN] = asset
		if asset.Properties["decision"] == iamauth.StatusAllowed {
			t.Fatalf("scan asset stored a validated decision: %s", asset.ARN)
		}
		if asset.AssetType == models.AssetIAMRole {
			if asset.AccountID == "" || !containsAccount(asset.ARN, asset.AccountID) {
				t.Fatalf("role ownership: %+v", asset)
			}
		}
	}
	for _, rel := range rels {
		if rel.RelType == models.RelHasAuthorizationDecision || rel.RelType == models.RelAuthorizationTargets {
			t.Fatalf("generator emitted an authorization result edge: %+v", rel)
		}
		if _, ok := known[rel.SourceARN]; !ok {
			t.Fatalf("missing relationship source %s", rel.SourceARN)
		}
		if _, ok := known[rel.TargetARN]; ok || hasPrefix(rel.TargetARN, "account:") {
			continue
		}
		t.Fatalf("relationship target is neither collected nor an account owner: %+v", rel)
	}
}

func TestSecurityScenarios_AuthorizationGoldens(t *testing.T) {
	when := time.Date(2026, 10, 10, 15, 0, 0, 0, time.UTC)
	cases := []struct {
		scenario string
		role     string
		action   string
		resource string
		context  map[string]string
		status   string
		reason   string
	}{
		{"iam-01", roleARN(demoAcctCore, "SecAdminRole"), "s3:GetObject", objectARN("sec-admin", "readme.txt"), nil, iamauth.StatusAllowed, iamauth.ReasonAllowed},
		{"iam-01", roleARN(demoAcctCore, "SecAdminRole"), "s3:PutObject", objectARN("sec-admin", "readme.txt"), nil, iamauth.StatusAllowed, iamauth.ReasonAllowed},
		{"iam-02", roleARN(demoAcctCore, "SecAdminDenyRole"), "s3:GetObject", objectARN("sec-deny", "readme.txt"), nil, iamauth.StatusDenied, iamauth.ReasonExplicitDeny},
		{"iam-02", roleARN(demoAcctCore, "SecAdminDenyRole"), "s3:PutObject", objectARN("sec-deny", "readme.txt"), nil, iamauth.StatusAllowed, iamauth.ReasonAllowed},
		{"iam-03", roleARN(demoAcctCore, "SecAdminMissingSCP"), "s3:GetObject", objectARN("sec-missing-scp", "readme.txt"), nil, iamauth.StatusUnknown, iamauth.ReasonMissingSCP},
		{"iam-04", roleARN(demoAcctCore, "SecRestrictedRole"), "s3:GetObject", objectARN("sec-restricted", "readme.txt"), nil, iamauth.StatusAllowed, iamauth.ReasonAllowed},
		{"iam-04", roleARN(demoAcctCore, "SecRestrictedRole"), "iam:AttachRolePolicy", roleARN(demoAcctCore, "SecRestrictedTarget"), nil, iamauth.StatusDenied, iamauth.ReasonExplicitDeny},
		{"iam-04", roleARN(demoAcctCore, "SecRestrictedRole"), "s3:PutObject", objectARN("sec-restricted", "readme.txt"), nil, iamauth.StatusUnknown, iamauth.ReasonNoAllow},
		{"iam-05", roleARN(demoAcctCore, "SecBoundaryRole"), "s3:GetObject", objectARN("sec-boundary", "readme.txt"), nil, iamauth.StatusAllowed, iamauth.ReasonAllowed},
		{"iam-05", roleARN(demoAcctCore, "SecBoundaryRole"), "s3:PutObject", objectARN("sec-boundary", "readme.txt"), nil, iamauth.StatusUnknown, iamauth.ReasonBoundaryNoAllow},
		{"iam-05b", roleARN(demoAcctCore, "SecBoundaryUnread"), "s3:GetObject", objectARN("sec-boundary-unread", "readme.txt"), nil, iamauth.StatusUnknown, iamauth.ReasonMissingBoundary},
		{"iam-06", roleARN(demoAcctCore, "SecConditionalRole"), "s3:GetObject", objectARN("sec-conditional", "readme.txt"), nil, iamauth.StatusConditional, iamauth.ReasonMissingContext},
		{"iam-06", roleARN(demoAcctCore, "SecConditionalRole"), "s3:GetObject", objectARN("sec-conditional", "readme.txt"), map[string]string{"aws:RequestedRegion": "us-east-1"}, iamauth.StatusAllowed, iamauth.ReasonAllowed},
		{"iam-06", roleARN(demoAcctCore, "SecConditionalRole"), "s3:GetObject", objectARN("sec-conditional", "readme.txt"), map[string]string{"aws:RequestedRegion": "eu-west-1"}, iamauth.StatusUnknown, iamauth.ReasonNoAllow},
		{"iam-07", roleARN(demoAcctCore, "SecAssumeCaller"), iamauth.ActionAssumeRole, roleARN(demoAcctData, "SecAssumeTarget"), nil, iamauth.StatusAllowed, iamauth.ReasonAllowed},
		{"iam-08", roleARN(demoAcctCore, "SecTrustOnlyCaller"), iamauth.ActionAssumeRole, roleARN(demoAcctData, "SecTrustOnlyTarget"), nil, iamauth.StatusUnknown, iamauth.ReasonNoAllow},
		{"iam-09", roleARN(demoAcctCore, "SecTrustDenyCaller"), iamauth.ActionAssumeRole, roleARN(demoAcctData, "SecTrustDenyTarget"), nil, iamauth.StatusDenied, iamauth.ReasonExplicitDeny},
		{"iam-10-denied", roleARN(demoAcctCore, "SecRetrievalDenied"), "s3:GetObject", objectARN("sec-retrieval-denied", "readme.txt"), nil, iamauth.StatusUnknown, iamauth.ReasonMissingIdentity},
		{"iam-10-missing", roleARN(demoAcctCore, "SecRetrievalMissingVersion"), "s3:GetObject", objectARN("sec-retrieval-missing", "readme.txt"), nil, iamauth.StatusUnknown, iamauth.ReasonMissingIdentity},
		{"iam-10-malformed", roleARN(demoAcctCore, "SecRetrievalMalformed"), "s3:GetObject", objectARN("sec-retrieval-malformed", "readme.txt"), nil, iamauth.StatusUnknown, iamauth.ReasonMissingIdentity},
		{"iam-10-empty", roleARN(demoAcctCore, "SecEmptyInventory"), "s3:GetObject", objectARN("sec-empty-inventory", "readme.txt"), nil, iamauth.StatusUnknown, iamauth.ReasonNoAllow},
		{"iam-session-missing", roleARN(demoAcctCore, "SecSessionMissing"), "s3:GetObject", objectARN("sec-session", "readme.txt"), nil, iamauth.StatusUnknown, iamauth.ReasonMissingSession},
		{"s3-01", roleARN(demoAcctCore, "SecSameReader"), "s3:GetObject", objectARN("sec-same", "readme.txt"), nil, iamauth.StatusAllowed, iamauth.ReasonAllowed},
		{"s3-02", roleARN(demoAcctCore, "SecCrossReader"), "s3:GetObject", objectARN("sec-foreign", "secret.txt"), nil, iamauth.StatusAllowed, iamauth.ReasonAllowed},
		{"s3-03", roleARN(demoAcctCore, "SecBucketDenyReader"), "s3:GetObject", objectARN("sec-bucket-deny", "readme.txt"), nil, iamauth.StatusDenied, iamauth.ReasonExplicitDeny},
		{"s3-04", roleARN(demoAcctCore, "SecNoBucketPolicy"), "s3:GetObject", objectARN("sec-no-policy", "readme.txt"), nil, iamauth.StatusAllowed, iamauth.ReasonAllowed},
		{"s3-05", roleARN(demoAcctCore, "SecBucketPolicyDenied"), "s3:GetObject", objectARN("sec-policy-denied", "readme.txt"), nil, iamauth.StatusUnknown, iamauth.ReasonMissingResource},
		{"s3-06", roleARN(demoAcctCore, "SecOwnerEnforced"), "s3:GetObject", objectARN("sec-owner-enforced", "readme.txt"), nil, iamauth.StatusAllowed, iamauth.ReasonAllowed},
		{"s3-07", roleARN(demoAcctCore, "SecOwnershipMissing"), "s3:GetObject", objectARN("sec-ownership-missing", "readme.txt"), nil, iamauth.StatusUnknown, iamauth.ReasonMissingACL},
		{"s3-08", roleARN(demoAcctCore, "SecSSES3"), "s3:GetObject", objectARN("sec-sse-s3", "readme.txt"), nil, iamauth.StatusAllowed, iamauth.ReasonAllowed},
		{"s3-09", roleARN(demoAcctCore, "SecSSEKMS"), "s3:GetObject", objectARN("sec-sse-kms", "readme.txt"), nil, iamauth.StatusUnknown, iamauth.ReasonMissingKMS},
		{"s3-11", roleARN(demoAcctCore, "SecBPAPartial"), "s3:GetObject", objectARN("sec-bpa", "readme.txt"), nil, iamauth.StatusUnknown, iamauth.ReasonMissingBPA},
		{"s3-12", roleARN(demoAcctCore, "SecMultiAction"), "s3:GetObject", objectARN("sec-actions", "readme.txt"), nil, iamauth.StatusAllowed, iamauth.ReasonAllowed},
		{"s3-12", roleARN(demoAcctCore, "SecMultiAction"), "s3:PutObject", objectARN("sec-actions", "readme.txt"), nil, iamauth.StatusAllowed, iamauth.ReasonAllowed},
		{"s3-12", roleARN(demoAcctCore, "SecMultiAction"), "s3:DeleteObject", objectARN("sec-actions", "readme.txt"), nil, iamauth.StatusDenied, iamauth.ReasonExplicitDeny},
	}
	for _, tc := range cases {
		t.Run(tc.scenario+"/"+tc.action, func(t *testing.T) {
			dir := t.TempDir()
			scanID := "demo-" + tc.scenario
			if _, err := generateDemoScanWithOptions(dir, when, scanID, demoOptions{Scenario: tc.scenario, Profile: "legacy", Seed: 1}); err != nil {
				t.Fatal(err)
			}
			report := analyzeDemo(t, dir, scanID, tc.role, tc.context)
			if tc.scenario == "iam-01" && len(report.BroadPrivilegeCandidates) == 0 {
				t.Fatal("expected an administrative candidate from the policy document")
			}
			if tc.scenario == "iam-03" {
				if len(report.BroadPrivilegeCandidates) == 0 {
					t.Fatal("missing SCP still leaves the administrative candidate visible")
				}
				for _, hit := range report.Decisions {
					if hit.Status == iamauth.StatusAllowed {
						t.Fatalf("missing SCP produced a validated allow: %+v", hit)
					}
				}
			}
			if tc.scenario == "iam-10-denied" {
				assertRetrieval(t, dir, scanID, "arn:aws:iam::aws:policy/AdministratorAccess", models.PolicyRetrievalMissing, "was denied")
			}
			if tc.scenario == "iam-10-missing" {
				assertRetrieval(t, dir, scanID, "arn:aws:iam::"+demoAcctCore+":policy/SecMissingVersion", models.PolicyRetrievalMissing, "GetPolicyVersion")
			}
			if tc.scenario == "iam-10-malformed" {
				assertRetrieval(t, dir, scanID, "arn:aws:iam::"+demoAcctCore+":policy/SecMalformed", models.PolicyRetrievalMalformed, "")
			}
			if tc.scenario == "s3-02" {
				hit := findDecision(report, tc.action, tc.resource)
				if hit.SameAccount {
					t.Fatal("cross-account object was marked same-account")
				}
			}
			hit := findDecision(report, tc.action, tc.resource)
			if hit.Status != tc.status || hit.Reason != tc.reason {
				t.Fatalf("got %s/%s want %s/%s", hit.Status, hit.Reason, tc.status, tc.reason)
			}
		})
	}
}

func TestSecurityScenarios_BucketWithoutObjectsAndUnsupportedInventory(t *testing.T) {
	when := time.Date(2026, 10, 10, 15, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	if _, err := generateDemoScanWithOptions(dir, when, "demo-s3-10", demoOptions{Scenario: "s3-10", Profile: "legacy", Seed: 1}); err != nil {
		t.Fatal(err)
	}
	report := analyzeDemo(t, dir, "demo-s3-10", roleARN(demoAcctCore, "SecBucketOnly"), nil)
	if len(report.BucketScopes) == 0 {
		t.Fatal("expected a bucket scope note")
	}
	for _, hit := range report.Decisions {
		if hit.ResourceARN == objectARN("sec-no-objects", "readme.txt") {
			t.Fatalf("analysis invented an object: %+v", hit)
		}
	}

	if _, err := generateDemoScanWithOptions(dir, when, "demo-inventory", demoOptions{Scenario: "inventory", Profile: "legacy", Seed: 1}); err != nil {
		t.Fatal(err)
	}
	inventory := analyzeDemo(t, dir, "demo-inventory", roleARN(demoAcctCore, "SecInventoryObserver"), nil)
	if !containsString(inventory.UnsupportedActions, "secretsmanager:GetSecretValue") || !containsString(inventory.UnsupportedActions, "ec2:StopInstances") {
		t.Fatalf("unsupported catalog: %v", inventory.UnsupportedActions)
	}
	for _, hit := range inventory.Decisions {
		if hit.Status == iamauth.StatusAllowed {
			t.Fatalf("unsupported inventory validated access: %+v", hit)
		}
	}
}

func TestSecurityScenarios_HistoryFingerprints(t *testing.T) {
	when := time.Date(2026, 10, 10, 15, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	if _, err := generateDemoScanWithOptions(dir, when, "demo-history", demoOptions{Scenario: "history", Profile: "legacy", Seed: 1}); err != nil {
		t.Fatal(err)
	}
	object := objectARN("sec-history", "notes.txt")
	role := roleARN(demoAcctCore, "SecHistoryRole")
	broad := analyzeDemo(t, dir, "demo-history-history-broad", role, nil)
	restricted := analyzeDemo(t, dir, "demo-history-history-restricted", role, nil)
	denied := analyzeDemo(t, dir, "demo-history-history-deny", role, nil)
	missing := analyzeDemo(t, dir, "demo-history-history-evidence-missing", role, nil)
	present := analyzeDemo(t, dir, "demo-history-history-evidence-present", role, nil)
	assertDecision(t, broad, "s3:GetObject", object, iamauth.StatusAllowed, iamauth.ReasonAllowed)
	assertDecision(t, restricted, "s3:PutObject", object, iamauth.StatusUnknown, iamauth.ReasonNoAllow)
	assertDecision(t, denied, "s3:GetObject", object, iamauth.StatusDenied, iamauth.ReasonExplicitDeny)
	assertDecision(t, missing, "s3:GetObject", object, iamauth.StatusUnknown, iamauth.ReasonMissingIdentity)
	assertDecision(t, present, "s3:GetObject", object, iamauth.StatusAllowed, iamauth.ReasonAllowed)
	if findDecision(broad, "s3:GetObject", object).EvidenceFingerprint == findDecision(restricted, "s3:GetObject", object).EvidenceFingerprint {
		t.Fatal("policy change did not change the evidence fingerprint")
	}
	caller := roleARN(demoAcctCore, "SecHistoryCaller")
	target := roleARN(demoAcctData, "SecHistoryTarget")
	trusted := analyzeDemo(t, dir, "demo-history-history-trust", caller, nil)
	removed := analyzeDemo(t, dir, "demo-history-history-trust-removed", caller, nil)
	assertDecision(t, trusted, iamauth.ActionAssumeRole, target, iamauth.StatusAllowed, iamauth.ReasonAllowed)
	assertDecision(t, removed, iamauth.ActionAssumeRole, target, iamauth.StatusUnknown, iamauth.ReasonMissingTrust)
}

func TestSecurityScenarios_EndToEndNeo4j(t *testing.T) {
	uri := os.Getenv("CLOUDRIFT_NEO4J_URI")
	if uri == "" {
		t.Skip("CLOUDRIFT_NEO4J_URI not set")
	}
	user := os.Getenv("CLOUDRIFT_NEO4J_USER")
	if user == "" {
		user = "neo4j"
	}
	when := time.Date(2026, 10, 10, 15, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	const scanID = "demo-sec-e2e"
	if _, err := generateDemoScanWithOptions(dir, when, scanID, demoOptions{Scenario: "s3-01", Profile: "legacy", Seed: 1}); err != nil {
		t.Fatal(err)
	}
	meta, assets, rels, findings := loadGraphDemo(t, dir, scanID)
	role := roleARN(demoAcctCore, "SecSameReader")
	object := objectARN("sec-same", "readme.txt")
	report := analyzeDemo(t, dir, scanID, role, nil)
	assertDecision(t, report, "s3:GetObject", object, iamauth.StatusAllowed, iamauth.ReasonAllowed)

	ctx := context.Background()
	driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(user, os.Getenv("CLOUDRIFT_NEO4J_PASSWORD"), ""))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = driver.Close(ctx) })
	if err := driver.VerifyConnectivity(ctx); err != nil {
		t.Fatal(err)
	}
	ex := graph.NewDriverExecer(driver, os.Getenv("CLOUDRIFT_NEO4J_DATABASE"))
	for _, ddl := range graph.SchemaStatements() {
		if err := ex.Run(ctx, ddl, nil); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_ = ex.Run(ctx, `MATCH (n) WHERE n.scan_id = $scan DETACH DELETE n`, map[string]any{"scan": scanID})
	})
	if err := graph.WriteScan(ctx, ex, meta, assets, rels, findings); err != nil {
		t.Fatal(err)
	}
	var nodes []models.AssetNode
	var edges []models.Relationship
	for _, hit := range report.Decisions {
		if hit.Action != "s3:GetObject" || hit.ResourceARN != object {
			continue
		}
		decision := iamauth.AuthorizationDecision{
			ID: hit.DecisionID, Status: hit.Status, Reason: hit.Reason, PrincipalARN: role,
			Action: hit.Action, ResourceARN: hit.ResourceARN, ResourceAccountID: hit.AccountID,
			ScanID: scanID, EvidenceFingerprint: hit.EvidenceFingerprint, SameAccount: hit.SameAccount,
			EvaluatedAt: when,
		}
		node, projected := iamauth.ProjectCapability(decision, true)
		nodes = append(nodes, node)
		edges = append(edges, projected...)
	}
	if err := graph.WriteAuthorizationFacts(ctx, ex, scanID, nodes, edges); err != nil {
		t.Fatal(err)
	}
	session := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead, DatabaseName: os.Getenv("CLOUDRIFT_NEO4J_DATABASE")})
	defer session.Close(ctx)
	rows, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, `
MATCH (role:Asset {arn: $role, scan_id: $scan})-[:HAS_AUTHORIZATION_DECISION]->(d:Asset {scan_id: $scan})-[t:AUTHORIZATION_TARGETS]->(obj:Asset {arn: $object, scan_id: $scan})
RETURN t.decision AS decision
`, map[string]any{"role": role, "scan": scanID, "object": object})
		if err != nil {
			return nil, err
		}
		var out []string
		for res.Next(ctx) {
			v, _ := res.Record().Get("decision")
			out = append(out, v.(string))
		}
		return out, res.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	got := rows.([]string)
	if len(got) != 1 || got[0] != iamauth.StatusAllowed {
		t.Fatalf("neo4j decision: %#v", got)
	}
}

func TestDemoCommand_SecurityFlags(t *testing.T) {
	root := newRootCommand()
	generate, _, err := root.Find([]string{"demo", "generate"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"scenario", "profile", "seed", "include-security-fixtures"} {
		if generate.Flags().Lookup(name) == nil {
			t.Fatalf("missing --%s", name)
		}
	}
}

func analyzeDemo(t *testing.T, dir, scanID, role string, ctx map[string]string) schema.PermissionBlastReport {
	t.Helper()
	assets, rels := loadDemo(t, dir, scanID)
	return blastradius.AnalyzePermissionBlast(blastradius.PermissionBlastRequest{
		ScanID: scanID, RoleARN: role, AssumedCompromise: true, SessionSource: "assumed",
		RequestContext: ctx, Assets: assets, Relationships: rels,
		EvaluatedAt: time.Date(2026, 10, 10, 15, 0, 0, 0, time.UTC),
	})
}

func loadDemo(t *testing.T, dir, scanID string) ([]models.AssetNode, []models.Relationship) {
	t.Helper()
	assets, err := scans.LoadAssets(dir, scanID)
	if err != nil {
		t.Fatal(err)
	}
	rels, err := scans.LoadRelationships(dir, scanID)
	if err != nil {
		t.Fatal(err)
	}
	return assets, rels
}

func loadGraphDemo(t *testing.T, dir, scanID string) (models.ScanSnapshot, []models.AssetNode, []models.Relationship, []models.Finding) {
	t.Helper()
	var meta models.ScanSnapshot
	readJSON(t, filepath.Join(dir, scanID, "scan-metadata.json"), &meta)
	var findings []models.Finding
	readJSON(t, filepath.Join(dir, scanID, "findings.json"), &findings)
	assets, rels := loadDemo(t, dir, scanID)
	return meta, assets, rels, findings
}

func findDecision(report schema.PermissionBlastReport, action, resource string) schema.PermissionDecision {
	for _, hit := range report.Decisions {
		if hit.Action == action && hit.ResourceARN == resource {
			return hit
		}
	}
	return schema.PermissionDecision{}
}

func assertDecision(t *testing.T, report schema.PermissionBlastReport, action, resource, status, reason string) {
	t.Helper()
	hit := findDecision(report, action, resource)
	if hit.Status != status || hit.Reason != reason {
		t.Fatalf("%s %s got %s/%s want %s/%s", action, resource, hit.Status, hit.Reason, status, reason)
	}
}

func assertRetrieval(t *testing.T, dir, scanID, arn, status, evidencePart string) {
	t.Helper()
	assets, _ := loadDemo(t, dir, scanID)
	for _, asset := range assets {
		if asset.ARN != arn {
			continue
		}
		if asset.Properties["retrieval_status"] != status {
			t.Fatalf("retrieval status: %#v", asset.Properties["retrieval_status"])
		}
		evidence, _ := asset.Properties["retrieval_evidence"].(string)
		if !strings.Contains(evidence, evidencePart) {
			t.Fatalf("retrieval evidence: %s", evidence)
		}
		return
	}
	t.Fatalf("missing policy %s", arn)
}

func containsAccount(arn, account string) bool {
	return strings.Contains(arn, account)
}

func hasPrefix(s, prefix string) bool {
	return strings.HasPrefix(s, prefix)
}

func containsString(values []string, want string) bool {
	return slicesContains(values, want)
}

func slicesContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
