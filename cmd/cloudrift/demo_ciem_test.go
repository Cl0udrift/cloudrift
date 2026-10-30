package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/blastradius"
	"github.com/Zero0x00/cloudrift/internal/ciem"
	"github.com/Zero0x00/cloudrift/internal/iamauth"
	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/scans"
)

func TestCIEMDemo_FindingWorkflow(t *testing.T) {
	when := time.Date(2026, 10, 10, 20, 0, 0, 0, time.UTC)
	left := t.TempDir()
	right := t.TempDir()
	if _, err := generateDemoScanWithOptions(left, when, "ciem-broad", demoOptions{Scenario: "ciem-broad", Profile: "legacy", Seed: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := generateDemoScanWithOptions(right, when, "ciem-broad", demoOptions{Scenario: "ciem-broad", Profile: "legacy", Seed: 1}); err != nil {
		t.Fatal(err)
	}
	a, findingsA, err := scans.LoadScanArtifacts(left, "ciem-broad")
	_, findingsB, errB := scans.LoadScanArtifacts(right, "ciem-broad")
	if err != nil || errB != nil || a.Synthetic == false || len(findingsA) != 1 || findingsA[0].ID != findingsB[0].ID {
		t.Fatalf("findings %v %v err %v %v", findingsA, findingsB, err, errB)
	}
	if findingsA[0].Module != models.ModuleExternalAccess || findingsA[0].Severity == "" {
		t.Fatalf("finding identity changed: %+v", findingsA[0])
	}
	assets, _ := scans.LoadAssets(left, "ciem-broad")
	rels, _ := scans.LoadRelationships(left, "ciem-broad")
	assessment := ciem.Assess("ciem-broad", findingsA[0], assets, rels, findingsA)
	if !assessment.Applicable || assessment.Kind != "role_compromise" || assessment.ExecutionEnabled {
		t.Fatalf("%+v", assessment)
	}
	if assessment.EntryFeasibility != "external_caller_permission_not_inspected" || assessment.PrivilegeEscalation != "VALIDATED_POSSIBLE" {
		t.Fatalf("entry=%s escalation=%s", assessment.EntryFeasibility, assessment.PrivilegeEscalation)
	}
	if len(assessment.BroadPrivilegeCandidates) == 0 || assessment.ValidatedResourceAccess == false || len(assessment.Recommendations) == 0 {
		t.Fatalf("impact candidates=%v access=%v recs=%d", assessment.BroadPrivilegeCandidates, assessment.ValidatedResourceAccess, len(assessment.Recommendations))
	}
	for _, rec := range assessment.Recommendations {
		if rec.Executable || rec.ID == "delete-role" {
			t.Fatalf("executable recommendation %+v", rec)
		}
	}

	multiDir := t.TempDir()
	if _, err := generateDemoScanWithOptions(multiDir, when, "ciem-multi", demoOptions{Scenario: "ciem-multi", Profile: "legacy", Seed: 1}); err != nil {
		t.Fatal(err)
	}
	_, multi, err := scans.LoadScanArtifacts(multiDir, "ciem-multi")
	if err != nil || len(multi) != 2 {
		t.Fatalf("multi findings %d %v", len(multi), err)
	}
	mAssets, _ := scans.LoadAssets(multiDir, "ciem-multi")
	mRels, _ := scans.LoadRelationships(multiDir, "ciem-multi")
	first := ciem.Assess("ciem-multi", multi[0], mAssets, mRels, multi)
	second := ciem.Assess("ciem-multi", multi[1], mAssets, mRels, multi)
	if first.SharedImpactKey == "" || first.SharedImpactKey != second.SharedImpactKey || len(first.SiblingFindingIDs) != 1 {
		t.Fatalf("shared impact %s %s siblings %v", first.SharedImpactKey, second.SharedImpactKey, first.SiblingFindingIDs)
	}
	if len(first.UniqueImpactedResources) != len(second.UniqueImpactedResources) {
		t.Fatal("sibling findings multiplied resources")
	}

	staleDir := t.TempDir()
	if _, err := generateDemoScanWithOptions(staleDir, when, "ciem-stale", demoOptions{Scenario: "ciem-stale", Profile: "legacy", Seed: 1}); err != nil {
		t.Fatal(err)
	}
	_, staleFindings, _ := scans.LoadScanArtifacts(staleDir, "ciem-stale")
	sAssets, _ := scans.LoadAssets(staleDir, "ciem-stale")
	sRels, _ := scans.LoadRelationships(staleDir, "ciem-stale")
	stale := ciem.Assess("ciem-stale", staleFindings[0], sAssets, sRels, staleFindings)
	if !hasRec(stale, "review-stale-trust") {
		t.Fatalf("stale recommendations %+v verdict %v", stale.Recommendations, staleFindings[0].Evidence["verdict"])
	}

	bucketDir := t.TempDir()
	if _, err := generateDemoScanWithOptions(bucketDir, when, "ciem-bucket", demoOptions{Scenario: "ciem-bucket", Profile: "legacy", Seed: 1}); err != nil {
		t.Fatal(err)
	}
	_, bucketFindings, _ := scans.LoadScanArtifacts(bucketDir, "ciem-bucket")
	if len(bucketFindings) != 1 || bucketFindings[0].AffectedARN == "" {
		t.Fatalf("bucket findings %+v", bucketFindings)
	}
	bAssets, _ := scans.LoadAssets(bucketDir, "ciem-bucket")
	bRels, _ := scans.LoadRelationships(bucketDir, "ciem-bucket")
	bucket := ciem.Assess("ciem-bucket", bucketFindings[0], bAssets, bRels, bucketFindings)
	if bucket.Kind != "resource_policy" || bucket.ResourceImpactPaths != 0 {
		t.Fatalf("bucket assessment %+v", bucket)
	}

	chainDir := t.TempDir()
	if _, err := generateDemoScanWithOptions(chainDir, when, "ciem-chain", demoOptions{Scenario: "ciem-chain", Profile: "legacy", Seed: 1}); err != nil {
		t.Fatal(err)
	}
	_, chainFindings, _ := scans.LoadScanArtifacts(chainDir, "ciem-chain")
	cAssets, _ := scans.LoadAssets(chainDir, "ciem-chain")
	cRels, _ := scans.LoadRelationships(chainDir, "ciem-chain")
	chain := ciem.Assess("ciem-chain", chainFindings[0], cAssets, cRels, chainFindings)
	if chain.ResourceImpactPaths != 1 || chain.ValidatedTransitions != 2 || !chain.ValidatedIdentityMovement || chain.PrivilegeEscalation != "NONE_FOUND_IN_MODELED_TECHNIQUES" {
		t.Fatalf("chain paths=%d transitions=%d move=%v escalation=%s", chain.ResourceImpactPaths, chain.ValidatedTransitions, chain.ValidatedIdentityMovement, chain.PrivilegeEscalation)
	}
	if chain.EvidenceCoverage.SessionContext != "SUPPORTED_HYPOTHETICAL_ASSUMPTION" {
		t.Fatal(chain.EvidenceCoverage.SessionContext)
	}

	scpDir := t.TempDir()
	if _, err := generateDemoScanWithOptions(scpDir, when, "ciem-scp", demoOptions{Scenario: "ciem-scp", Profile: "legacy", Seed: 1}); err != nil {
		t.Fatal(err)
	}
	_, scpFindings, _ := scans.LoadScanArtifacts(scpDir, "ciem-scp")
	scpAssets, _ := scans.LoadAssets(scpDir, "ciem-scp")
	scpRels, _ := scans.LoadRelationships(scpDir, "ciem-scp")
	scp := ciem.Assess("ciem-scp", scpFindings[0], scpAssets, scpRels, scpFindings)
	if scp.ValidatedDenied == 0 || scp.ResourceImpactPaths != 0 || scp.EvidenceCoverage.OrganizationsSCP != "COMPLETE_FOR_SUPPORTED_SCOPE" {
		t.Fatalf("scp denied=%d paths=%d coverage=%s", scp.ValidatedDenied, scp.ResourceImpactPaths, scp.EvidenceCoverage.OrganizationsSCP)
	}

	scopeDir := t.TempDir()
	if _, err := generateDemoScanWithOptions(scopeDir, when, "ciem-scope", demoOptions{Scenario: "ciem-scope", Profile: "legacy", Seed: 1}); err != nil {
		t.Fatal(err)
	}
	_, scopeFindings, _ := scans.LoadScanArtifacts(scopeDir, "ciem-scope")
	scopeAssets, _ := scans.LoadAssets(scopeDir, "ciem-scope")
	scopeRels, _ := scans.LoadRelationships(scopeDir, "ciem-scope")
	scope := ciem.Assess("ciem-scope", scopeFindings[0], scopeAssets, scopeRels, scopeFindings)
	if len(scope.UniqueImpactedResources) != 0 || scope.ResourceImpactPaths != 0 || len(scope.BucketScopeNotes) == 0 || !strings.Contains(scope.BucketScopeNotes[0], "BUCKET_SCOPE_PERMISSION") {
		t.Fatalf("scope resources=%v paths=%d notes=%v", scope.UniqueImpactedResources, scope.ResourceImpactPaths, scope.BucketScopeNotes)
	}
	if scope.EvidenceCoverage.S3ObjectInventory != "NOT_COLLECTED" {
		t.Fatal(scope.EvidenceCoverage.S3ObjectInventory)
	}
}

func TestCIEMDemo_OrgHierarchy(t *testing.T) {
	when := time.Date(2026, 10, 10, 21, 0, 0, 0, time.UTC)
	load := func(scenario string) (schema.CIEMAssessment, schema.PermissionBlastReport, string) {
		t.Helper()
		dir := t.TempDir()
		if _, err := generateDemoScanWithOptions(dir, when, scenario, demoOptions{Scenario: scenario, Profile: "legacy", Seed: 1}); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(dir, scenario, "assets", "security_fixtures.json"))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "VALIDATED_ALLOWED") || strings.Contains(string(raw), "VALIDATED_DENIED") {
			t.Fatal("scan input contains an authorization decision")
		}
		_, findings, err := scans.LoadScanArtifacts(dir, scenario)
		if err != nil || len(findings) == 0 {
			t.Fatalf("findings %v", err)
		}
		assets, _ := scans.LoadAssets(dir, scenario)
		rels, _ := scans.LoadRelationships(dir, scenario)
		assessment := ciem.Assess(scenario, findings[0], assets, rels, findings)
		blast := blastradius.AnalyzePermissionBlast(blastradius.PermissionBlastRequest{
			ScanID: scenario, RoleARN: assessment.RoleARN, AssumedCompromise: true, SessionSource: "assumed",
			Assets: assets, Relationships: rels,
		})
		return assessment, blast, string(raw)
	}
	reason := func(report schema.PermissionBlastReport, action, resource string) schema.PermissionDecision {
		t.Helper()
		for _, decision := range report.Decisions {
			if decision.Action == action && decision.ResourceARN == resource {
				return decision
			}
		}
		t.Fatalf("missing %s %s", action, resource)
		return schema.PermissionDecision{}
	}

	union, unionBlast, _ := load("ciem-scp-union")
	got := reason(unionBlast, iamauth.ActionGetObject, objectARN("scp-union", "readme.txt"))
	if union.ValidatedAllowed == 0 || union.ResourceImpactPaths == 0 || got.Status != iamauth.StatusAllowed {
		t.Fatalf("union allowed=%d paths=%d decision=%+v", union.ValidatedAllowed, union.ResourceImpactPaths, got)
	}
	ancestor, ancestorBlast, _ := load("ciem-scp-ancestor")
	ancestorDecision := reason(ancestorBlast, iamauth.ActionGetObject, objectARN("scp-ancestor", "readme.txt"))
	if ancestor.ValidatedAllowed != 0 || ancestor.ResourceImpactPaths != 0 || ancestorDecision.Reason != iamauth.ReasonSCPNoAllow {
		t.Fatalf("ancestor allowed=%d paths=%d %+v", ancestor.ValidatedAllowed, ancestor.ResourceImpactPaths, ancestorDecision)
	}
	deny, denyBlast, _ := load("ciem-scp-deny")
	denyDecision := reason(denyBlast, iamauth.ActionGetObject, objectARN("scp-deny", "readme.txt"))
	if deny.ValidatedDenied == 0 || deny.ResourceImpactPaths != 0 || denyDecision.Status != iamauth.StatusDenied {
		t.Fatalf("ancestor deny=%d paths=%d %+v", deny.ValidatedDenied, deny.ResourceImpactPaths, denyDecision)
	}
	gap, gapBlast, _ := load("ciem-scp-gap")
	gapDecision := reason(gapBlast, iamauth.ActionGetObject, objectARN("scp-gap", "readme.txt"))
	if gap.ValidatedAllowed != 0 || gapDecision.Reason != iamauth.ReasonMissingSCP {
		t.Fatalf("gap %+v", gapDecision)
	}
	implicit, implicitBlast, _ := load("ciem-scp-implicit")
	implicitDecision := reason(implicitBlast, iamauth.ActionGetObject, objectARN("scp-implicit", "readme.txt"))
	if implicit.ValidatedAllowed != 0 || implicitDecision.Reason != iamauth.ReasonSCPNoAllow {
		t.Fatalf("implicit %+v", implicitDecision)
	}
	moved, movedBlast, _ := load("ciem-scp-moved")
	movedDecision := reason(movedBlast, iamauth.ActionGetObject, objectARN("scp-moved", "readme.txt"))
	if moved.ValidatedAllowed == 0 || movedDecision.Status != iamauth.StatusAllowed || movedDecision.EvidenceFingerprint == got.EvidenceFingerprint {
		t.Fatalf("moved attachment reused evidence %+v", movedDecision)
	}
	cross, crossBlast, _ := load("ciem-rcp-cross")
	crossDecision := reason(crossBlast, iamauth.ActionGetObject, objectARN("ciem-rcp", "readme.txt"))
	if cross.ResourceImpactPaths != 0 || crossDecision.Status != iamauth.StatusDenied {
		t.Fatalf("target RCP %+v paths=%d", crossDecision, cross.ResourceImpactPaths)
	}
	assumed, assumeBlast, _ := load("ciem-rcp-assume")
	assumeDecision := reason(assumeBlast, iamauth.ActionAssumeRole, roleARN(demoAcctData, "CIEMRCPTarget"))
	if assumed.ResourceImpactPaths != 0 || assumeDecision.Status != iamauth.StatusDenied {
		t.Fatalf("assume RCP %+v", assumeDecision)
	}
	mgmt, mgmtBlast, _ := load("ciem-mgmt")
	mgmtDecision := reason(mgmtBlast, iamauth.ActionGetObject, objectARN("ciem-mgmt", "readme.txt"))
	if mgmt.ValidatedAllowed == 0 || mgmtDecision.Status != iamauth.StatusAllowed {
		t.Fatalf("management resource %+v", mgmtDecision)
	}
}

func hasRec(assessment schema.CIEMAssessment, id string) bool {
	for _, rec := range assessment.Recommendations {
		if rec.ID == id {
			return true
		}
	}
	return false
}
