package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/blastradius"
	"github.com/Zero0x00/cloudrift/internal/graph"
	"github.com/Zero0x00/cloudrift/internal/iamauth"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestIdentityAttack_ChainAndRejections(t *testing.T) {
	when := time.Date(2026, 10, 10, 16, 0, 0, 0, time.UTC)
	chain := attackReport(t, when, "attack-chain", nil)
	object := objectARN("sec-chain", "readme.txt")
	caller := roleARN(demoAcctCore, "SecChainCaller")
	target := roleARN(demoAcctCore, "SecChainTarget")
	assume := attackHop(chain, "ASSUME_ROLE", caller, target)
	read := attackHop(chain, "READ_S3_OBJECT", target, object)
	if assume.Status != iamauth.StatusAllowed || read.Status != iamauth.StatusAllowed {
		t.Fatalf("chain assume=%s read=%s", assume.Status, read.Status)
	}
	if assume.EvidenceFingerprint == "" || read.DecisionID == "" || assume.DecisionID == read.DecisionID {
		t.Fatalf("hops did not keep distinct decisions: %+v %+v", assume, read)
	}
	if len(chain.ImpactedResources) != 1 || chain.ImpactedResources[0] != object {
		t.Fatalf("impacted: %v", chain.ImpactedResources)
	}
	if chain.ResourceImpactPathCount != 1 || chain.ValidatedTransitionCount != 2 || chain.ReachableIdentityCount != 1 {
		t.Fatalf("paths=%d transitions=%d roles=%d", chain.ResourceImpactPathCount, chain.ValidatedTransitionCount, chain.ReachableIdentityCount)
	}
	if assume.SessionOrigin != "hypothetical_initial" || read.SessionOrigin != "modeled_assume_role" {
		t.Fatalf("session origins assume=%s read=%s", assume.SessionOrigin, read.SessionOrigin)
	}
	if assume.SessionEvidenceClass != "scenario_assumption" || read.ContextFingerprint == assume.ContextFingerprint && assume.ContextFingerprint != "none" {
		t.Fatalf("session class=%s context reused", assume.SessionEvidenceClass)
	}
	if !attackPathReaches(chain, object) {
		t.Fatal("no validated path reaches the object")
	}

	denied := attackReport(t, when, "attack-trust-deny", nil)
	denyHop := attackHop(denied, "ASSUME_ROLE", roleARN(demoAcctCore, "SecDenyCaller"), roleARN(demoAcctCore, "SecDenyTarget"))
	if denyHop.Status != iamauth.StatusDenied || len(denied.Paths) != 0 || len(denied.ImpactedResources) != 0 {
		t.Fatalf("deny: %+v paths=%d", denyHop, len(denied.Paths))
	}
	noCaller := attackReport(t, when, "attack-no-caller", nil)
	if attackHop(noCaller, "ASSUME_ROLE", roleARN(demoAcctCore, "SecUnauthCaller"), roleARN(demoAcctCore, "SecUnauthTarget")).Status == iamauth.StatusAllowed || len(noCaller.Paths) != 0 {
		t.Fatal("trust without caller allow became a path")
	}
	noSession := attackReport(t, when, "attack-caller-session", nil)
	if attackHop(noSession, "ASSUME_ROLE", roleARN(demoAcctCore, "SecNoSessionCaller"), roleARN(demoAcctCore, "SecNoSessionTarget")).Reason != iamauth.ReasonMissingSession || len(noSession.Paths) != 0 {
		t.Fatal("missing caller session was treated as absent")
	}
	targetSession := attackReport(t, when, "attack-target-session", nil)
	if attackHop(targetSession, "ASSUME_ROLE", roleARN(demoAcctCore, "SecOpenCaller"), roleARN(demoAcctCore, "SecOpenTarget")).Status != iamauth.StatusAllowed {
		t.Fatal("caller with a recorded session did not assume")
	}
	if attackHop(targetSession, "READ_S3_OBJECT", roleARN(demoAcctCore, "SecOpenTarget"), objectARN("sec-open-target", "readme.txt")).Reason != iamauth.ReasonMissingSession || len(targetSession.ImpactedResources) != 0 {
		t.Fatal("missing target session became a read")
	}
	mfa := attackReport(t, when, "attack-mfa", nil)
	if attackHop(mfa, "ASSUME_ROLE", roleARN(demoAcctCore, "SecMFACaller"), roleARN(demoAcctCore, "SecMFATarget")).Status != iamauth.StatusConditional || len(mfa.Paths) != 0 {
		t.Fatal("missing MFA context was not conditional")
	}
	mfaOK := attackReport(t, when, "attack-mfa", map[string]string{"aws:MultiFactorAuthPresent": "true"})
	if attackHop(mfaOK, "ASSUME_ROLE", roleARN(demoAcctCore, "SecMFACaller"), roleARN(demoAcctCore, "SecMFATarget")).Status != iamauth.StatusAllowed || len(mfaOK.ImpactedResources) != 1 {
		t.Fatal("satisfied MFA context did not open the target session")
	}
	ext := attackReport(t, when, "attack-external-id", nil)
	if attackHop(ext, "ASSUME_ROLE", roleARN(demoAcctCore, "SecExtCaller"), roleARN(demoAcctCore, "SecExtTarget")).Status != iamauth.StatusConditional {
		t.Fatal("missing external id was not conditional")
	}
	extOK := attackReport(t, when, "attack-external-id", map[string]string{"sts:ExternalId": "chain-external-id"})
	if attackHop(extOK, "READ_S3_OBJECT", roleARN(demoAcctCore, "SecExtTarget"), objectARN("sec-external", "readme.txt")).Status != iamauth.StatusAllowed {
		t.Fatal("satisfied external id did not allow the object read")
	}
	cross := attackReport(t, when, "attack-cross", nil)
	crossAssume := attackHop(cross, "ASSUME_ROLE", roleARN(demoAcctCore, "SecCrossCaller"), roleARN(demoAcctData, "SecCrossTarget"))
	if crossAssume.Status != iamauth.StatusAllowed || crossAssume.SameAccount || len(cross.ImpactedResources) != 1 {
		t.Fatalf("cross chain: %+v impacted=%v", crossAssume, cross.ImpactedResources)
	}
	cycle := attackReport(t, when, "attack-cycle", nil)
	var sawCycle bool
	for _, hop := range cycle.Transitions {
		if hop.Cycle {
			sawCycle = true
		}
	}
	if !sawCycle || cycle.StatesExplored > 8 || cycle.ValidatedRoleTransitions < 2 {
		t.Fatalf("cycle search: explored=%d validated=%d", cycle.StatesExplored, cycle.ValidatedRoleTransitions)
	}
	multi := attackReport(t, when, "attack-multipath", nil)
	if len(multi.ImpactedResources) != 1 || pathsEnding(multi, objectARN("sec-multi", "readme.txt")) < 2 {
		t.Fatalf("multipath impacted=%v paths=%d", multi.ImpactedResources, pathsEnding(multi, objectARN("sec-multi", "readme.txt")))
	}
	blind := attackReport(t, when, "attack-no-read", nil)
	if attackHop(blind, "ASSUME_ROLE", roleARN(demoAcctCore, "SecBlindCaller"), roleARN(demoAcctCore, "SecBlindTarget")).Status != iamauth.StatusAllowed || len(blind.ImpactedResources) != 0 || blind.ResourceImpactPathCount != 0 || blind.ReachableIdentityCount != 1 {
		t.Fatal("role assumption was treated as object access")
	}
	fed := attackReport(t, when, "attack-federated", nil)
	if attackHop(fed, "ASSUME_ROLE", roleARN(demoAcctCore, "SecFedCaller"), roleARN(demoAcctCore, "SecFedTarget")).Status == iamauth.StatusAllowed || !containsString(fed.UnsupportedTechniques, "sts:AssumeRoleWithWebIdentity") {
		t.Fatal("federated assumption was evaluated as sts:AssumeRole")
	}
	scp := attackReport(t, when, "attack-missing-scp", nil)
	if attackHop(scp, "ASSUME_ROLE", roleARN(demoAcctCore, "SecSCPCaller"), roleARN(demoAcctCore, "SecSCPTarget")).Reason != iamauth.ReasonMissingSCP || len(scp.Paths) != 0 {
		t.Fatal("missing SCP became a validated assumption")
	}
	open := attackReport(t, when, "attack-history-open", nil)
	closed := attackReport(t, when, "attack-history-closed", nil)
	if len(open.ImpactedResources) != 1 || len(closed.ImpactedResources) != 0 {
		t.Fatalf("history open=%v closed=%v", open.ImpactedResources, closed.ImpactedResources)
	}
	if attackHop(open, "READ_S3_OBJECT", roleARN(demoAcctCore, "SecAttackHistTarget"), objectARN("sec-attack-hist", "notes.txt")).EvidenceFingerprint ==
		attackHop(closed, "ASSUME_ROLE", roleARN(demoAcctCore, "SecAttackHistCaller"), roleARN(demoAcctCore, "SecAttackHistTarget")).EvidenceFingerprint {
		t.Fatal("history scans shared an evidence fingerprint")
	}
}

func TestIdentityAttack_Neo4jProjection(t *testing.T) {
	uri := os.Getenv("CLOUDRIFT_NEO4J_URI")
	if uri == "" {
		t.Skip("CLOUDRIFT_NEO4J_URI not set")
	}
	when := time.Date(2026, 10, 10, 16, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	const scanID = "demo-attack-chain-e2e"
	if _, err := generateDemoScanWithOptions(dir, when, scanID, demoOptions{Scenario: "attack-chain", Profile: "legacy", Seed: 1}); err != nil {
		t.Fatal(err)
	}
	meta, assets, rels, findings := loadGraphDemo(t, dir, scanID)
	report := blastradius.AnalyzeIdentityAttack(context.Background(), blastradius.IdentityAttackRequest{
		ScanID: scanID, InitialPrincipal: roleARN(demoAcctCore, "SecChainCaller"), SessionSource: "assumed",
		Assets: assets, Relationships: rels, EvaluatedAt: when,
	})
	if len(report.ImpactedResources) != 1 {
		t.Fatalf("chain: %+v", report.ImpactedResources)
	}
	user := os.Getenv("CLOUDRIFT_NEO4J_USER")
	if user == "" {
		user = "neo4j"
	}
	ctx := context.Background()
	driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(user, os.Getenv("CLOUDRIFT_NEO4J_PASSWORD"), ""))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = driver.Close(ctx) })
	ex := graph.NewDriverExecer(driver, os.Getenv("CLOUDRIFT_NEO4J_DATABASE"))
	t.Cleanup(func() {
		_ = ex.Run(ctx, `MATCH (n) WHERE n.scan_id = $scan DETACH DELETE n`, map[string]any{"scan": scanID})
	})
	if err := graph.WriteScan(ctx, ex, meta, assets, rels, findings); err != nil {
		t.Fatal(err)
	}
	var hops []models.Relationship
	for _, hop := range report.Transitions {
		if hop.Status != iamauth.StatusAllowed {
			continue
		}
		hops = append(hops, models.Relationship{
			SourceARN: hop.SourcePrincipal, TargetARN: hop.TargetARN, RelType: models.RelValidatedAttackTransition, ScanID: scanID,
			Properties: map[string]any{
				"technique": hop.Technique, "decision": hop.Status, "decision_id": hop.DecisionID,
				"feasibility": hop.Feasibility, "evidence_fingerprint": hop.EvidenceFingerprint, "hypothetical": true,
			},
		})
	}
	if err := graph.WriteAuthorizationFacts(ctx, ex, scanID, nil, hops); err != nil {
		t.Fatal(err)
	}
	session := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead, DatabaseName: os.Getenv("CLOUDRIFT_NEO4J_DATABASE")})
	defer session.Close(ctx)
	rows, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, `
MATCH (a:Asset {arn: $caller, scan_id: $scan})-[ab:VALIDATED_ATTACK_TRANSITION {scan_id: $scan}]->(b:Asset {arn: $target, scan_id: $scan})-[read:VALIDATED_ATTACK_TRANSITION {scan_id: $scan}]->(obj:Asset {arn: $object, scan_id: $scan})
RETURN ab.technique AS assume, read.technique AS readTech, ab.decision AS decision
`, map[string]any{
			"caller": roleARN(demoAcctCore, "SecChainCaller"),
			"target": roleARN(demoAcctCore, "SecChainTarget"),
			"object": objectARN("sec-chain", "readme.txt"),
			"scan":   scanID,
		})
		if err != nil {
			return nil, err
		}
		var out []string
		for res.Next(ctx) {
			assume, _ := res.Record().Get("assume")
			readTech, _ := res.Record().Get("readTech")
			out = append(out, assume.(string)+"|"+readTech.(string))
		}
		return out, res.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	got := rows.([]string)
	if len(got) != 1 || got[0] != "ASSUME_ROLE|READ_S3_OBJECT" {
		t.Fatalf("neo4j chain: %#v", got)
	}
}

func TestIdentityAttack_DoesNotEmitStoredTransitions(t *testing.T) {
	dir := t.TempDir()
	if _, err := generateDemoScanWithOptions(dir, time.Date(2026, 10, 10, 16, 0, 0, 0, time.UTC), "demo-attack-chain", demoOptions{Scenario: "attack-chain", Profile: "legacy", Seed: 1}); err != nil {
		t.Fatal(err)
	}
	_, rels := loadDemo(t, dir, "demo-attack-chain")
	for _, rel := range rels {
		if rel.RelType == models.RelValidatedAttackTransition || rel.RelType == models.RelHasAuthorizationDecision {
			t.Fatalf("generator stored an evaluated hop: %+v", rel)
		}
	}
}

func attackReport(t *testing.T, when time.Time, scenario string, ctx map[string]string) schema.IdentityAttackReport {
	t.Helper()
	dir := t.TempDir()
	scanID := "demo-" + scenario
	if _, err := generateDemoScanWithOptions(dir, when, scanID, demoOptions{Scenario: scenario, Profile: "legacy", Seed: 1}); err != nil {
		t.Fatal(err)
	}
	assets, rels := loadDemo(t, dir, scanID)
	var principal string
	for _, asset := range assets {
		if asset.AssetType == models.AssetIAMRole && (principal == "" || asset.Name < principal) {
			if asset.Name == "SecChainCaller" || asset.Name == "SecDenyCaller" || asset.Name == "SecUnauthCaller" || asset.Name == "SecNoSessionCaller" || asset.Name == "SecOpenCaller" || asset.Name == "SecMFACaller" || asset.Name == "SecExtCaller" || asset.Name == "SecCrossCaller" || asset.Name == "SecCycleA" || asset.Name == "SecMultiA" || asset.Name == "SecBlindCaller" || asset.Name == "SecFedCaller" || asset.Name == "SecSCPCaller" || asset.Name == "SecAttackHistCaller" {
				principal = asset.ARN
			}
		}
	}
	if principal == "" {
		t.Fatalf("scenario %s has no start role", scenario)
	}
	return blastradius.AnalyzeIdentityAttack(context.Background(), blastradius.IdentityAttackRequest{
		ScanID: scanID, InitialPrincipal: principal, SessionSource: "assumed",
		RequestContext: ctx, Assets: assets, Relationships: rels, EvaluatedAt: when,
	})
}

func attackHop(report schema.IdentityAttackReport, technique, source, target string) blastradiusAttack {
	for _, hop := range report.Transitions {
		if hop.Technique == technique && hop.SourcePrincipal == source && hop.TargetARN == target {
			return blastradiusAttack{
				Status: hop.Status, Reason: hop.Reason, DecisionID: hop.DecisionID,
				EvidenceFingerprint: hop.EvidenceFingerprint, SameAccount: hop.SameAccount,
				SessionOrigin: hop.SessionOrigin, SessionEvidenceClass: hop.SessionEvidenceClass,
				ContextFingerprint: hop.ContextFingerprint,
			}
		}
	}
	return blastradiusAttack{}
}

type blastradiusAttack struct {
	Status, Reason, DecisionID, EvidenceFingerprint string
	SessionOrigin, SessionEvidenceClass             string
	ContextFingerprint                              string
	SameAccount                                     bool
}

func attackPathReaches(report schema.IdentityAttackReport, object string) bool {
	for _, path := range report.Paths {
		if len(path.NodeIDs) > 0 && path.NodeIDs[len(path.NodeIDs)-1] == object && path.Validity == "VALIDATED_POSSIBLE" {
			return true
		}
	}
	return false
}

func pathsEnding(report schema.IdentityAttackReport, object string) int {
	n := 0
	for _, path := range report.Paths {
		if len(path.NodeIDs) > 0 && path.NodeIDs[len(path.NodeIDs)-1] == object {
			n++
		}
	}
	return n
}
