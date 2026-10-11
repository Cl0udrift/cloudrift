package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Zero0x00/cloudrift/internal/ciem"
	"github.com/Zero0x00/cloudrift/internal/iamauth"
	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/scans"
)

func TestIdentityDemos(t *testing.T) {
	when := time.Date(2026, 10, 10, 22, 0, 0, 0, time.UTC)
	load := func(scenario string) ([]models.AssetNode, []models.Relationship) {
		t.Helper()
		dir := t.TempDir()
		if _, err := generateDemoScanWithOptions(dir, when, scenario, demoOptions{Scenario: scenario, Profile: "legacy", Seed: 1}); err != nil {
			t.Fatal(err)
		}
		rawAssets, _ := scans.LoadAssets(dir, scenario)
		rels, _ := scans.LoadRelationships(dir, scenario)
		return rawAssets, rels
	}
	role := func(assets []models.AssetNode, name string) models.AssetNode {
		t.Helper()
		for _, asset := range assets {
			if asset.AssetType == models.AssetIAMRole && asset.Name == name {
				return asset
			}
		}
		t.Fatalf("missing role %s", name)
		return models.AssetNode{}
	}
	labels := func(assets []models.AssetNode, rels []models.Relationship, name string) []string {
		item := role(assets, name)
		return ciem.ClassifyRole(item, rels, assets)
	}

	narrowAssets, narrowRels := load("id-narrow")
	narrow := role(narrowAssets, "IDNarrow")
	if !hasLabel(labels(narrowAssets, narrowRels, "IDNarrow"), ciem.ClassSameAccount) {
		t.Fatal(labels(narrowAssets, narrowRels, "IDNarrow"))
	}
	narrowImpact := ciem.Impact(context.Background(), "id-narrow", narrow, narrowAssets, narrowRels)
	if narrowImpact.ValidatedAllowed == 0 || len(narrowImpact.BroadPrivilegeCandidates) != 0 {
		t.Fatalf("narrow %+v", narrowImpact)
	}

	adminAssets, adminRels := load("id-admin-no-path")
	admin := role(adminAssets, "IDAdminIdle")
	adminImpact := ciem.Impact(context.Background(), "id-admin-no-path", admin, adminAssets, adminRels)
	if len(adminImpact.BroadPrivilegeCandidates) == 0 || adminImpact.ResourceImpactPaths != 0 {
		t.Fatalf("admin without path %+v", adminImpact)
	}

	sameAssets, sameRels := load("id-same-trust")
	if !hasLabel(labels(sameAssets, sameRels, "IDSameTarget"), ciem.ClassSameAccount) {
		t.Fatal(labels(sameAssets, sameRels, "IDSameTarget"))
	}
	crossAssets, crossRels := load("id-cross-trust")
	if !hasLabel(labels(crossAssets, crossRels, "IDCrossTarget"), ciem.ClassInternalCrossAccount) {
		t.Fatal(labels(crossAssets, crossRels, "IDCrossTarget"))
	}
	noPermAssets, noPermRels := load("id-trust-no-caller")
	noPerm := role(noPermAssets, "IDNoPermCaller")
	noPermImpact := ciem.Impact(context.Background(), "id-trust-no-caller", noPerm, noPermAssets, noPermRels)
	if noPermImpact.ReachableIdentities != 0 || noPermImpact.ValidatedIdentityMovement {
		t.Fatalf("trust without caller permission %+v", noPermImpact)
	}
	okAssets, okRels := load("id-assume-ok")
	okCaller := role(okAssets, "IDAssumeCaller")
	okImpact := ciem.Impact(context.Background(), "id-assume-ok", okCaller, okAssets, okRels)
	if okImpact.ValidatedTransitions == 0 {
		t.Fatalf("validated assume %+v", okImpact)
	}
	denyAssets, denyRels := load("id-trust-deny")
	denyCaller := role(denyAssets, "IDDenyCaller")
	denyImpact := ciem.Impact(context.Background(), "id-trust-deny", denyCaller, denyAssets, denyRels)
	if denyImpact.ValidatedDenied == 0 || denyImpact.ValidatedTransitions != 0 {
		t.Fatalf("trust deny %+v", denyImpact)
	}

	boundAssets, boundRels := load("id-boundary")
	bound := ciem.Impact(context.Background(), "id-boundary", role(boundAssets, "IDBoundary"), boundAssets, boundRels)
	if bound.ValidatedDenied == 0 {
		t.Fatalf("boundary %+v", bound)
	}
	scpAssets, scpRels := load("id-scp")
	scp := ciem.Impact(context.Background(), "id-scp", role(scpAssets, "IDSCP"), scpAssets, scpRels)
	if scp.ValidatedDenied == 0 {
		t.Fatalf("scp %+v", scp)
	}
	rcpAssets, rcpRels := load("id-rcp")
	rcp := ciem.Impact(context.Background(), "id-rcp", role(rcpAssets, "IDRCP"), rcpAssets, rcpRels)
	if rcp.ValidatedDenied == 0 {
		t.Fatalf("rcp %+v", rcp)
	}
	missingAssets, missingRels := load("id-missing-org")
	missing := ciem.Impact(context.Background(), "id-missing-org", role(missingAssets, "IDMissingOrg"), missingAssets, missingRels)
	if missing.ValidatedAllowed != 0 {
		t.Fatalf("missing org %+v", missing)
	}
	sessionAssets, sessionRels := load("id-missing-session")
	session := ciem.Impact(context.Background(), "id-missing-session", role(sessionAssets, "IDMissingSession"), sessionAssets, sessionRels)
	if session.ValidatedAllowed != 0 {
		t.Fatalf("missing session %+v", session)
	}

	sharedAssets, _ := load("id-shared-policy")
	policyARN := "arn:aws:iam::aws:policy/AdministratorAccess"
	seen := 0
	for _, asset := range sharedAssets {
		if asset.ARN == policyARN {
			seen++
		}
	}
	if seen < 1 {
		t.Fatal("shared managed policy was not stored")
	}
	mixedAssets, mixedRels := load("id-mixed")
	mixed := labels(mixedAssets, mixedRels, "IDMixed")
	if !hasLabel(mixed, ciem.ClassMixedTrust) || !hasLabel(mixed, ciem.ClassExternalDelegated) || !hasLabel(mixed, ciem.ClassSameAccount) {
		t.Fatal(mixed)
	}
	serviceAssets, serviceRels := load("id-service")
	if !hasLabel(labels(serviceAssets, serviceRels, "IDService"), ciem.ClassAWSServiceRole) {
		t.Fatal(labels(serviceAssets, serviceRels, "IDService"))
	}
	for _, asset := range serviceAssets {
		if asset.AssetType == "ec2_instance" {
			t.Fatal("service trust was treated as an attached instance")
		}
	}
	slrAssets, slrRels := load("id-slr")
	if !hasLabel(labels(slrAssets, slrRels, "IDSLR"), ciem.ClassServiceLinkedRole) {
		t.Fatal(labels(slrAssets, slrRels, "IDSLR"))
	}
	wildAssets, wildRels := load("id-wildcard")
	if !hasLabel(labels(wildAssets, wildRels, "IDWildcard"), ciem.ClassExternalDelegated) {
		t.Fatal(labels(wildAssets, wildRels, "IDWildcard"))
	}
	profile := ciem.Profile("id-wildcard", role(wildAssets, "IDWildcard"), wildAssets, wildRels)
	if len(profile.Trusts) == 0 || profile.Trusts[0].Kind != "CONFIGURED_TRUST" || profile.ExecutionEnabled {
		t.Fatalf("%+v", profile)
	}

	multiAssets, multiRels := load("id-multipath")
	multi := ciem.Impact(context.Background(), "id-multipath", role(multiAssets, "IDMultiCaller"), multiAssets, multiRels)
	if multi.ResourceImpactPaths < 1 {
		t.Fatalf("multipath %+v", multi)
	}

	histA, relA := load("id-hist-a")
	histB, relB := load("id-hist-b")
	a := ciem.Impact(context.Background(), "id-hist-a", role(histA, "IDHistory"), histA, relA)
	b := ciem.Impact(context.Background(), "id-hist-b", role(histB, "IDHistory"), histB, relB)
	if a.RoleARN != b.RoleARN || len(b.BroadPrivilegeCandidates) == 0 {
		t.Fatalf("history a=%s b=%v", a.RoleARN, b.BroadPrivilegeCandidates)
	}

	filtered := ciem.ListRoles(narrowAssets, narrowRels, ciem.InventoryFilter{AccountID: demoAcctCore, Search: "IDNarrow"})
	if len(filtered) != 1 {
		t.Fatal(filtered)
	}
	_ = iamauth.EvaluatorVersion
	if strings.Contains(strings.Join(profile.BroadCandidates, ","), "VALIDATED") {
		t.Fatal("profile stored a decision")
	}
}

func hasLabel(labels []string, want string) bool {
	for _, label := range labels {
		if label == want {
			return true
		}
	}
	return false
}
