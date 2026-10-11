package main

import (
	"context"
	"testing"
	"time"

	"github.com/Zero0x00/cloudrift/internal/ciem"
	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/scans"
)

func TestWorkloadDemos(t *testing.T) {
	when := time.Date(2026, 10, 10, 23, 0, 0, 0, time.UTC)
	load := func(scenario string) ([]models.AssetNode, []models.Relationship) {
		t.Helper()
		dir := t.TempDir()
		if _, err := generateDemoScanWithOptions(dir, when, scenario, demoOptions{Scenario: scenario, Profile: "legacy", Seed: 1}); err != nil {
			t.Fatal(err)
		}
		assets, err := scans.LoadAssets(dir, scenario)
		if err != nil {
			t.Fatal(err)
		}
		rels, err := scans.LoadRelationships(dir, scenario)
		if err != nil {
			t.Fatal(err)
		}
		return assets, rels
	}
	role := func(assets []models.AssetNode, name string) models.AssetNode {
		t.Helper()
		for _, asset := range assets {
			if asset.AssetType == models.AssetIAMRole && asset.Name == name {
				return asset
			}
		}
		t.Fatalf("missing %s", name)
		return models.AssetNode{}
	}

	mapped, mappedRels := load("wl-ec2-map")
	attached := ciem.WorkloadsForRole(role(mapped, "WLMapRole").ARN, mapped, mappedRels)
	if len(attached) != 1 || attached[0].Kind != "CONFIGURED_ROLE_ATTACHMENT" || attached[0].Mechanism != "instance_profile" {
		t.Fatal(attached)
	}
	none, noneRels := load("wl-ec2-none")
	if len(ciem.WorkloadsForRole(role(none, "WLNoneRole").ARN, none, noneRels)) != 0 {
		t.Fatal("instance without a profile was attached")
	}
	names, namesRels := load("wl-ec2-names")
	for _, asset := range names {
		if asset.AssetType == models.AssetInstanceProfile && asset.Name == "WLAppRole" {
			t.Fatal("profile name matched the role name")
		}
	}
	if len(ciem.WorkloadsForRole(role(names, "WLAppRole").ARN, names, namesRels)) != 1 {
		t.Fatal("differently named profile did not resolve")
	}
	denied, deniedRels := load("wl-ec2-denied")
	if len(ciem.WorkloadsForRole(role(denied, "WLDeniedRole").ARN, denied, deniedRels)) != 0 {
		t.Fatal("denied profile read became an attachment")
	}
	shared, sharedRels := load("wl-ec2-share")
	sharedItems := ciem.WorkloadsForRole(role(shared, "WLSharedRole").ARN, shared, sharedRels)
	if len(sharedItems) != 2 {
		t.Fatal(sharedItems)
	}
	scoped, scopedRels := load("wl-lambda-scoped")
	scopedRole := role(scoped, "WLLambdaScoped")
	if len(ciem.WorkloadsForRole(scopedRole.ARN, scoped, scopedRels)) != 1 {
		t.Fatal("lambda execution role was not mapped")
	}
	impact := ciem.Impact(context.Background(), "wl-lambda-scoped", scopedRole, scoped, scopedRels)
	if impact.ValidatedAllowed == 0 || impact.Kind != "internal_role_compromise" {
		t.Fatalf("%+v", impact)
	}
	admin, adminRels := load("wl-lambda-admin")
	adminImpact := ciem.Impact(context.Background(), "wl-lambda-admin", role(admin, "WLLambdaAdmin"), admin, adminRels)
	if len(adminImpact.BroadPrivilegeCandidates) == 0 {
		t.Fatal(adminImpact.BroadPrivilegeCandidates)
	}
	missing, missingRels := load("wl-lambda-missing")
	listed := ciem.ListWorkloads(missing, missingRels, "", "", string(models.AssetLambdaFunction), "")
	if len(listed) != 1 || listed[0].Kind != "UNRESOLVED_ROLE" {
		t.Fatal(listed)
	}
	missingSCP, missingSCPRels := load("wl-missing-scp")
	scpImpact := ciem.Impact(context.Background(), "wl-missing-scp", role(missingSCP, "WLMissingSCP"), missingSCP, missingSCPRels)
	if scpImpact.EvidenceCoverage.OrganizationsSCP != "NOT_COLLECTED" || scpImpact.EvidenceCoverage.SessionContext != "UNKNOWN_SESSION_RESTRICTIONS" {
		t.Fatalf("%+v", scpImpact.EvidenceCoverage)
	}
	deniedPolicy, deniedPolicyRels := load("wl-deny")
	denyImpact := ciem.Impact(context.Background(), "wl-deny", role(deniedPolicy, "WLDeny"), deniedPolicy, deniedPolicyRels)
	if denyImpact.ValidatedDenied == 0 {
		t.Fatalf("explicit deny was not evaluated: %+v", denyImpact)
	}
	trustOnly, trustRels := load("wl-lambda-trust")
	profile := ciem.Profile("wl-lambda-trust", role(trustOnly, "WLServiceOnly"), trustOnly, trustRels)
	if profile.WorkloadCount != 0 || profile.AttachmentNote == "" {
		t.Fatal(profile.AttachmentNote)
	}
	gap, gapRels := load("wl-org-gap")
	if !hasLabel(ciem.ClassifyRole(role(gap, "WLOrgGap"), gapRels, gap), ciem.ClassInternalNotScanned) {
		t.Fatal(ciem.ClassifyRole(role(gap, "WLOrgGap"), gapRels, gap))
	}
	unknown, unknownRels := load("wl-org-unknown")
	if !hasLabel(ciem.ClassifyRole(role(unknown, "WLOrgUnknown"), unknownRels, unknown), ciem.ClassUnknownOrgMembership) {
		t.Fatal(ciem.ClassifyRole(role(unknown, "WLOrgUnknown"), unknownRels, unknown))
	}
	both, bothRels := load("wl-shared-resource")
	bothRole := role(both, "WLBoth")
	bothImpact := ciem.Impact(context.Background(), "wl-shared-resource", bothRole, both, bothRels)
	if len(ciem.WorkloadsForRole(bothRole.ARN, both, bothRels)) != 2 || len(bothImpact.UniqueImpactedResources) != 1 {
		t.Fatalf("workloads=%d resources=%v", len(ciem.WorkloadsForRole(bothRole.ARN, both, bothRels)), bothImpact.UniqueImpactedResources)
	}
	listedBoth := ciem.ListWorkloads(both, bothRels, "", "", "", bothRole.ARN)
	if len(listedBoth) != 2 {
		t.Fatalf("shared role list dropped a workload: %+v", listedBoth)
	}
	assumeAssets, assumeRels := load("wl-assume")
	assumeImpact := ciem.Impact(context.Background(), "wl-assume", role(assumeAssets, "WLAssumeCaller"), assumeAssets, assumeRels)
	if !assumeImpact.ValidatedIdentityMovement {
		t.Fatalf("%+v", assumeImpact)
	}
	histA, relA := load("wl-hist-a")
	histB, relB := load("wl-hist-b")
	a := ciem.Impact(context.Background(), "wl-hist-a", role(histA, "WLHistory"), histA, relA)
	b := ciem.Impact(context.Background(), "wl-hist-b", role(histB, "WLHistory"), histB, relB)
	if a.RoleARN != b.RoleARN || len(b.BroadPrivilegeCandidates) == 0 {
		t.Fatal(b.BroadPrivilegeCandidates)
	}
	one, oneRels := load("wl-attach-a")
	two, twoRels := load("wl-attach-b")
	if len(ciem.WorkloadsForRole(role(one, "WLAttachRole").ARN, one, oneRels)) != 1 || len(ciem.WorkloadsForRole(role(two, "WLAttachRole").ARN, two, twoRels)) != 2 {
		t.Fatal("attachment count did not change across scans")
	}
}
