package main

import (
	"context"
	"testing"
	"time"

	"github.com/Zero0x00/cloudrift/internal/ciem"
	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/scans"
)

func TestContainerDemos(t *testing.T) {
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

	taskAssets, taskRels := load("ecs-task-role")
	taskItems := ciem.WorkloadsForRole(role(taskAssets, "ECSTask").ARN, taskAssets, taskRels)
	if len(taskItems) != 1 || taskItems[0].Mechanism != "ecs_task_role" || taskItems[0].Status != "TASK_DEFINITION_CONFIGURATION" {
		t.Fatal(taskItems)
	}
	execAssets, execRels := load("ecs-exec-role")
	execItems := ciem.WorkloadsForRole(role(execAssets, "ECSExec").ARN, execAssets, execRels)
	if len(execItems) != 1 || execItems[0].Mechanism != "ecs_execution_role" {
		t.Fatal(execItems)
	}
	bothAssets, bothRels := load("ecs-both")
	if len(ciem.WorkloadsForRole(role(bothAssets, "ECSTask").ARN, bothAssets, bothRels)) != 1 || len(ciem.WorkloadsForRole(role(bothAssets, "ECSExec").ARN, bothAssets, bothRels)) != 1 {
		t.Fatal("task and execution roles were merged")
	}
	runAssets, runRels := load("ecs-running")
	rev3 := ciem.WorkloadsForRole(role(runAssets, "ECSRev3").ARN, runAssets, runRels)
	var sawRunning bool
	for _, item := range rev3 {
		if item.WorkloadType == string(models.AssetECSTask) && item.Status == "OBSERVED_TASK_CONFIGURATION" && item.Revision == "3" {
			sawRunning = true
		}
	}
	if !sawRunning {
		t.Fatal(rev3)
	}
	if len(ciem.WorkloadsForRole(role(runAssets, "ECSRev4").ARN, runAssets, runRels)) != 1 {
		t.Fatal("newer revision was attributed to the running task")
	}
	idleAssets, idleRels := load("ecs-service-idle")
	idle := ciem.WorkloadsForRole(role(idleAssets, "ECSIdle").ARN, idleAssets, idleRels)
	var sawService, sawTask bool
	for _, item := range idle {
		if item.WorkloadType == string(models.AssetECSService) {
			sawService = true
			if item.RuntimeObserved == "OBSERVED_RUNNING" {
				t.Fatal("idle service was treated as running")
			}
		}
		if item.WorkloadType == string(models.AssetECSTask) {
			sawTask = true
		}
	}
	if !sawService || sawTask {
		t.Fatal(idle)
	}
	missingAssets, missingRels := load("ecs-missing-role")
	listed := ciem.ListWorkloads(missingAssets, missingRels, "", "", string(models.AssetECSTaskDefinition), "")
	if len(listed) != 1 || listed[0].Kind != "UNRESOLVED_ROLE" {
		t.Fatal(listed)
	}
	sharedAssets, sharedRels := load("ecs-shared")
	if len(ciem.WorkloadsForRole(role(sharedAssets, "ECSShared").ARN, sharedAssets, sharedRels)) != 2 {
		t.Fatal("shared task role attachments were collapsed")
	}
	partial, _ := load("ecs-partial")
	if len(partial) != 1 || partial[0].Properties["status"] != "partial" {
		t.Fatal(partial)
	}
	podAssets, podRels := load("eks-pod-id")
	podItems := ciem.WorkloadsForRole(role(podAssets, "PodRole").ARN, podAssets, podRels)
	if len(podItems) != 1 || podItems[0].RuntimeObserved != "NOT_COLLECTED" || podItems[0].Mechanism != "eks_pod_identity" {
		t.Fatal(podItems)
	}
	for _, asset := range podAssets {
		if asset.AssetType == "eks_pod" {
			t.Fatal("pod invented")
		}
	}
	absent, _ := load("eks-sa-absent")
	for _, asset := range absent {
		if asset.AssetType == models.AssetEKSPodIdentity && asset.Properties["kubernetes_service_account"] != "not_collected" {
			t.Fatal(asset.Properties)
		}
	}
	eksMissing, eksMissingRels := load("eks-missing-role")
	eksListed := ciem.ListWorkloads(eksMissing, eksMissingRels, "", "", string(models.AssetEKSPodIdentity), "")
	if len(eksListed) != 1 || eksListed[0].Kind != "UNRESOLVED_ROLE" {
		t.Fatal(eksListed)
	}
	irsaAssets, irsaRels := load("irsa-exact")
	irsaItems := ciem.WorkloadsForRole(role(irsaAssets, "IRSARole").ARN, irsaAssets, irsaRels)
	if len(irsaItems) != 1 || irsaItems[0].Kind != "IRSA_TRUST_CONFIGURATION" || irsaItems[0].RuntimeObserved != "NOT_COLLECTED" {
		t.Fatal(irsaItems)
	}
	wildAssets, wildRels := load("irsa-wildcard")
	wild := ciem.Profile("irsa-wildcard", role(wildAssets, "IRSARole"), wildAssets, wildRels)
	var sawWild bool
	for _, rec := range wild.Recommendations {
		if rec.ID == "review-irsa-wildcard" && !rec.Executable {
			sawWild = true
		}
	}
	if !sawWild {
		t.Fatal(wild.Recommendations)
	}
	none, _ := load("irsa-no-k8s")
	for _, asset := range none {
		if asset.AssetType == "eks_pod" || asset.Properties["kubernetes_attachment"] == "observed" {
			t.Fatal(asset)
		}
	}
	shareAssets, shareRels := load("share-ecs-lambda")
	shareRole := role(shareAssets, "SharedContainer")
	shareImpact := ciem.Impact(context.Background(), "share-ecs-lambda", shareRole, shareAssets, shareRels)
	if len(ciem.WorkloadsForRole(shareRole.ARN, shareAssets, shareRels)) < 2 || len(shareImpact.UniqueImpactedResources) != 1 {
		t.Fatalf("workloads=%d resources=%v", len(ciem.WorkloadsForRole(shareRole.ARN, shareAssets, shareRels)), shareImpact.UniqueImpactedResources)
	}
	denyAssets, denyRels := load("ct-deny")
	denyImpact := ciem.Impact(context.Background(), "ct-deny", role(denyAssets, "CTDeny"), denyAssets, denyRels)
	if denyImpact.ValidatedDenied == 0 {
		t.Fatal(denyImpact)
	}
	scpAssets, scpRels := load("ct-missing-scp")
	scpImpact := ciem.Impact(context.Background(), "ct-missing-scp", role(scpAssets, "CTMissing"), scpAssets, scpRels)
	if scpImpact.EvidenceCoverage.OrganizationsSCP != "NOT_COLLECTED" || scpImpact.EvidenceCoverage.SessionContext != "UNKNOWN_SESSION_RESTRICTIONS" {
		t.Fatal(scpImpact.EvidenceCoverage)
	}
	assumeAssets, assumeRels := load("ct-assume")
	assumeImpact := ciem.Impact(context.Background(), "ct-assume", role(assumeAssets, "CTAssumeCaller"), assumeAssets, assumeRels)
	if !assumeImpact.ValidatedIdentityMovement {
		t.Fatal(assumeImpact)
	}
	histA, relA := load("ct-hist-a")
	histB, relB := load("ct-hist-b")
	if role(histA, "CTHistory").ARN != role(histB, "CTHistory").ARN {
		t.Fatal("history role identity changed")
	}
	b := ciem.Impact(context.Background(), "ct-hist-b", role(histB, "CTHistory"), histB, relB)
	a := ciem.Impact(context.Background(), "ct-hist-a", role(histA, "CTHistory"), histA, relA)
	if len(a.BroadPrivilegeCandidates) != 0 || len(b.BroadPrivilegeCandidates) == 0 {
		t.Fatal(b.BroadPrivilegeCandidates)
	}
}
