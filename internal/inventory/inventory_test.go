package inventory

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestSummaryExcludesEvidenceAndBalancesServices(t *testing.T) {
	assets := []models.AssetNode{
		{ARN: "arn:aws:ec2:us-east-1:111:instance/i-1", AssetType: models.AssetEC2Instance, AccountID: "111", Region: "us-east-1", Name: "i-1"},
		{ARN: "arn:aws:iam::111:instance-profile/p", AssetType: models.AssetInstanceProfile, AccountID: "111", Name: "p"},
		{ARN: "arn:aws:iam::111:role/App", AssetType: models.AssetIAMRole, AccountID: "111", Name: "App"},
		{ARN: "arn:aws:iam::111:policy/P", AssetType: models.AssetIAMPolicy, AccountID: "111", Name: "P"},
		{ARN: "arn:aws:iam::111:policy/P:statement", AssetType: models.AssetIAMPolicyStatement, AccountID: "111"},
		{ARN: "arn:cloudrift:decision:1", AssetType: models.AssetIAMAuthorizationDecision},
		{ARN: "arn:cloudrift:principal:1", AssetType: models.AssetExternalPrincipal},
		{ARN: "org:111", AssetType: models.AssetOrganizationAccount, AccountID: "111"},
		{ARN: "arn:cloudrift:irsa:1", AssetType: models.AssetIRSATrust, AccountID: "111", Region: "us-east-1"},
		{ARN: "arn:cloudrift:sa:1", AssetType: models.AssetEKSServiceAccountRef},
		{ARN: "arn:aws:eks:us-east-1:111:podidentityassociation/c/ns/sa", AssetType: models.AssetEKSPodIdentity, AccountID: "111", Region: "us-east-1", Name: "ns/sa"},
		{ARN: "arn:aws:ecs:us-east-1:111:task-definition/app:1", AssetType: models.AssetECSTaskDefinition, AccountID: "111", Region: "us-east-1", Name: "app:1"},
		{ARN: "arn:aws:ecs:us-east-1:111:task/c/t", AssetType: models.AssetECSTask, AccountID: "111", Region: "us-east-1", Name: "t"},
		{ARN: "arn:aws:s3:::logs", AssetType: models.AssetS3Bucket, AccountID: "111", Name: "logs"},
		{ARN: "custom:thing", AssetType: "widget", AccountID: "222", Region: "eu-west-1", Name: "thing"},
		{ARN: "arn:aws:ec2:us-east-1:111:instance/i-1", AssetType: models.AssetEC2Instance, Name: "duplicate"},
	}
	findings := []models.Finding{{ID: "f1", AffectedARN: "arn:aws:s3:::logs", Severity: "high", Module: "orphaned_edge", Title: "bucket"}}
	summary := Summarize(models.ScanSnapshot{ScanID: "s", Synthetic: true, Timestamp: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)}, assets, nil, findings, Filter{})
	sum := 0
	services := map[string]bool{}
	for _, card := range summary.Services {
		sum += card.Count
		if card.Count > 0 {
			services[card.Service] = true
		}
		if card.Service == "s3" && card.FindingCount != 1 {
			t.Fatalf("s3 findings %+v", card)
		}
	}
	if summary.TotalAssets != sum || summary.TotalAssets != 9 {
		t.Fatalf("total %d sum %d", summary.TotalAssets, sum)
	}
	if summary.ServiceCount != len(services) || summary.AccountCount != 2 || summary.RegionCount != 2 {
		t.Fatalf("%+v", summary)
	}
	categorySum := 0
	for _, category := range summary.Categories {
		categorySum += category.Count
	}
	if categorySum != summary.TotalAssets {
		t.Fatalf("categories %d total %d", categorySum, summary.TotalAssets)
	}
	for _, card := range summary.Services {
		if card.Count > 0 && card.Coverage == "COLLECTED" {
			t.Fatalf("assets without collection status were treated as complete: %+v", card)
		}
	}
	for _, card := range summary.Services {
		if card.Service == "eks" && card.Count != 1 {
			t.Fatalf("pod counted as more than the association: %+v", card)
		}
		if card.Service == "ecs" && card.Count != 2 {
			t.Fatalf("ecs %+v", card)
		}
		if card.Service == "iam" && card.Count != 3 {
			t.Fatalf("iam %+v", card)
		}
	}
	filtered := Summarize(models.ScanSnapshot{}, assets, nil, nil, Filter{AccountID: "222", Region: "eu-west-1"})
	if filtered.TotalAssets != 1 || filtered.Services[len(filtered.Services)-1].Service != "other" {
		t.Fatalf("%+v", filtered)
	}
	listed := Build(assets, nil, findings, Filter{AccountID: "111", Region: "us-east-1", Service: "ecs", Query: "app"})
	if len(listed) != 1 || listed[0].ResourceType != "ecs_task_definition" {
		t.Fatalf("%+v", listed)
	}
	page := Page(Build(assets, nil, nil, Filter{}), "name", 1, 2)
	if page.TotalItems != 9 || len(page.Items) != 2 || page.TotalPages != 5 {
		t.Fatalf("%+v", page)
	}
	empty := Summarize(models.ScanSnapshot{}, nil, nil, nil, Filter{})
	if empty.TotalAssets != 0 {
		t.Fatal(empty.TotalAssets)
	}
	for _, card := range empty.Services {
		if card.Count != 0 || card.Coverage != "NOT_RECORDED" {
			t.Fatalf("empty shown as collected zero: %+v", card)
		}
	}
}

func TestReconcileDuplicatesAndCategories(t *testing.T) {
	first := models.AssetNode{ARN: "arn:aws:ec2:us-east-1:111:instance/i-1", AssetType: models.AssetEC2Instance, Name: "web", AccountID: "111", Properties: map[string]any{"state": "running"}}
	second := models.AssetNode{ARN: first.ARN, AssetType: models.AssetEC2Instance, Name: "api", Region: "us-east-1", Properties: map[string]any{"az": "us-east-1a"}}
	conflict := models.AssetNode{ARN: first.ARN, AssetType: models.AssetEC2Instance, Name: "web", AccountID: "999", Properties: map[string]any{"state": "stopped"}}
	noARN := models.AssetNode{AssetType: models.AssetS3Bucket, Name: "logs", AccountID: "111", Region: "us-east-1"}
	sameNoARN := models.AssetNode{AssetType: models.AssetS3Bucket, Name: "logs", AccountID: "111", Region: "us-east-1", Properties: map[string]any{"encryption": "AES256"}}
	otherName := models.AssetNode{AssetType: models.AssetS3Bucket, Name: "other", AccountID: "111", Region: "us-east-1"}
	otherScan := models.AssetNode{ScanID: "scan-b", ARN: first.ARN, AssetType: models.AssetEC2Instance, Name: "foreign"}
	forward := Build([]models.AssetNode{first, second, conflict, noARN, sameNoARN, otherName, otherScan}, nil, nil, Filter{})
	reverse := Build([]models.AssetNode{otherScan, otherName, sameNoARN, noARN, conflict, second, first}, nil, nil, Filter{})
	if len(forward) != 4 || len(reverse) != 4 {
		t.Fatalf("forward %d reverse %d", len(forward), len(reverse))
	}
	var instanceName, instanceRegion, instanceID string
	for _, item := range forward {
		if item.ResourceType == "ec2_instance" && item.AccountID == "111" {
			instanceName, instanceRegion, instanceID = item.Name, item.Region, item.ID
		}
	}
	if instanceRegion != "us-east-1" || instanceName != "api" {
		t.Fatalf("merge name %s region %s", instanceName, instanceRegion)
	}
	conflicted := []models.AssetNode{
		{ARN: "arn:aws:ec2:us-east-1:111111111111:instance/i-9", AssetType: models.AssetEC2Instance, AccountID: "000000000000", Name: "a"},
		{ARN: "arn:aws:ec2:us-east-1:111111111111:instance/i-9", AssetType: models.AssetEC2Instance, AccountID: "222222222222", Name: "a", Properties: map[string]any{"trust_policy": "a", "state": "running"}},
		{ARN: "arn:aws:ec2:us-east-1:111111111111:instance/i-9", AssetType: models.AssetEC2Instance, AccountID: "222222222222", Name: "a", Properties: map[string]any{"trust_policy": "b", "state": "stopped"}},
	}
	wrongAccount := Build(conflicted, nil, nil, Filter{})
	if len(wrongAccount) != 1 || wrongAccount[0].AccountID != "111111111111" {
		t.Fatalf("ARN account lost: %+v", wrongAccount)
	}
	conflictDetail, ok := Detail("s", wrongAccount[0].ID, conflicted, nil, nil)
	if !ok {
		t.Fatal("conflict detail missing")
	}
	if _, present := conflictDetail.Evidence["trust_policy"]; present {
		t.Fatal("conflicting trust policy was kept")
	}
	if conflictDetail.Evidence["state"] != "running" {
		t.Fatalf("non-security property: %+v", conflictDetail.Evidence)
	}
	detail, ok := Detail("s", instanceID, []models.AssetNode{first, second, conflict}, nil, nil)
	if !ok || detail.Evidence["az"] != "us-east-1a" || !strings.Contains(fmt.Sprint(detail.Evidence["inventory_conflicts"]), "name") {
		t.Fatalf("%+v", detail.Evidence)
	}
	task := models.AssetNode{ARN: "arn:aws:ecs:us-east-1:111:task/c/t", AssetType: models.AssetECSTask, AccountID: "111", Region: "us-east-1"}
	def := models.AssetNode{ARN: "arn:aws:ecs:us-east-1:111:task-definition/app:1", AssetType: models.AssetECSTaskDefinition, AccountID: "111", Region: "us-east-1"}
	listed := Build([]models.AssetNode{task, def}, nil, nil, Filter{Category: "configuration"})
	if len(listed) != 1 || listed[0].RecordKind != "configuration" || listed[0].ResourceType != "ecs_task_definition" {
		t.Fatalf("%+v", listed)
	}
}

func TestCoverageDoesNotTreatPresenceAsCompletion(t *testing.T) {
	assets := make([]models.AssetNode, 12)
	for i := range assets {
		assets[i] = models.AssetNode{ARN: fmt.Sprintf("arn:aws:s3:::b-%d", i), AssetType: models.AssetS3Bucket, AccountID: "111", Region: "us-east-1"}
	}
	assets = append(assets, models.AssetNode{
		ARN: "arn:cloudrift:collection-status:s3:222::global", AssetType: "collection_status", AccountID: "222",
		Properties: map[string]any{"collector": "s3", "status": "succeeded", "scope": "global"},
	})
	summary := Summarize(models.ScanSnapshot{}, assets, nil, nil, Filter{AccountID: "111"})
	for _, card := range summary.Services {
		if card.Service == "s3" && (card.Count != 12 || card.Coverage != "UNKNOWN") {
			t.Fatalf("%+v", card)
		}
	}
	zero := Summarize(models.ScanSnapshot{}, []models.AssetNode{{
		ARN: "arn:cloudrift:collection-status:acm:111::global", AssetType: "collection_status", AccountID: "111",
		Properties: map[string]any{"collector": "acm", "status": "succeeded", "scope": "global"},
	}}, nil, nil, Filter{})
	regional := Summarize(models.ScanSnapshot{}, []models.AssetNode{
		{ARN: "arn:aws:eks:us-east-1:111:cluster/a", AssetType: models.AssetEKSCluster, AccountID: "111", Region: "us-east-1"},
		{ARN: "arn:cloudrift:collection-status:eks:111:us-east-1:regional", AssetType: "collection_status", AccountID: "111", Region: "us-east-1", Properties: map[string]any{"collector": "eks", "status": "succeeded", "scope": "regional"}},
		{ARN: "arn:cloudrift:workload-collection:::111:eu-west-1:eks", AssetType: "workload_collection_status", AccountID: "111", Region: "eu-west-1", Properties: map[string]any{"collector": "eks", "status": "failed"}},
	}, nil, nil, Filter{Region: "us-east-1"})
	for _, card := range zero.Services {
		if card.Service == "acm" && (card.Count != 0 || card.Coverage != "COLLECTED") {
			t.Fatalf("zero success %+v", card)
		}
	}
	for _, card := range regional.Services {
		if card.Service == "eks" && (card.Count != 1 || card.Coverage != "COLLECTED") {
			t.Fatalf("filtered coverage %+v", card)
		}
		if card.Service == "s3" && card.Coverage != "NOT_APPLICABLE" {
			t.Fatalf("global service under region filter %+v", card)
		}
	}
}

func TestPartialCoverageIsNotSuccessfulZero(t *testing.T) {
	assets := []models.AssetNode{{
		ARN: "arn:cloudrift:workload-collection:::111:us-east-1:ecs", AssetType: "workload_collection_status",
		AccountID: "111", Region: "us-east-1",
		Properties: map[string]any{"status": "partial", "collector": "ecs", "error": "AccessDenied"},
	}}
	summary := Summarize(models.ScanSnapshot{}, assets, nil, nil, Filter{})
	for _, card := range summary.Services {
		if card.Service == "ecs" {
			if card.Count != 0 || card.Coverage != "PARTIAL" || card.CoverageText == "0 resources discovered in the successfully collected scope." {
				t.Fatalf("%+v", card)
			}
		}
	}
}

func TestDetailInstanceProfileAndRedaction(t *testing.T) {
	instance := models.AssetNode{ARN: "arn:aws:ec2:us-east-1:111:instance/i-1", AssetType: models.AssetEC2Instance, AccountID: "111", Region: "us-east-1", Name: "i-1", Properties: map[string]any{"state": "running", "password": "nope", "name": "web"}}
	profile := models.AssetNode{ARN: "arn:aws:iam::111:instance-profile/p", AssetType: models.AssetInstanceProfile, AccountID: "111", Name: "p"}
	role := models.AssetNode{ARN: "arn:aws:iam::111:role/App", AssetType: models.AssetIAMRole, AccountID: "111", Name: "App"}
	rels := []models.Relationship{
		{SourceARN: instance.ARN, TargetARN: profile.ARN, RelType: models.RelEC2UsesInstanceProfile},
		{SourceARN: profile.ARN, TargetARN: role.ARN, RelType: models.RelInstanceProfileContains},
	}
	detail, ok := Detail("scan", instance.ARN, []models.AssetNode{instance, profile, role}, rels, []models.Finding{{ID: "f", AffectedARN: instance.ARN, Title: "edge", Severity: "low", Module: "orphaned_edge"}})
	if !ok || len(detail.IdentityLinks) != 1 || detail.IdentityLinks[0].RoleARN != role.ARN {
		t.Fatalf("%+v", detail)
	}
	if _, leaked := detail.Evidence["password"]; leaked || detail.Evidence["name"] != "web" {
		t.Fatalf("%+v", detail.Evidence)
	}
	if len(detail.Findings) != 1 {
		t.Fatal(detail.Findings)
	}
	if _, ok := Detail("scan", "arn:cloudrift:decision:1", []models.AssetNode{{ARN: "arn:cloudrift:decision:1", AssetType: models.AssetIAMAuthorizationDecision}}, nil, nil); ok {
		t.Fatal("evidence node returned as inventory")
	}
}

func TestSummaryScale(t *testing.T) {
	assets := make([]models.AssetNode, 4000)
	for i := range assets {
		assets[i] = models.AssetNode{ARN: fmt.Sprintf("arn:aws:s3:::b-%d", i), AssetType: models.AssetS3Bucket, AccountID: "111", Name: "b"}
	}
	start := time.Now()
	summary := Summarize(models.ScanSnapshot{}, assets, nil, nil, Filter{})
	elapsed := time.Since(start)
	if summary.TotalAssets != 4000 {
		t.Fatal(summary.TotalAssets)
	}
	t.Logf("summary_4000=%s", elapsed)
	if elapsed > 2*time.Second {
		t.Fatalf("summary too slow: %s", elapsed)
	}
}
