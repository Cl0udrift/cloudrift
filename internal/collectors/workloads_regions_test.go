package collectors

import (
	"context"
	"sync"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"

	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/inventory"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestCollectWorkloads_AccountScopedDiscovery(t *testing.T) {
	origDiscover := describeAccountRegions
	origClients := regionalWorkloadClients
	t.Cleanup(func() {
		describeAccountRegions = origDiscover
		regionalWorkloadClients = origClients
	})
	var mu sync.Mutex
	scanned := map[string][]string{}
	describeAccountRegions = func(ctx context.Context, account Account) RegionDiscoveryResult {
		switch account.ID {
		case "111111111111":
			return RegionDiscoveryResult{AccountID: account.ID, Partition: "aws", Status: "succeeded", Mode: "auto", Selected: []string{"us-west-2", "us-east-1"}, NotEnabled: []string{"af-south-1"}}
		case "222222222222":
			return RegionDiscoveryResult{AccountID: account.ID, Partition: "aws", Status: "succeeded", Mode: "auto", Selected: []string{"eu-west-1"}}
		default:
			return RegionDiscoveryResult{AccountID: account.ID, Partition: "aws", Status: "failed", Mode: "auto", Error: "access_denied"}
		}
	}
	regionalWorkloadClients = func(cfg awsv2.Config) WorkloadClients {
		mu.Lock()
		scanned[cfg.Region] = append(scanned[cfg.Region], cfg.Region)
		mu.Unlock()
		return WorkloadClients{EC2: fakeEC2{}, IAM: fakeProfiles{}, Lambda: fakeLambda{}, ECS: fakeECS{}, EKS: fakeEKS{quiet: true}}
	}
	cfg := config.Default()
	cfg.Scan.IAMPolicyInventory = true
	sess := awsv2.Config{}
	assets, _, err := CollectWorkloads(context.Background(), cfg, []Account{
		{ID: "111111111111", Session: &sess},
		{ID: "222222222222", Session: &sess},
		{ID: "333333333333", Session: &sess},
		{ID: "444444444444"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := scanned["af-south-1"]; ok {
		t.Fatal("disabled region was scanned")
	}
	if len(scanned["us-east-1"]) != 1 || len(scanned["us-west-2"]) != 1 || len(scanned["eu-west-1"]) != 1 || len(scanned) != 3 {
		t.Fatalf("scanned %#v", scanned)
	}
	cov := inventory.RegionCoverage(models.ScanSnapshot{RegionMode: "auto"}, assets, inventory.Filter{})
	if !cov.Recorded || len(cov.Accounts) != 3 {
		t.Fatalf("%+v", cov)
	}
	byID := map[string]int{}
	for _, account := range cov.Accounts {
		byID[account.AccountID] = account.Succeeded
		if account.AccountID == "333333333333" && (account.Discovery == "succeeded" || account.Regions[0].State != "REGION_DISCOVERY_FAILED") {
			t.Fatalf("failed discovery %+v", account)
		}
		if account.AccountID == "111111111111" && (account.Succeeded != 2 || account.Excluded != 1) {
			t.Fatalf("core %+v", account)
		}
	}
	if byID["222222222222"] != 1 {
		t.Fatal(byID)
	}
}

func TestCollectWorkloads_ExplicitAndCancel(t *testing.T) {
	origDiscover := describeAccountRegions
	origClients := regionalWorkloadClients
	t.Cleanup(func() {
		describeAccountRegions = origDiscover
		regionalWorkloadClients = origClients
	})
	describeAccountRegions = func(ctx context.Context, account Account) RegionDiscoveryResult {
		return RegionDiscoveryResult{AccountID: account.ID, Partition: "aws", Status: "succeeded", Mode: "auto", Selected: []string{"us-east-1", "us-west-2"}}
	}
	var regions []string
	regionalWorkloadClients = func(cfg awsv2.Config) WorkloadClients {
		regions = append(regions, cfg.Region)
		return WorkloadClients{EC2: fakeEC2{}, IAM: fakeProfiles{}, Lambda: fakeLambda{}, ECS: fakeECS{}, EKS: fakeEKS{quiet: true}}
	}
	cfg := config.Default()
	cfg.Scan.IAMPolicyInventory = true
	cfg.AWS.Regions = []string{"eu-west-1"}
	sess := awsv2.Config{}
	assets, _, err := CollectWorkloads(context.Background(), cfg, []Account{{ID: "111111111111", Session: &sess}})
	if err != nil || len(regions) != 1 || regions[0] != "eu-west-1" {
		t.Fatalf("explicit %v %v", regions, err)
	}
	for _, asset := range assets {
		if asset.Properties["region_mode"] == "auto" {
			t.Fatal("explicit scan discovered regions")
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg = config.Default()
	cfg.Scan.IAMPolicyInventory = true
	assets, _, err = CollectWorkloads(ctx, cfg, []Account{{ID: "111111111111", Session: &sess}})
	if err != nil {
		t.Fatal(err)
	}
	cancelled := false
	for _, asset := range assets {
		if asset.Properties["detail"] == "cancelled" {
			cancelled = true
		}
		if asset.Properties["status"] == "succeeded" && asset.Properties["collector"] == "ec2" {
			t.Fatal("cancelled scan recorded a regional success")
		}
	}
	if !cancelled {
		t.Fatal("cancellation was not recorded")
	}
}

func TestCollectRegionalWorkloads_ZeroResourcesAndPartial(t *testing.T) {
	assets, _, err := CollectRegionalWorkloads(context.Background(), "111111111111", "us-east-1", WorkloadClients{
		EC2: fakeEC2{}, IAM: fakeProfiles{}, Lambda: fakeLambda{}, ECS: fakeECS{}, EKS: fakeEKS{quiet: true},
	}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	succeeded := 0
	for _, asset := range assets {
		if asset.AssetType == "collection_status" && asset.Properties["status"] == "succeeded" {
			succeeded++
		}
		if asset.AssetType == models.AssetEC2Instance || asset.AssetType == models.AssetLambdaFunction {
			t.Fatalf("zero collection invented %s", asset.AssetType)
		}
	}
	if succeeded != 4 {
		t.Fatalf("expected four succeeded collectors, got %d", succeeded)
	}

	assets, _, err = CollectRegionalWorkloads(context.Background(), "111111111111", "us-west-2", WorkloadClients{
		EC2: fakeEC2{fail: true}, IAM: fakeProfiles{}, Lambda: fakeLambda{}, ECS: fakeECS{}, EKS: fakeEKS{quiet: true},
	}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	ec2Failed, lambdaOK := false, false
	for _, asset := range assets {
		if asset.Properties["collector"] == "ec2" && asset.Properties["status"] == "failed" {
			ec2Failed = true
		}
		if asset.Properties["collector"] == "lambda" && asset.Properties["status"] == "succeeded" {
			lambdaOK = true
		}
	}
	if !ec2Failed || !lambdaOK {
		t.Fatal("partial region dropped the successful collector")
	}
}
