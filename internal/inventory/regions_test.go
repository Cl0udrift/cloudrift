package inventory

import (
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestRegionCoverage_OldScanAndFailedList(t *testing.T) {
	old := RegionCoverage(models.ScanSnapshot{}, nil, Filter{})
	if old.Recorded {
		t.Fatal("an old scan was marked recorded")
	}
	assets := []models.AssetNode{{
		ARN: "arn:cloudrift:collection-status:s3:111::global", AssetType: "collection_status", AccountID: "111111111111",
		Properties: map[string]any{"collector": "s3", "status": "failed", "scope": "global", "detail": "pagination"},
	}}
	summary := Summarize(models.ScanSnapshot{}, assets, nil, nil, Filter{})
	for _, card := range summary.Services {
		if card.Service == "s3" && card.Coverage == "COLLECTED" {
			t.Fatal("pagination failure was reported collected")
		}
	}
}

func TestRegionCoverage_AccountFilterKeepsFailedRegion(t *testing.T) {
	assets := []models.AssetNode{{
		ARN: "arn:cloudrift:collection-status:region_discovery:111::account", AssetType: "collection_status", AccountID: "111111111111", Name: "region_discovery",
		Properties: map[string]any{"collector": "region_discovery", "status": "succeeded", "scope": "account", "region_mode": "auto", "partition": "aws", "selected_regions": "us-east-1,us-west-2", "not_enabled": "af-south-1"},
	}}
	for _, region := range []string{"us-east-1", "us-west-2"} {
		for _, svc := range []string{"ec2", "lambda", "ecs", "eks"} {
			status := "succeeded"
			if region == "us-west-2" && svc == "lambda" {
				status = "failed"
			}
			assets = append(assets, models.AssetNode{
				ARN: "arn:cloudrift:collection-status:" + svc + ":111:" + region + ":regional", AssetType: "collection_status", AccountID: "111111111111", Region: region,
				Properties: map[string]any{"collector": svc, "status": status, "scope": "regional"},
			})
		}
	}
	cov := RegionCoverage(models.ScanSnapshot{RegionMode: "auto"}, assets, Filter{AccountID: "111111111111", Service: "lambda"})
	if len(cov.Accounts) != 1 || cov.Accounts[0].Partial != 1 || cov.Accounts[0].Excluded != 1 {
		t.Fatalf("%+v", cov.Accounts)
	}
	seenFailed := false
	for _, region := range cov.Accounts[0].Regions {
		if region.Region == "us-west-2" && region.State == "REGION_SCAN_PARTIAL" {
			seenFailed = true
		}
	}
	if !seenFailed {
		t.Fatal("service filter hid the partial region")
	}
}
