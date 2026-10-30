package main

import (
	"testing"
	"time"

	"github.com/Zero0x00/cloudrift/internal/inventory"
	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/scans"
)

func TestRegionCoverageScenario(t *testing.T) {
	dir := t.TempDir()
	if _, err := generateDemoScanWithOptions(dir, time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC), "regions-coverage", demoOptions{Scenario: "regions-coverage", Profile: "legacy", Seed: 1}); err != nil {
		t.Fatal(err)
	}
	meta, _, err := scans.LoadScanArtifacts(dir, "regions-coverage")
	if err != nil {
		t.Fatal(err)
	}
	assets, err := scans.LoadAssets(dir, "regions-coverage")
	if err != nil {
		t.Fatal(err)
	}
	cov := inventory.RegionCoverage(*meta, assets, inventory.Filter{})
	if !cov.Recorded || len(cov.Accounts) != 2 {
		t.Fatalf("%+v", cov)
	}
	var coreSucceeded, corePartial, dataFailed bool
	for _, account := range cov.Accounts {
		switch account.AccountID {
		case "111111111111":
			coreSucceeded = account.Succeeded == 1
			corePartial = account.Partial == 1 && account.Excluded == 1
		case "222222222222":
			dataFailed = account.Discovery == "failed" && account.Regions[0].State == "REGION_DISCOVERY_FAILED"
		}
	}
	if !coreSucceeded || !corePartial || !dataFailed {
		t.Fatalf("%+v", cov.Accounts)
	}
	old := inventory.RegionCoverage(models.ScanSnapshot{}, nil, inventory.Filter{})
	if old.Recorded || old.Note == "" {
		t.Fatalf("old scan looked complete: %+v", old)
	}
}
