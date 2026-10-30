package config

import "testing"

func TestResolveRegionMode(t *testing.T) {
	ciem := Default()
	ciem.Scan.IAMPolicyInventory = true
	mode, regions, err := ResolveRegionMode(ciem)
	if err != nil || mode != RegionModeAuto || len(regions) != 0 {
		t.Fatalf("empty CIEM config: %s %v %v", mode, regions, err)
	}

	legacy := Default()
	mode, regions, err = ResolveRegionMode(legacy)
	if err != nil || mode != RegionModeLegacy || len(regions) != 1 || regions[0] != "us-east-1" {
		t.Fatalf("legacy: %s %v %v", mode, regions, err)
	}

	explicit := Default()
	explicit.AWS.Regions = []string{"eu-west-1", "us-east-1", "eu-west-1"}
	explicit.Scan.IAMPolicyInventory = true
	mode, regions, err = ResolveRegionMode(explicit)
	if err != nil || mode != RegionModeExplicit || len(regions) != 2 || regions[0] != "eu-west-1" || regions[1] != "us-east-1" {
		t.Fatalf("explicit override: %s %v %v", mode, regions, err)
	}

	conflict := Default()
	conflict.AWS.RegionDiscovery = RegionModeAuto
	conflict.AWS.Regions = []string{"us-east-1"}
	if _, _, err = ResolveRegionMode(conflict); err == nil {
		t.Fatal("auto plus an allowlist was accepted")
	}

	missing := Default()
	missing.AWS.RegionDiscovery = RegionModeExplicit
	if _, _, err = ResolveRegionMode(missing); err == nil {
		t.Fatal("explicit without regions was accepted")
	}

	forced := Default()
	forced.AWS.RegionDiscovery = RegionModeLegacy
	forced.Scan.IAMPolicyInventory = true
	mode, regions, err = ResolveRegionMode(forced)
	if err != nil || mode != RegionModeLegacy || regions[0] != "us-east-1" {
		t.Fatalf("explicit legacy: %s %v %v", mode, regions, err)
	}
}
