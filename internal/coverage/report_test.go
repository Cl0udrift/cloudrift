package coverage

import (
	"testing"

	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestRegistryIsConsistent(t *testing.T) {
	valid := map[string]bool{}
	for _, f := range config.Schema() {
		valid[f.Key] = true
	}
	ids := map[string]bool{}
	for _, m := range Modules() {
		if ids[m.ID] {
			t.Fatalf("duplicate id %s", m.ID)
		}
		ids[m.ID] = true
		if m.Name == "" || m.Summary == "" || m.Area == "" || m.Status == "" {
			t.Fatalf("%s is incomplete", m.ID)
		}
		if m.Status != StatusPlanned && len(m.Covers) == 0 {
			t.Fatalf("%s covers nothing", m.ID)
		}
		if len(m.Limitations) == 0 {
			t.Fatalf("%s lists no limitation; every module has one", m.ID)
		}
		for _, k := range m.ConfigKeys {
			if !valid[k] {
				t.Fatalf("%s links to unknown setting %s", m.ID, k)
			}
		}
	}
}

func TestBuildLiveState(t *testing.T) {
	cfg := config.Default()
	cfg.Scan.ResourcePolicies = true
	assets := []models.AssetNode{
		{AssetType: "collection_status", Properties: map[string]any{"collector": "ec2", "status": "succeeded"}},
		{AssetType: "collection_status", Properties: map[string]any{"collector": "lambda", "status": "partial"}},
		{AssetType: models.AssetSecret},
	}
	rep := Build(cfg, "s1", assets)
	by := map[string]Module{}
	for _, m := range rep.Modules {
		by[m.ID] = m
	}
	if by["inventory"].Live.State != "partial" {
		t.Fatalf("inventory %+v", by["inventory"].Live)
	}
	rp := by["resource-policies"].Live
	if rp.State != "data_present" || rp.Enabled == nil || !*rp.Enabled {
		t.Fatalf("resource policies %+v", rp)
	}
	if sa := by["service-access"].Live; sa.Enabled == nil || *sa.Enabled || sa.State != "unknown" {
		t.Fatalf("service access %+v", sa)
	}
	if rep.Catalog.Evaluated == 0 || len(rep.Techniques) < 10 || rep.Totals[StatusReady] == 0 {
		t.Fatalf("derived data missing: %+v", rep.Catalog)
	}
	if rep.Catalog.NotEvaluated == nil || rep.Catalog.EvaluatedActions == nil {
		t.Fatal("empty lists must encode as [] not null")
	}
	if none := Build(cfg, "", nil); none.Modules[0].Live.State != "not_recorded" {
		t.Fatalf("no scan state %+v", none.Modules[0].Live)
	}
}
