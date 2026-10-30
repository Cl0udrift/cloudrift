package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSchemaKeysResolveAndDefaultsValidate(t *testing.T) {
	def := Default()
	for _, f := range Schema() {
		if _, ok := lookup(def, f.Key); !ok {
			t.Fatalf("%s does not match a config field", f.Key)
		}
		if f.Label == "" || f.Description == "" || f.Group == "" || f.Apply == "" {
			t.Fatalf("%s is missing text", f.Key)
		}
		cp := Default()
		if err := Set(cp, f.Key, Get(def, f.Key)); err != nil && !(f.Kind == "list" || Get(def, f.Key) == "") {
			t.Fatalf("default for %s does not validate: %v", f.Key, err)
		}
	}
}

func TestSetValidation(t *testing.T) {
	cfg := Default()
	bad := map[string]any{
		"scan.http_timeout_seconds":        0.0,
		"scan.http_probe_concurrency":      1.5,
		"scan.resource_policies":           "yes",
		"aws.regions":                      []any{"not a region"},
		"trust.approved_external_accounts": []any{"123"},
		"neo4j.uri":                        "http://x",
		"neo4j.password_env":               "bad name",
		"synthesis.provider":               "other",
		"nope.key":                         "x",
	}
	for k, v := range bad {
		if err := Set(cfg, k, v); err == nil {
			t.Errorf("%s accepted %v", k, v)
		}
	}
	if err := Set(cfg, "aws.regions", []any{"us-east-1", " eu-west-2 "}); err != nil || len(cfg.AWS.Regions) != 2 || cfg.AWS.Regions[1] != "eu-west-2" {
		t.Fatalf("regions %v %v", cfg.AWS.Regions, err)
	}
	cfg.AWS.RegionDiscovery = "auto"
	if ValidateCross(cfg) == nil {
		t.Fatal("regions with discovery auto passed")
	}
}

func TestSaveKeepsSecretsBacksUpAndRoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cloudrift.toml")
	if err := os.WriteFile(path, []byte("[neo4j]\npassword = \"keep-me\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Set(cfg, "scan.resource_policies", true); err != nil {
		t.Fatal(err)
	}
	if err := Set(cfg, "trust.approved_external_accounts", []any{"123456789012"}); err != nil {
		t.Fatal(err)
	}
	backup, err := Save(path, cfg)
	if err != nil || backup == "" {
		t.Fatalf("backup=%q err=%v", backup, err)
	}
	if old, _ := os.ReadFile(backup); string(old) != "[neo4j]\npassword = \"keep-me\"\n" {
		t.Fatalf("backup content %q", old)
	}
	got, err := Load(path)
	if err != nil || !got.Scan.ResourcePolicies || got.Neo4j.Password != "keep-me" || len(got.Trust.ApprovedExternalAccounts) != 1 {
		t.Fatalf("round trip %+v err=%v", got, err)
	}
	if b, _ := os.ReadFile(path); strings.Contains(string(b), "http_timeout_seconds") {
		t.Fatalf("defaults were written: %s", b)
	}
	if err := Set(got, "scan.resource_policies", false); err != nil {
		t.Fatal(err)
	}
	if _, err := Save(path, got); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); strings.Contains(string(b), "resource_policies") {
		t.Fatalf("a value set back to default stayed in the file: %s", b)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode())
	}
	for _, s := range Secrets(got) {
		if s.Key == "neo4j.password" && s.State != "set" {
			t.Fatal("secret state wrong")
		}
	}
}
