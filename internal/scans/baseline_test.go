package scans

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func put(t *testing.T, dir, id string, ts time.Time, accounts []string) {
	t.Helper()
	d := filepath.Join(dir, id)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	m, _ := json.Marshal(models.ScanSnapshot{ScanID: id, Timestamp: ts, AccountIDs: accounts})
	os.WriteFile(filepath.Join(d, "scan-metadata.json"), m, 0o644)
	os.WriteFile(filepath.Join(d, "findings.json"), []byte("[]"), 0o644)
}

func TestPreviousScanIsTheNewestEarlierScanOfTheSameAccounts(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	put(t, dir, "a1", base, []string{"1"})
	put(t, dir, "b1", base.Add(time.Hour), []string{"2"})
	put(t, dir, "a2", base.Add(2*time.Hour), []string{"1"})
	put(t, dir, "b2", base.Add(3*time.Hour), []string{"2"})
	put(t, dir, "ab", base.Add(4*time.Hour), []string{"2", "1"})
	if got := PreviousScanID(dir, "a2"); got != "a1" {
		t.Fatalf("a2 compares with a1, not the scan of account 2 between them: %q", got)
	}
	if got := PreviousScanID(dir, "b2"); got != "b1" {
		t.Fatalf("b2 compares with b1: %q", got)
	}
	if got := PreviousScanID(dir, "a1"); got != "" {
		t.Fatalf("the first scan of an account has no baseline: %q", got)
	}
	if got := PreviousScanID(dir, "ab"); got != "" {
		t.Fatalf("a different set of accounts is a different baseline: %q", got)
	}
}
