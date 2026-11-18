package models

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestFindingJSONShape(t *testing.T) {
	f := Finding{
		ID:           "abc123",
		Title:        "test",
		Severity:     SeverityHigh,
		Module:       ModuleOrphanedEdge,
		Claimability: ClaimDangling,
		AffectedARN:  "arn:aws:route53:::hostedzone/Z1/example.com",
		AccountID:    "123456789012",
		Hostname:     "app.example.com",
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, field := range []string{"\"id\"", "\"severity\"", "\"claimability\"", "\"affected_arn\""} {
		if !strings.Contains(s, field) {
			t.Fatalf("expected field %s in %s", field, s)
		}
	}
}

func TestSnapshotJSON(t *testing.T) {
	snap := ScanSnapshot{
		ScanID:    "scan-1",
		Timestamp: time.Now(),
		AccountIDs: []string{
			"1",
		},
	}
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, key := range []string{"embedding_provider", "embedding_model", "embedding_dimensions"} {
		if strings.Contains(s, key) {
			t.Fatalf("expected embedding keys omitted when unset, got %s", s)
		}
	}

	snapEmb := ScanSnapshot{
		ScanID:              "scan-2",
		Timestamp:           time.Unix(1, 0).UTC(),
		AccountIDs:          []string{"1"},
		EmbeddingProvider:   "openai",
		EmbeddingModel:      "text-embedding-3-small",
		EmbeddingDimensions: 384,
	}
	b2, err := json.Marshal(snapEmb)
	if err != nil {
		t.Fatal(err)
	}
	s2 := string(b2)
	for _, key := range []string{"\"embedding_provider\"", "\"embedding_model\"", "\"embedding_dimensions\""} {
		if !strings.Contains(s2, key) {
			t.Fatalf("expected %s in JSON: %s", key, s2)
		}
	}
}
