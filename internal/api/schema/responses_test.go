package schema

import (
	"encoding/json"
	"testing"
	"time"
)

func TestFindingsListResponseJSONShape(t *testing.T) {
	payload := FindingsListResponse{
		Items: []FindingListItem{
			{
				ID:                   "f1",
				Title:                "demo",
				Severity:             "high",
				Module:               "external_access",
				Claimability:         "unknown",
				AffectedARN:          "arn:aws:iam::111111111111:role/DemoRole",
				AccountID:            "111111111111",
				MonthlyDirectCostUSD: 1.23,
				MonthlyRiskCostUSD:   3.69,
			},
		},
		Pagination: PaginationMeta{Page: 1, PageSize: 50, TotalItems: 1, TotalPages: 1},
		Filters: FindingsAppliedFilter{
			Severity:  "high",
			Module:    "external_access",
			AccountID: "111111111111",
		},
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	for _, key := range []string{"items", "pagination", "filters"} {
		if _, ok := decoded[key]; !ok {
			t.Fatalf("missing top-level key %q", key)
		}
	}
}

func TestScanProgressEventJSONShape(t *testing.T) {
	event := ScanProgressEvent{
		EventType:         "scan_progress",
		ScanID:            "scan-20260418-100000",
		Stage:             "collectors",
		Message:           "Enumerating accounts",
		CompletedAccounts: 1,
		TotalAccounts:     5,
		Timestamp:         time.Date(2026, 4, 18, 10, 0, 0, 0, time.UTC),
	}

	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	for _, key := range []string{
		"event_type",
		"scan_id",
		"stage",
		"completed_accounts",
		"total_accounts",
		"timestamp",
	} {
		if _, ok := decoded[key]; !ok {
			t.Fatalf("missing event key %q", key)
		}
	}
}
