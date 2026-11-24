package handlers

import (
	"strings"
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func spendAsset(acct string, monthly float64) models.AssetNode {
	return models.AssetNode{AssetType: models.AssetAccountSpend, AccountID: acct, Properties: map[string]any{
		"monthly_usd": monthly, "period_start": "2026-10-01", "source": "AWS Cost Explorer, October 2026",
		"top_services": []any{map[string]any{"service": "Amazon EC2", "usd": monthly * 0.7}},
	}}
}

func adminFinding(id, acct, name string) models.Finding {
	return models.Finding{ID: id, Severity: models.SeverityHigh, AccountID: acct, Hostname: name, AffectedARN: "arn:user/" + name, Evidence: map[string]any{"issue_category": "user_administrative_access"}}
}

func TestSpendInReachCountsEachAccountOnceNotOncePerAdministrator(t *testing.T) {
	f := []models.Finding{adminFinding("1", "111", "alice"), adminFinding("2", "111", "bob"), adminFinding("3", "222", "carol"),
		{ID: "4", Severity: models.SeverityHigh, AccountID: "333", Evidence: map[string]any{"issue_category": "user_console_without_mfa"}}}
	r := buildSpendInReach(f, []models.AssetNode{spendAsset("111", 1000), spendAsset("222", 500), spendAsset("333", 9999)})
	if !r.Applicable || !r.Available || r.Monthly != 1500 || len(r.Accounts) != 2 || len(r.Subjects) != 3 {
		t.Fatalf("two administrators in one account share its spend; a non-administrator reaches nothing account-wide: %+v", r)
	}
	if r.Accounts[0].TopServices[0].Service != "Amazon EC2" {
		t.Fatalf("top services come through: %+v", r.Accounts[0])
	}
}

func TestSpendInReachSaysWhenThereIsNoBilling(t *testing.T) {
	r := buildSpendInReach([]models.Finding{adminFinding("1", "111", "alice")}, nil)
	if !r.Applicable || r.Available || r.Reason == "" || r.Monthly != 0 {
		t.Fatalf("an administrator with no billing data says how to get it: %+v", r)
	}
	failed := models.AssetNode{AssetType: "collection_status", Properties: map[string]any{"collector": "cost_explorer", "status": "failed", "detail": "Cost Explorer rejected the credentials."}}
	if r := buildSpendInReach([]models.Finding{adminFinding("1", "111", "alice")}, []models.AssetNode{failed}); r.Available || !strings.Contains(r.Reason, "could not be read") || !strings.Contains(r.Reason, "rejected the credentials") {
		t.Fatalf("a failed billing read is said, with its cause: %+v", r)
	}
	if none := buildSpendInReach([]models.Finding{{Severity: models.SeverityHigh, Evidence: map[string]any{}}}, nil); none.Applicable {
		t.Fatal("no administrator-level identity, nothing to show")
	}
}
