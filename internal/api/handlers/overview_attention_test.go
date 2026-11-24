package handlers

import (
	"strings"
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func idf(id, arn, name, cat string, sev models.Severity) models.Finding {
	return models.Finding{ID: id, Title: name + " " + cat, Severity: sev, Hostname: name, AffectedARN: arn, Evidence: map[string]any{"issue_category": cat}}
}

func TestAttentionGroupsFindingsByIdentityAndRanksTheWorst(t *testing.T) {
	fs := []models.Finding{
		idf("1", "arn:aws:iam::1:user/alice", "alice", "user_administrative_access", models.SeverityHigh),
		idf("2", "arn:aws:iam::1:user/alice", "alice", "user_console_without_mfa", models.SeverityHigh),
		idf("3", "arn:aws:iam::1:user/bob", "bob", "user_administrative_access", models.SeverityHigh),
		idf("4", "arn:aws:iam::1:user/carol", "carol", "user_console_without_mfa", models.SeverityMedium),
	}
	groups, headline := buildAttention(fs)
	if len(groups) != 2 {
		t.Fatalf("a medium finding is not for the headline: %d", len(groups))
	}
	if groups[0].Subject != "alice" || groups[0].Sentence != "alice has administrator access and signs in without MFA" || groups[0].IssueCount != 2 {
		t.Fatalf("alice has two problems and ranks first: %+v", groups[0])
	}
	if !strings.HasPrefix(headline, "2 identities or resources need attention") || !strings.Contains(headline, "alice has administrator access and signs in without MFA") {
		t.Fatalf("headline: %q", headline)
	}
	if g, h := buildAttention(nil); len(g) != 0 || h != "" {
		t.Fatal("nothing to say when nothing is high")
	}
}

func TestScanHealthSaysWhatCouldNotBeRead(t *testing.T) {
	meta := &models.ScanSnapshot{AccountIDs: []string{"1"}, CoverageComplete: true}
	assets := []models.AssetNode{
		status("ec2", "succeeded"), status("glue", "unsupported"), status("rds", "failed"), status("iam_credential_report", "partial"),
		{AssetType: models.AssetIAMRole, Region: "us-east-1"}, {AssetType: models.AssetIAMRole, Region: "eu-west-1"}, {AssetType: models.AssetIAMRole, Region: "global"},
	}
	h := buildHealth(meta, assets)
	if h.Complete || len(h.FailedCollectors) != 1 || h.FailedCollectors[0] != "rds" || len(h.PartialCollectors) != 1 || h.UnsupportedCount != 1 || h.RegionCount != 2 {
		t.Fatalf("health: %+v", h)
	}
	if h2 := buildHealth(meta, []models.AssetNode{status("ec2", "succeeded")}); !h2.Complete {
		t.Fatal("every collector succeeded and every account was reached")
	}
}
