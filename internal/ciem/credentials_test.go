package ciem

import (
	"testing"
	"time"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestKeyIssuesDoNotCountConsoleWithoutMFA(t *testing.T) {
	now := time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC)
	user := models.AssetNode{ARN: "arn:aws:iam::1:user/u", AssetType: models.AssetIAMUser, Properties: map[string]any{
		"credential_report": "collected", "console_enabled": true, "mfa_active": false,
		"access_keys": []map[string]any{{"slot": "access_key_1", "active": false}, {"slot": "access_key_2", "active": false}},
	}}
	c := CredentialSummaryFor(user, now)
	if c == nil || len(c.Findings) != 1 || c.KeyIssues != 0 {
		t.Fatalf("one finding (no MFA) and no key issue when both keys are inactive: %+v", c)
	}
	user.Properties["access_keys"] = []map[string]any{{"slot": "access_key_1", "active": true, "last_rotated": "2026-01-01T00:00:00Z"}}
	if c := CredentialSummaryFor(user, now); c.KeyIssues != 2 { // old, and never used
		t.Fatalf("an old key that was never used is two key issues: %+v", c)
	}
}
