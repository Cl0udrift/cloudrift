package alerting

import (
	"strings"
	"testing"
	"time"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func idFinding(id, title, arn, cat string) models.Finding {
	return models.Finding{ID: id, Title: title, Severity: models.SeverityHigh, AccountID: "1", AffectedARN: arn, Evidence: map[string]any{"issue_category": cat}}
}

func ruleOf(t RuleType) AlertRule {
	return AlertRule{ID: "r", Name: "n", Type: t, Enabled: true, Channel: Channel{Type: ChannelSlackWebhook, SlackWebhookURL: "https://hooks.slack.com/services/x/y/z"}}
}

func TestDeltaRulesOnlyCountTheirOwnCategoryAndNameWhatIsNew(t *testing.T) {
	dir := t.TempDir()
	base := idFinding("a", "alice has no MFA", "arn:aws:iam::1:user/alice", "user_console_without_mfa")
	writeScanBundle(t, dir, "s1", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), []models.Finding{base})
	ev := NewEvaluator(dir, "http://x")
	res, _ := ev.Evaluate(ruleOf(RuleNewConsoleNoMFA), "s1")
	if res.Triggered || !strings.Contains(res.Context.Payload.Title, "no previous scan") {
		t.Fatalf("first scan must say there is no baseline: %q", res.Context.Payload.Title)
	}
	bob := idFinding("b", "bob has no MFA", "arn:aws:iam::1:user/bob", "user_console_without_mfa")
	key := idFinding("c", "carol old key", "arn:aws:iam::1:user/carol", "user_access_key_hygiene")
	writeScanBundle(t, dir, "s2", time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), []models.Finding{base, bob, key})
	res, _ = ev.Evaluate(ruleOf(RuleNewConsoleNoMFA), "s2")
	p := res.Context.Payload
	if !res.Triggered || res.Context.SignalCount != 1 || p.Title != "1 new console user without MFA" || len(p.Items) != 1 || !strings.Contains(p.Items[0].URL, "finding_id=b") {
		t.Fatalf("expected one named, linked item: %+v", p)
	}
	res, _ = ev.Evaluate(ruleOf(RuleNewKeyIssues), "s2")
	if !res.Triggered || res.Context.SignalCount != 1 {
		t.Fatal("key rule must see the key finding only")
	}
	writeScanBundle(t, dir, "s3", time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC), []models.Finding{base, bob, key})
	res, _ = ev.Evaluate(ruleOf(RuleNewConsoleNoMFA), "s3")
	if res.Triggered || res.Context.Payload.Title != "No new console users without MFA" || res.Context.Payload.Severity != SeverityInfo {
		t.Fatalf("a quiet run must say so: %+v", res.Context.Payload)
	}
}

func TestPublicBucketRule(t *testing.T) {
	dir := t.TempDir()
	writeScanBundle(t, dir, "s1", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), nil)
	b := models.Finding{ID: "p", Title: "S3 bucket policy exposes logs (public_read)", Severity: models.SeverityHigh, AccountID: "1", AffectedARN: "arn:aws:s3:::logs",
		Evidence: map[string]any{"resource_type": "s3_bucket", "is_public": true}}
	private := b
	private.ID, private.AffectedARN, private.Evidence = "q", "arn:aws:s3:::other", map[string]any{"resource_type": "s3_bucket", "is_public": false}
	writeScanBundle(t, dir, "s2", time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), []models.Finding{b, private})
	res, _ := NewEvaluator(dir, "http://x").Evaluate(ruleOf(RuleNewPublicBucket), "s2")
	if !res.Triggered || res.Context.SignalCount != 1 || res.Context.Payload.Severity != SeverityCritical {
		t.Fatalf("only the public bucket counts: %+v", res.Context.Payload)
	}
}

func TestScanDigestStaysQuietWhenNothingChanged(t *testing.T) {
	dir := t.TempDir()
	f := idFinding("a", "x", "arn:aws:iam::1:user/a", "user_console_without_mfa")
	writeScanBundle(t, dir, "s1", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), []models.Finding{f})
	writeScanBundle(t, dir, "s2", time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), []models.Finding{f})
	ev := NewEvaluator(dir, "http://x")
	if res, _ := ev.Evaluate(ruleOf(RuleScanCompletion), "s1"); !res.Triggered {
		t.Fatal("the first scan reports its totals")
	}
	if res, _ := ev.Evaluate(ruleOf(RuleScanCompletion), "s2"); res.Triggered {
		t.Fatal("no change must not alert")
	}
	g := idFinding("b", "y", "arn:aws:iam::1:user/b", "user_console_without_mfa")
	writeScanBundle(t, dir, "s3", time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC), []models.Finding{g})
	res, _ := ev.Evaluate(ruleOf(RuleScanCompletion), "s3")
	if !res.Triggered || !strings.Contains(res.Context.Payload.Summary, "1 new, 1 resolved") {
		t.Fatalf("expected new and resolved counts: %q", res.Context.Payload.Summary)
	}
}

func TestReclaimableCountsFindingsOnly(t *testing.T) {
	dir := t.TempDir()
	f := models.Finding{ID: "a", Title: "dangling", Severity: models.SeverityHigh, AccountID: "1", Claimability: models.ClaimReclaimable}
	writeScanBundle(t, dir, "s1", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), []models.Finding{f})
	r := ruleOf(RuleReclaimableThreshold)
	res, _ := NewEvaluator(dir, "http://x").Evaluate(r, "s1")
	if !res.Triggered || strings.Contains(res.Context.Payload.Summary, "$") {
		t.Fatalf("must trigger with no dollar wording: %q", res.Context.Payload.Summary)
	}
	r.Threshold.CountMin = 2
	if res, _ = NewEvaluator(dir, "http://x").Evaluate(r, "s1"); res.Triggered {
		t.Fatal("one finding is below a limit of two")
	}
}

func TestSlackMessageListsItemsAndEscapesMarkup(t *testing.T) {
	blocks := formatSlackBlocks(AlertPayload{Title: "t", Summary: "s", Items: []AlertItem{{Title: "<b>x</b> & y", Detail: "HIGH", URL: "http://x/f"}}})
	found := false
	for _, b := range blocks {
		if txt, ok := b["text"].(map[string]any); ok && strings.Contains(txt["text"].(string), "<http://x/f|&lt;b&gt;x&lt;/b&gt; &amp; y>") {
			found = true
		}
	}
	if !found {
		t.Fatalf("item line missing or unescaped: %v", blocks)
	}
}

func TestOrphanedEdgeRuleCountsReclaimableAndDanglingOnly(t *testing.T) {
	dir := t.TempDir()
	writeScanBundle(t, dir, "s1", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), nil)
	mk := func(id string, c models.Claimability) models.Finding {
		return models.Finding{ID: id, Title: id, Severity: models.SeverityHigh, Module: models.ModuleOrphanedEdge, Claimability: c, AccountID: "1", AffectedARN: "arn:aws:route53:::Z/" + id}
	}
	writeScanBundle(t, dir, "s2", time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
		[]models.Finding{mk("a", models.ClaimReclaimable), mk("b", models.ClaimDangling), mk("c", models.ClaimBroken)})
	res, _ := NewEvaluator(dir, "http://x").Evaluate(ruleOf(RuleNewOrphanedEdge), "s2")
	if !res.Triggered || res.Context.SignalCount != 2 || res.Context.Payload.Severity != SeverityCritical {
		t.Fatalf("a broken name is not a takeover risk: %d %s", res.Context.SignalCount, res.Context.Payload.Severity)
	}
}
