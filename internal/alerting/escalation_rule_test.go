package alerting

import (
	"testing"
	"time"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func escalation(id, title, arn string, sev models.Severity) models.Finding {
	return models.Finding{ID: id, Title: title, Severity: sev, AccountID: "1", AffectedARN: arn, Evidence: map[string]any{"issue_category": "privilege_escalation"}}
}

func escalationRule() AlertRule {
	return AlertRule{ID: "r", Name: "esc", Type: RuleNewEscalationPaths, Enabled: true,
		Channel: Channel{Type: ChannelSlackWebhook, SlackWebhookURL: "https://hooks.slack.com/services/x/y/z"}}
}

func TestNewEscalationPathsRule(t *testing.T) {
	dir := t.TempDir()
	old := escalation("a", "alice can reach admin through role X", "arn:aws:iam::1:user/alice", models.SeverityHigh)
	writeScanBundle(t, dir, "s1", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), []models.Finding{old})
	ev := NewEvaluator(dir, "http://127.0.0.1:8080")

	if res, err := ev.Evaluate(escalationRule(), "s1"); err != nil || res.Triggered {
		t.Fatalf("a first scan has no baseline and must not trigger: %+v %v", res.Triggered, err)
	}

	fresh := escalation("b", "bob can reach admin through role Y", "arn:aws:iam::1:user/bob", models.SeverityMedium)
	unrelated := models.Finding{ID: "c", Title: "console without MFA", Severity: models.SeverityHigh, AccountID: "1", AffectedARN: "arn:aws:iam::1:user/c", Evidence: map[string]any{"issue_category": "user_console_without_mfa"}}
	writeScanBundle(t, dir, "s2", time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), []models.Finding{old, fresh, unrelated})
	res, err := ev.Evaluate(escalationRule(), "s2")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Triggered || res.Context.SignalCount != 1 {
		t.Fatalf("one new escalation path must trigger once, and a new non-escalation finding must not count: %+v", res.Context.SignalCount)
	}
	if res.Context.Payload.Severity != SeverityWarning {
		t.Fatalf("a Medium path is a warning, got %s", res.Context.Payload.Severity)
	}

	high := escalation("d", "dave can reach admin through role Z", "arn:aws:iam::1:user/dave", models.SeverityHigh)
	writeScanBundle(t, dir, "s3", time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC), []models.Finding{old, fresh, high})
	res, _ = ev.Evaluate(escalationRule(), "s3")
	if !res.Triggered || res.Context.SignalCount != 1 || res.Context.Payload.Severity != SeverityCritical {
		t.Fatalf("only the path new since s2 counts, and a High one escalates the alert: %d %s", res.Context.SignalCount, res.Context.Payload.Severity)
	}

	writeScanBundle(t, dir, "s4", time.Date(2026, 1, 4, 0, 0, 0, 0, time.UTC), []models.Finding{old, fresh, high})
	if res, _ = ev.Evaluate(escalationRule(), "s4"); res.Triggered {
		t.Fatal("an unchanged set of paths must not alert again")
	}
}

func TestEscalationRuleIsAnOfferedAndValidType(t *testing.T) {
	found := false
	for _, ty := range (&Service{}).SupportedTypes() {
		if ty.Type == RuleNewEscalationPaths {
			found = true
		}
	}
	if !found {
		t.Fatal("the catalog must offer the escalation rule")
	}
	if err := validateRule(escalationRule()); err != nil {
		t.Fatalf("the rule must validate: %v", err)
	}
}
