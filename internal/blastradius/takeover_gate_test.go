package blastradius

import (
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
)

const gateBob = "arn:aws:iam::111111111111:user/bob"

// credUser is a target user with a collected credential report: console state and how many key slots are in use.
func credUser(arn string, console bool, keys int) models.AssetNode {
	n := controlled(models.AssetNode{ARN: arn, AssetType: models.AssetIAMUser, Name: "bob"})
	n.Properties["credential_report"] = "collected"
	n.Properties["console_enabled"] = console
	var slots []map[string]any
	for i := 0; i < 2; i++ {
		used := i < keys
		rotated := ""
		if used {
			rotated = "2026-01-01T00:00:00Z"
		}
		slots = append(slots, map[string]any{"slot": "access_key_" + string(rune('1'+i)), "active": used, "last_rotated": rotated})
	}
	n.Properties["access_keys"] = slots
	return n
}

// The caller may call the action on the target; whether the call can succeed depends on the target's credential state.
func TestTakeoverNeedsTheStateAWSChecks(t *testing.T) {
	noReport := controlled(models.AssetNode{ARN: gateBob, AssetType: models.AssetIAMUser, Name: "bob"})
	cases := []struct {
		name   string
		policy string
		bob    models.AssetNode
		want   bool
	}{
		{"create key, one key held", allowDoc("iam:CreateAccessKey", gateBob), credUser(gateBob, false, 1), true},
		{"create key, no keys held", allowDoc("iam:CreateAccessKey", gateBob), credUser(gateBob, false, 0), true},
		{"create key, two keys held, cannot delete", allowDoc("iam:CreateAccessKey", gateBob), credUser(gateBob, false, 2), false},
		{"create key, two keys held, can delete", `{"Statement":[{"Effect":"Allow","Action":["iam:CreateAccessKey","iam:DeleteAccessKey"],"Resource":"` + gateBob + `"}]}`, credUser(gateBob, false, 2), true},
		{"create key, two keys held, delete denied", `{"Statement":[{"Effect":"Allow","Action":["iam:CreateAccessKey","iam:DeleteAccessKey"],"Resource":"` + gateBob + `"},{"Effect":"Deny","Action":"iam:DeleteAccessKey","Resource":"*"}]}`, credUser(gateBob, false, 2), false},
		{"create login profile, none exists", allowDoc("iam:CreateLoginProfile", gateBob), credUser(gateBob, false, 0), true},
		{"create login profile, one exists", allowDoc("iam:CreateLoginProfile", gateBob), credUser(gateBob, true, 0), false},
		{"update login profile, one exists", allowDoc("iam:UpdateLoginProfile", gateBob), credUser(gateBob, true, 0), true},
		{"update login profile, none exists", allowDoc("iam:UpdateLoginProfile", gateBob), credUser(gateBob, false, 0), false},
		{"credential report not collected", allowDoc("iam:CreateAccessKey", gateBob), noReport, false},
	}
	for _, c := range cases {
		r := attackFrom([]models.AssetNode{ugUserNode(c.policy), c.bob})
		if got := hasEscalation(r, "USER_TAKEOVER", gateBob); got != c.want {
			t.Errorf("%s: takeover reported=%v, want %v", c.name, got, c.want)
		}
	}
}
