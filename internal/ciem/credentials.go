package ciem

import (
	"time"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
)

const staleKeyDays = 90

// CredentialSummaryFor reads the credential report facts stored on a user node.
// It returns nil when the report was not collected for the user, so callers never
// show "no keys" for a user whose keys are simply unknown.
func CredentialSummaryFor(user models.AssetNode, now time.Time) *schema.CredentialSummary {
	if user.AssetType != models.AssetIAMUser || strProp(user, "credential_report") != "collected" {
		return nil
	}
	out := &schema.CredentialSummary{Keys: []schema.KeySummary{}, Findings: []string{}}
	out.Console, _ = user.Properties["console_enabled"].(bool)
	out.MFA, _ = user.Properties["mfa_active"].(bool)
	out.PasswordLastUsed = strProp(user, "password_last_used")
	if out.Console && !out.MFA {
		out.Findings = append(out.Findings, "Console access without MFA")
	}
	for _, raw := range keyMaps(user.Properties["access_keys"]) {
		key := schema.KeySummary{Slot: anyStr(raw["slot"]), LastRotated: anyStr(raw["last_rotated"]), LastUsed: anyStr(raw["last_used"]), LastService: anyStr(raw["last_service"])}
		key.Active, _ = raw["active"].(bool)
		if t, err := time.Parse(time.RFC3339, key.LastRotated); err == nil {
			days := int(now.Sub(t).Hours() / 24)
			key.AgeDays = &days
		}
		out.Keys = append(out.Keys, key)
		if !key.Active {
			continue
		}
		if key.AgeDays != nil && *key.AgeDays > staleKeyDays {
			out.Findings = append(out.Findings, "Active access key older than 90 days")
		}
		if t, err := time.Parse(time.RFC3339, key.LastUsed); err != nil {
			out.Findings = append(out.Findings, "Active access key that has never been used")
		} else if now.Sub(t).Hours()/24 > staleKeyDays {
			out.Findings = append(out.Findings, "Active access key unused for over 90 days")
		}
	}
	return out
}

func keyMaps(v any) []map[string]any {
	switch typed := v.(type) {
	case []map[string]any:
		return typed
	case []any: // after a JSON round trip through the scan store
		var out []map[string]any
		for _, item := range typed {
			if m, ok := item.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

func anyStr(v any) string {
	s, _ := v.(string)
	return s
}
