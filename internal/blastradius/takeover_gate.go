package blastradius

import (
	"strings"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/iamauth"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// gateTakeover applies the state AWS checks before an access-key or login-profile call can succeed. An allowed
// policy decision is not enough: a user with two keys cannot get a third, a login profile cannot be created
// twice, and a missing one cannot be updated. The state comes from the credential report. When it was not
// collected the result is UNKNOWN, never an allow. Only an allowed decision is changed.
func gateTakeover(d schema.PermissionDecision, action string, target models.AssetNode, eval func(string) schema.PermissionDecision) schema.PermissionDecision {
	if d.Status != iamauth.StatusAllowed {
		return d
	}
	block := func(reason, why string) schema.PermissionDecision {
		d.Status, d.Reason = iamauth.StatusUnknown, reason
		d.Evidence = append(d.Evidence, why)
		d.Explanation = why
		return d
	}
	if report, _ := permStringProp(target.Properties, "credential_report"); report != "collected" {
		return block("credential_report_missing", "the credential report was not collected for this user, so the state AWS checks before this call cannot be confirmed")
	}
	console, _ := target.Properties["console_enabled"].(bool)
	switch strings.ToLower(action) {
	case "iam:createloginprofile":
		if console {
			return block("login_profile_exists", "the user already has a console password, so iam:CreateLoginProfile fails")
		}
	case "iam:updateloginprofile":
		if !console {
			return block("no_login_profile", "the user has no console password, so iam:UpdateLoginProfile fails")
		}
	case "iam:createaccesskey":
		if keysHeld(target) >= 2 {
			// A user holds at most two keys. The caller can still free a slot with iam:DeleteAccessKey.
			if del := eval("iam:DeleteAccessKey"); del.Status == iamauth.StatusAllowed {
				d.Evidence = append(d.Evidence, "the user holds two access keys; iam:DeleteAccessKey is also allowed, which frees a slot")
				return d
			}
			return block("access_key_limit_reached", "the user already holds two access keys, so iam:CreateAccessKey fails unless a key is deleted first, and iam:DeleteAccessKey is not allowed")
		}
	}
	return d
}

// keysHeld counts the access key slots in use, active or not.
func keysHeld(user models.AssetNode) int {
	n := 0
	switch keys := user.Properties["access_keys"].(type) {
	case []map[string]any:
		for _, k := range keys {
			if keyInUse(k) {
				n++
			}
		}
	case []any:
		for _, item := range keys {
			if k, ok := item.(map[string]any); ok && keyInUse(k) {
				n++
			}
		}
	}
	return n
}

func keyInUse(k map[string]any) bool {
	active, _ := k["active"].(bool)
	rotated, _ := k["last_rotated"].(string)
	return active || strings.TrimSpace(rotated) != ""
}
