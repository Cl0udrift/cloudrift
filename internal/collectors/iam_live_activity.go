package collectors

import (
	"context"
	"fmt"
	"strings"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// IAMLiveActivityAPI reads, at call time, what the credential report only shows as of its generation time: when an
// access key was last used and when a console user last signed in.
type IAMLiveActivityAPI interface {
	ListAccessKeys(ctx context.Context, params *iam.ListAccessKeysInput, optFns ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	GetAccessKeyLastUsed(ctx context.Context, params *iam.GetAccessKeyLastUsedInput, optFns ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error)
	GetUser(ctx context.Context, params *iam.GetUserInput, optFns ...func(*iam.Options)) (*iam.GetUserOutput, error)
}

type liveKeyActivityKey struct{}

// WithLiveKeyActivity marks the context so the IAM collector refreshes last-used data live. It is a context value
// because the collector's signature is shared with its tests and the flag is read once.
func WithLiveKeyActivity(ctx context.Context, on bool, maxCalls int) context.Context {
	if !on {
		return ctx
	}
	if maxCalls <= 0 {
		maxCalls = 400
	}
	return context.WithValue(ctx, liveKeyActivityKey{}, maxCalls)
}

func liveKeyBudget(ctx context.Context) int {
	n, _ := ctx.Value(liveKeyActivityKey{}).(int)
	return n
}

// refreshLiveActivity replaces the credential report's last-used values with IAM's current ones where they are newer.
// It never lowers a value: the report and the live call can disagree by the lag in either, and the later date wins.
// It stops at maxCalls and returns how many users it could not check; a denied call stops it with an error, and the
// report's values stay.
func refreshLiveActivity(ctx context.Context, api IAMLiveActivityAPI, users []models.AssetNode, maxCalls int, now time.Time) (skipped int, err error) {
	calls := 0
	for i := range users {
		props := users[i].Properties
		if users[i].AssetType != models.AssetIAMUser || props == nil || props["credential_report"] != "collected" {
			continue
		}
		name := users[i].Name
		keys, _ := props["access_keys"].([]map[string]any)
		hasActive := false
		for _, k := range keys {
			if active, _ := k["active"].(bool); active {
				hasActive = true
			}
		}
		console, _ := props["console_enabled"].(bool)
		need := 0
		if console {
			need++
		}
		if hasActive {
			need++
			for _, k := range keys {
				if active, _ := k["active"].(bool); active {
					need++
				}
			}
		}
		if need == 0 {
			continue
		}
		if calls+need > maxCalls {
			skipped++
			continue
		}
		if console {
			calls++
			out, gerr := api.GetUser(ctx, &iam.GetUserInput{UserName: awsv2.String(name)})
			if gerr != nil {
				return skipped, gerr
			}
			if out.User != nil && out.User.PasswordLastUsed != nil {
				if t := out.User.PasswordLastUsed.UTC().Format(time.RFC3339); t > fmt.Sprint(props["password_last_used"]) {
					props["password_last_used"] = t
				}
			}
		}
		if hasActive {
			calls++
			list, lerr := api.ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: awsv2.String(name)})
			if lerr != nil {
				return skipped, lerr
			}
			for _, k := range keys {
				active, _ := k["active"].(bool)
				if !active {
					continue
				}
				id := matchKeyID(k, list, keys)
				if id == "" {
					continue
				}
				calls++
				used, uerr := api.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{AccessKeyId: awsv2.String(id)})
				if uerr != nil {
					return skipped, uerr
				}
				if used.AccessKeyLastUsed != nil && used.AccessKeyLastUsed.LastUsedDate != nil {
					live := used.AccessKeyLastUsed.LastUsedDate.UTC().Format(time.RFC3339)
					if current, _ := k["last_used"].(string); live > current {
						k["last_used"] = live
						if svc := awsv2.ToString(used.AccessKeyLastUsed.ServiceName); svc != "" {
							k["last_service"] = svc
						}
						k["last_used_source"] = "live"
					}
				}
			}
		}
		props["access_keys"] = keys
		props["live_activity_checked_at"] = now.UTC().Format(time.RFC3339)
	}
	return skipped, nil
}

// matchKeyID finds the access key id for a report slot. The report names slots, not ids, so a key is matched by its
// creation time (the report's last-rotated date); with one active key in the report and one in IAM they are the same.
func matchKeyID(slot map[string]any, list *iam.ListAccessKeysOutput, all []map[string]any) string {
	rotated, _ := slot["last_rotated"].(string)
	var active []string
	for _, m := range list.AccessKeyMetadata {
		if m.Status != "Active" {
			continue
		}
		id := awsv2.ToString(m.AccessKeyId)
		active = append(active, id)
		if m.CreateDate != nil && rotated != "" && strings.HasPrefix(m.CreateDate.UTC().Format(time.RFC3339), rotated[:min(len(rotated), 19)]) {
			return id
		}
	}
	activeSlots := 0
	for _, k := range all {
		if a, _ := k["active"].(bool); a {
			activeSlots++
		}
	}
	if len(active) == 1 && activeSlots == 1 {
		return active[0]
	}
	return ""
}
