package collectors

import (
	"context"
	"sort"
	"sync"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// roleActivityConcurrency bounds parallel per-role GetRole calls. An account can hold
// thousands of IAM roles; fetching RoleLastUsed one role at a time made activity the
// slowest stage on large accounts.
const roleActivityConcurrency = 32

type RoleActivity struct {
	RoleARN       string     `json:"role_arn"`
	RoleName      string     `json:"role_name"`
	AccountID     string     `json:"account_id"`
	LastUsedAt    *time.Time `json:"last_used_at,omitempty"`
	DaysSinceUsed int        `json:"days_since_used"`
	// LastUsedRegion is the Region of the last use reported by IAM, when present.
	LastUsedRegion string `json:"last_used_region,omitempty"`
	// Status says what IAM reported. Never infer "unused" from a missing record.
	Status string `json:"status,omitempty"`
}

// Role activity states recorded on role assets as role_last_used_status.
const (
	ActivityUsed            = "used"
	ActivityNotUsedInWindow = "not_used_in_tracking_window" // IAM returned RoleLastUsed with no date
	ActivityNotReported     = "not_reported"                // IAM returned no RoleLastUsed field
	ActivityNotCollected    = "not_collected"               // GetRole did not succeed for this role
)

// StampRoleActivity records last-used evidence on role assets so it persists in the scan.
// A role with no activity record is marked not_collected, never "unused". Note that
// IAM only tracks roles for a bounded window (about 400 days), and last-used covers
// the role as a whole, not individual permissions.
func StampRoleActivity(assets []models.AssetNode, rows []RoleActivity) {
	byARN := IndexActivityByRoleARN(rows)
	for i := range assets {
		if assets[i].AssetType != models.AssetIAMRole {
			continue
		}
		if assets[i].Properties == nil {
			assets[i].Properties = map[string]any{}
		}
		row, ok := byARN[assets[i].ARN]
		if !ok {
			assets[i].Properties["role_last_used_status"] = ActivityNotCollected
			continue
		}
		status := row.Status
		if status == "" { // records from older collectors
			status = ActivityNotReported
			if row.LastUsedAt != nil {
				status = ActivityUsed
			}
		}
		assets[i].Properties["role_last_used_status"] = status
		if row.LastUsedAt != nil {
			assets[i].Properties["role_last_used"] = row.LastUsedAt.UTC().Format(time.RFC3339)
			assets[i].Properties["role_days_since_used"] = row.DaysSinceUsed
		}
		if row.LastUsedRegion != "" {
			assets[i].Properties["role_last_used_region"] = row.LastUsedRegion
		}
	}
}

type IAMActivityAPI interface {
	ListRoles(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error)
	GetRole(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error)
}

var newIAMActivityClient = func(cfg awsv2.Config) IAMActivityAPI {
	return iam.NewFromConfig(cfg)
}

var activityNowUTC = func() time.Time {
	return time.Now().UTC()
}

func CollectActivity(ctx context.Context, accounts []Account) ([]RoleActivity, error) {
	return CollectActivityWithConfig(ctx, config.Default(), accounts)
}

func CollectActivityWithConfig(ctx context.Context, cfg *config.Config, accounts []Account) ([]RoleActivity, error) {
	sem := make(chan struct{}, max(1, cfg.Scan.RoleAssumptionConcurrency))
	// Shared across accounts so total parallel GetRole calls stay bounded.
	roleSem := make(chan struct{}, roleActivityConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error

	var all []RoleActivity
	for _, account := range accounts {
		account := account
		if account.Session == nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			local, err := collectActivityFromClient(ctx, account.ID, newIAMActivityClient(*account.Session), roleSem)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}

			mu.Lock()
			all = append(all, local...)
			mu.Unlock()
		}()
	}
	wg.Wait()

	warnPartial(ctx, "activity", firstErr)

	sort.Slice(all, func(i, j int) bool {
		return all[i].RoleARN < all[j].RoleARN
	})
	return all, nil
}

func collectActivityFromClient(ctx context.Context, accountID string, client IAMActivityAPI, roleSem chan struct{}) ([]RoleActivity, error) {
	now := activityNowUTC().Truncate(24 * time.Hour)

	// Paginate the (cheap) role listing first, then fan out the expensive per-role
	// GetRole calls concurrently. Listing errors are fatal for the account (nothing to
	// work with); a single role's GetRole failure is skipped, not fatal, so one throttled
	// or access-denied role does not discard the whole account's activity.
	var roles []iamtypes.Role
	var marker *string
	for {
		listOut, err := client.ListRoles(ctx, &iam.ListRolesInput{Marker: marker})
		if err != nil {
			return nil, err
		}
		roles = append(roles, listOut.Roles...)
		if !listOut.IsTruncated || listOut.Marker == nil {
			break
		}
		marker = listOut.Marker
	}

	var out []RoleActivity
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, role := range roles {
		role := role
		wg.Add(1)
		go func() {
			defer wg.Done()
			roleSem <- struct{}{}
			defer func() { <-roleSem }()

			roleName := awsv2.ToString(role.RoleName)
			getOut, err := client.GetRole(ctx, &iam.GetRoleInput{RoleName: awsv2.String(roleName)})
			if err != nil {
				return
			}

			roleARN := awsv2.ToString(role.Arn)
			if getOut.Role != nil && getOut.Role.Arn != nil {
				roleARN = awsv2.ToString(getOut.Role.Arn)
			}

			activity := RoleActivity{
				RoleARN:       roleARN,
				RoleName:      roleName,
				AccountID:     accountID,
				DaysSinceUsed: -1,
			}

			switch {
			case getOut.Role == nil || getOut.Role.RoleLastUsed == nil:
				activity.Status = ActivityNotReported
			case getOut.Role.RoleLastUsed.LastUsedDate == nil:
				activity.Status = ActivityNotUsedInWindow
			default:
				activity.Status = ActivityUsed
			}
			if getOut.Role != nil && getOut.Role.RoleLastUsed != nil {
				activity.LastUsedRegion = awsv2.ToString(getOut.Role.RoleLastUsed.Region)
			}
			if getOut.Role != nil && getOut.Role.RoleLastUsed != nil && getOut.Role.RoleLastUsed.LastUsedDate != nil {
				lastUsed := getOut.Role.RoleLastUsed.LastUsedDate.UTC()
				lastUsedDay := lastUsed.Truncate(24 * time.Hour)
				days := int(now.Sub(lastUsedDay).Hours() / 24)
				if days < 0 {
					days = 0
				}
				activity.LastUsedAt = &lastUsed
				activity.DaysSinceUsed = days
			}

			mu.Lock()
			out = append(out, activity)
			mu.Unlock()
		}()
	}
	wg.Wait()

	sort.Slice(out, func(i, j int) bool {
		return out[i].RoleARN < out[j].RoleARN
	})
	return out, nil
}

func IndexActivityByRoleARN(rows []RoleActivity) map[string]RoleActivity {
	index := make(map[string]RoleActivity, len(rows))
	for _, row := range rows {
		index[row.RoleARN] = row
	}
	return index
}

func setActivityNow(now time.Time) func() {
	prev := activityNowUTC
	activityNowUTC = func() time.Time { return now.UTC() }
	return func() {
		activityNowUTC = prev
	}
}

