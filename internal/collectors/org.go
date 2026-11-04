package collectors

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"

	"github.com/Zero0x00/cloudrift/internal/aws"
	"github.com/Zero0x00/cloudrift/internal/config"
)

// Coverage records which org accounts a scan actually reached. It is the trust signal
// for findings: a reclaimable verdict is only safe when coverage is complete, because a
// bucket "missing" from scanned accounts could still be owned by an account we skipped.
type Coverage struct {
	Discovered int               `json:"discovered"`       // accounts returned by Organizations
	Scanned    []string          `json:"scanned"`          // account IDs successfully assumed
	Failed     map[string]string `json:"failed,omitempty"` // account ID -> assume error
	// OrgPolicyDiscovery is set only for a CIEM scan. Empty means the legacy
	// scan did not attempt organization policy collection.
	OrgPolicyDiscovery string `json:"org_policy_discovery,omitempty"`
	CIEMCollection     string `json:"ciem_collection,omitempty"`
	// OrgMembershipKnown is true only after Organizations ListAccounts succeeded.
	// KnownOrgAccountIDs includes members that could not be assumed.
	OrgMembershipKnown bool     `json:"org_membership_known,omitempty"`
	KnownOrgAccountIDs []string `json:"known_org_account_ids,omitempty"`
	// RegionMode is auto, explicit, or legacy_default. legacy_default is the
	// historical us-east-1 workload scope, not full enabled-Region coverage.
	RegionMode string `json:"region_mode,omitempty"`
	// ScanMode is the mode that actually ran: organization or account. ScanModeNote says why when
	// it differs from what was asked, for example an auto scan on an account outside any organization.
	ScanMode     string `json:"scan_mode,omitempty"`
	ScanModeNote string `json:"scan_mode_note,omitempty"`
}

// Complete reports whether every discovered account was successfully assumed.
func (c Coverage) Complete() bool { return len(c.Failed) == 0 }

// diagKey is the context key carrying an optional diagnostics sink.
type diagKey struct{}

// DiagFunc receives collector diagnostics (partial-failure details). The pipeline installs
// one so these surface in scan progress and the dashboard, not only in server logs.
type DiagFunc func(collector, message string)

// WithDiagnostics returns a context carrying a diagnostics sink for collectors to report to.
func WithDiagnostics(ctx context.Context, fn DiagFunc) context.Context {
	if fn == nil {
		return ctx
	}
	return context.WithValue(ctx, diagKey{}, fn)
}

func reportDiag(ctx context.Context, collector, message string) {
	if fn, ok := ctx.Value(diagKey{}).(DiagFunc); ok && fn != nil {
		fn(collector, message)
	}
}

// warnPartial logs (without aborting) when a collector produced partial results because
// some per-account API calls failed. Collectors stay resilient: one account's missing
// permission or throttle must not discard every other account's findings. The error is
// also forwarded to the diagnostics sink (if any) so operators can see the real cause
// (e.g. AccessDenied) in the dashboard.
func warnPartial(ctx context.Context, collector string, err error) {
	if err != nil {
		slog.Warn("collector produced partial results", "collector", collector, "error", err)
		reportDiag(ctx, collector, err.Error())
	}
}

type Account struct {
	ID      string
	Name    string
	OUPath  string
	Team    string
	Owner   string
	Contact string
	Session *awsv2.Config
}

type OrganizationsAPI interface {
	ListAccounts(ctx context.Context, params *organizations.ListAccountsInput, optFns ...func(*organizations.Options)) (*organizations.ListAccountsOutput, error)
	ListTagsForResource(ctx context.Context, params *organizations.ListTagsForResourceInput, optFns ...func(*organizations.Options)) (*organizations.ListTagsForResourceOutput, error)
	ListParents(ctx context.Context, params *organizations.ListParentsInput, optFns ...func(*organizations.Options)) (*organizations.ListParentsOutput, error)
	DescribeOrganizationalUnit(ctx context.Context, params *organizations.DescribeOrganizationalUnitInput, optFns ...func(*organizations.Options)) (*organizations.DescribeOrganizationalUnitOutput, error)
}

func CollectAccounts(ctx context.Context, cfg *config.Config, orgAPI OrganizationsAPI, sm *aws.SessionManager) ([]Account, Coverage, error) {
	var accounts []types.Account
	p := organizations.NewListAccountsPaginator(orgAPI, &organizations.ListAccountsInput{})
	for p.HasMorePages() {
		out, err := p.NextPage(ctx)
		if err != nil {
			// Listing the org itself is fatal — without it there is nothing to scan.
			return nil, Coverage{}, err
		}
		accounts = append(accounts, out.Accounts...)
	}

	out := make([]Account, len(accounts))
	failed := make(map[string]string)
	sem := make(chan struct{}, max(1, cfg.Scan.RoleAssumptionConcurrency))
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i, a := range accounts {
		i, a := i, a
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			accID := awsv2.ToString(a.Id)
			session, err := sm.AssumeAccount(ctx, accID)
			if err != nil {
				// Resilient: an account we cannot assume (closed, missing audit role, SCP
				// denial) is recorded and skipped, never aborting the whole org scan.
				mu.Lock()
				failed[accID] = err.Error()
				mu.Unlock()
				return
			}

			out[i] = Account{
				ID:      accID,
				Name:    awsv2.ToString(a.Name),
				OUPath:  buildOUPath(ctx, orgAPI, accID),
				Team:    tagValue(ctx, orgAPI, accID, "Team"),
				Owner:   tagValue(ctx, orgAPI, accID, "Owner"),
				Contact: tagValue(ctx, orgAPI, accID, "Contact"),
				Session: &session,
			}
		}()
	}
	wg.Wait()

	// Compact to successfully-assumed accounts; failed entries are left zero-value.
	scanned := make([]Account, 0, len(out))
	scannedIDs := make([]string, 0, len(out))
	for _, acc := range out {
		if acc.Session == nil {
			continue
		}
		scanned = append(scanned, acc)
		scannedIDs = append(scannedIDs, acc.ID)
	}
	sort.Strings(scannedIDs)
	known := make([]string, 0, len(accounts))
	for _, item := range accounts {
		if id := strings.TrimSpace(awsv2.ToString(item.Id)); id != "" {
			known = append(known, id)
		}
	}
	sort.Strings(known)
	cov := Coverage{
		Discovered: len(accounts), Scanned: scannedIDs, Failed: failed,
		OrgMembershipKnown: true, KnownOrgAccountIDs: known,
	}
	if len(failed) > 0 {
		slog.Warn("account collection skipped accounts that could not be assumed", "failed", len(failed), "discovered", len(accounts))
		// Surface the real reason (e.g. AccessDenied assuming the audit role) to operators.
		reportDiag(ctx, "accounts", fmt.Sprintf("%d of %d accounts could not be assumed via role %q: %s",
			len(failed), len(accounts), cfg.AWS.OrgRoleName, sampleReason(failed)))
	}
	return scanned, cov, nil
}

// sampleReason returns one representative failure reason from the failed map for operator
// diagnostics (the reasons are typically identical, e.g. the same AccessDenied).
func sampleReason(failed map[string]string) string {
	for _, reason := range failed {
		return reason
	}
	return "unknown error"
}

func tagValue(ctx context.Context, orgAPI OrganizationsAPI, accountID, key string) string {
	out, err := orgAPI.ListTagsForResource(ctx, &organizations.ListTagsForResourceInput{ResourceId: &accountID})
	if err != nil {
		return ""
	}
	for _, t := range out.Tags {
		if awsv2.ToString(t.Key) == key {
			return awsv2.ToString(t.Value)
		}
	}
	return ""
}

func buildOUPath(ctx context.Context, orgAPI OrganizationsAPI, accountID string) string {
	var parts []string
	current := accountID
	for {
		resp, err := orgAPI.ListParents(ctx, &organizations.ListParentsInput{
			ChildId: awsv2.String(current),
		})
		if err != nil || len(resp.Parents) == 0 {
			break
		}
		parent := resp.Parents[0]
		pid := awsv2.ToString(parent.Id)
		if parent.Type == types.ParentTypeRoot {
			parts = append([]string{"root"}, parts...)
			break
		}
		ouName := pid
		if d, err := orgAPI.DescribeOrganizationalUnit(ctx, &organizations.DescribeOrganizationalUnitInput{
			OrganizationalUnitId: awsv2.String(pid),
		}); err == nil && d.OrganizationalUnit != nil {
			ouName = awsv2.ToString(d.OrganizationalUnit.Name)
		}
		parts = append([]string{ouName}, parts...)
		current = pid
	}
	if len(parts) == 0 {
		return "unknown"
	}
	return fmt.Sprintf("/%s", joinPath(parts))
}

func joinPath(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for i := 1; i < len(parts); i++ {
		out += "/" + parts[i]
	}
	return out
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
