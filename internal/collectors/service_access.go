package collectors

import (
	"context"
	"errors"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"

	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// Service last-accessed collection is opt-in (scan.service_last_accessed, default false).
// It uses IAM access advisor data: for each role, which AWS services the role's permissions
// allow and when each was last authenticated. It does not show which individual actions were used.
// Required IAM actions are listed in docs/audits/service-last-accessed.md.

// Per-role collection states stored as service_last_accessed_status.
const (
	ServiceAccessComplete     = "complete"
	ServiceAccessPartial      = "partial"       // job still running after the poll limit, or pages capped
	ServiceAccessFailed       = "failed"        // IAM reported the job failed
	ServiceAccessNotCollected = "not_collected" // the API call did not succeed or ran out of time
	ServiceAccessSkipped      = "skipped_service_linked"
)

const (
	serviceAccessDefaultConcurrency = 8
	serviceAccessMaxConcurrency     = 16
	serviceAccessMaxPages           = 20
	serviceAccessThrottleRetries    = 5
)

// ServiceAccessOptions bounds a collection run. The zero value is the safe default.
type ServiceAccessOptions struct {
	ActionLevel bool
	// Concurrency bounds in-flight Generate calls. Get calls use twice that. Jobs wait for AWS
	// without holding either slot, so a slow job does not block other roles.
	Concurrency int
	// SkipServiceLinked is an optional scope reduction. Default false collects every role.
	SkipServiceLinked bool
	// AccountTimeout is an optional total budget per account. Zero means none: nothing is dropped by default.
	AccountTimeout time.Duration
}

func serviceAccessOptions(cfg *config.Config) ServiceAccessOptions {
	opt := ServiceAccessOptions{
		ActionLevel:       cfg.Scan.ServiceLastAccessedGranularity == "action",
		Concurrency:       cfg.Scan.ServiceLastAccessedConcurrency,
		SkipServiceLinked: cfg.Scan.ServiceLastAccessedSkipServiceLinked,
		AccountTimeout:    time.Duration(cfg.Scan.ServiceLastAccessedTimeoutSeconds) * time.Second,
	}
	if opt.Concurrency <= 0 {
		opt.Concurrency = serviceAccessDefaultConcurrency
	}
	if opt.Concurrency > serviceAccessMaxConcurrency {
		opt.Concurrency = serviceAccessMaxConcurrency
	}
	return opt
}

var (
	// A job is polled first after serviceAccessFirstPoll, then with 1.5x backoff up to serviceAccessPollInterval.
	serviceAccessFirstPoll    = 1 * time.Second
	serviceAccessPollInterval = 5 * time.Second
	// serviceAccessJobTimeout bounds one role's job. A job past it is recorded as partial.
	serviceAccessJobTimeout   = 5 * time.Minute
	serviceAccessThrottleBase = 1 * time.Second
	serviceAccessSleep        = func(ctx context.Context, d time.Duration) error {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			return nil
		}
	}
)

// TrackedAction is one action IAM tracks at action level (only some services and actions).
type TrackedAction struct {
	ActionName         string     `json:"action_name"`
	LastAccessedTime   *time.Time `json:"last_accessed_time,omitempty"`
	LastAccessedRegion string     `json:"last_accessed_region,omitempty"`
}

type ServiceAccess struct {
	TrackedActions             []TrackedAction `json:"tracked_actions,omitempty"`
	ServiceNamespace           string          `json:"service_namespace"`
	ServiceName                string          `json:"service_name"`
	LastAuthenticated          *time.Time      `json:"last_authenticated,omitempty"`
	LastAuthenticatedRegion    string          `json:"last_authenticated_region,omitempty"`
	LastAuthenticatedEntity    string          `json:"last_authenticated_entity,omitempty"`
	TotalAuthenticatedEntities int             `json:"total_authenticated_entities,omitempty"`
}

type RoleServiceAccess struct {
	RoleARN      string          `json:"role_arn"`
	AccountID    string          `json:"account_id"`
	Status       string          `json:"status"`
	JobCompleted *time.Time      `json:"job_completed,omitempty"`
	Services     []ServiceAccess `json:"services,omitempty"`
}

type IAMServiceAccessAPI interface {
	ListRoles(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error)
	GenerateServiceLastAccessedDetails(ctx context.Context, params *iam.GenerateServiceLastAccessedDetailsInput, optFns ...func(*iam.Options)) (*iam.GenerateServiceLastAccessedDetailsOutput, error)
	GetServiceLastAccessedDetails(ctx context.Context, params *iam.GetServiceLastAccessedDetailsInput, optFns ...func(*iam.Options)) (*iam.GetServiceLastAccessedDetailsOutput, error)
}

var newIAMServiceAccessClient = func(cfg awsv2.Config) IAMServiceAccessAPI {
	return iam.NewFromConfig(cfg)
}

// CollectServiceLastAccessed runs only when cfg.Scan.ServiceLastAccessed is true. A failure for one
// account or role is logged and recorded per role, never fatal for the scan.
func CollectServiceLastAccessed(ctx context.Context, cfg *config.Config, accounts []Account) []RoleServiceAccess {
	if cfg == nil || !cfg.Scan.ServiceLastAccessed {
		return nil
	}
	opt := serviceAccessOptions(cfg)
	lim := newServiceAccessLimiter(opt.Concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	var all []RoleServiceAccess
	for _, account := range accounts {
		account := account
		if account.Session == nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			actx, cancel := ctx, context.CancelFunc(func() {})
			if opt.AccountTimeout > 0 {
				actx, cancel = context.WithTimeout(ctx, opt.AccountTimeout)
			}
			defer cancel()
			rows, err := collectServiceAccessFromClient(actx, account.ID, newIAMServiceAccessClient(*account.Session), lim, opt)
			mu.Lock()
			defer mu.Unlock()
			if err != nil && firstErr == nil {
				firstErr = err
			}
			all = append(all, rows...)
		}()
	}
	wg.Wait()
	warnPartial(ctx, "service-last-accessed", firstErr)
	sort.Slice(all, func(i, j int) bool { return all[i].RoleARN < all[j].RoleARN })
	return all
}

func collectServiceAccessFromClient(ctx context.Context, accountID string, client IAMServiceAccessAPI, lim *serviceAccessLimiter, opt ServiceAccessOptions) ([]RoleServiceAccess, error) {
	var roles []iamtypes.Role
	var marker *string
	for {
		out, err := client.ListRoles(ctx, &iam.ListRolesInput{Marker: marker})
		if err != nil {
			return nil, err
		}
		roles = append(roles, out.Roles...)
		if !out.IsTruncated || out.Marker == nil {
			break
		}
		marker = out.Marker
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	var rows []RoleServiceAccess
	for _, role := range roles {
		arn := awsv2.ToString(role.Arn)
		if arn == "" {
			continue
		}
		if opt.SkipServiceLinked && isServiceLinkedRole(role) {
			// Recorded as skipped by design, so it is never mistaken for "no access".
			mu.Lock()
			rows = append(rows, RoleServiceAccess{RoleARN: arn, AccountID: accountID, Status: ServiceAccessSkipped})
			mu.Unlock()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			row := collectOneRoleServiceAccess(ctx, client, arn, opt.ActionLevel, lim)
			row.AccountID = accountID
			mu.Lock()
			rows = append(rows, row)
			mu.Unlock()
		}()
	}
	wg.Wait()
	return rows, nil
}

type serviceAccessLimiter struct{ gen, get chan struct{} }

func newServiceAccessLimiter(concurrency int) *serviceAccessLimiter {
	return &serviceAccessLimiter{gen: make(chan struct{}, concurrency), get: make(chan struct{}, concurrency*2)}
}

// do runs one API call inside a limiter slot and retries throttling errors with jittered backoff.
// The slot is released between attempts and while waiting for the job.
func (l *serviceAccessLimiter) do(ctx context.Context, slots chan struct{}, call func() error) error {
	var err error
	for attempt := 0; attempt <= serviceAccessThrottleRetries; attempt++ {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		err = call()
		<-slots
		if err == nil || !isThrottle(err) {
			return err
		}
		backoff := serviceAccessThrottleBase << attempt
		backoff += time.Duration(rand.Int63n(int64(backoff/2) + 1))
		if serviceAccessSleep(ctx, backoff) != nil {
			return err
		}
	}
	return err
}

func isThrottle(err error) bool {
	var api smithy.APIError
	if errors.As(err, &api) {
		code := api.ErrorCode()
		return strings.Contains(code, "Throttl") || code == "RequestLimitExceeded" || code == "ServiceUnavailable"
	}
	return false
}

// collectOneRoleServiceAccess starts one access advisor job, then waits for it OUTSIDE any limiter slot
// (adaptive poll interval), and pages the result. Waiting never blocks other roles.
func collectOneRoleServiceAccess(ctx context.Context, client IAMServiceAccessAPI, roleARN string, actionLevel bool, lim *serviceAccessLimiter) RoleServiceAccess {
	row := RoleServiceAccess{RoleARN: roleARN, Status: ServiceAccessNotCollected}
	granularity := iamtypes.AccessAdvisorUsageGranularityTypeServiceLevel
	if actionLevel {
		granularity = iamtypes.AccessAdvisorUsageGranularityTypeActionLevel
	}
	var gen *iam.GenerateServiceLastAccessedDetailsOutput
	if err := lim.do(ctx, lim.gen, func() (err error) {
		gen, err = client.GenerateServiceLastAccessedDetails(ctx, &iam.GenerateServiceLastAccessedDetailsInput{
			Arn: awsv2.String(roleARN), Granularity: granularity,
		})
		return err
	}); err != nil || gen == nil || gen.JobId == nil {
		return row
	}
	jobCtx, cancel := context.WithTimeout(ctx, serviceAccessJobTimeout)
	defer cancel()
	wait := serviceAccessFirstPoll
	for {
		if serviceAccessSleep(jobCtx, wait) != nil {
			if ctx.Err() == nil {
				row.Status = ServiceAccessPartial // this job outlived serviceAccessJobTimeout
			}
			return row
		}
		wait = wait * 3 / 2
		if wait > serviceAccessPollInterval {
			wait = serviceAccessPollInterval
		}
		var services []ServiceAccess
		var completed *time.Time
		var marker *string
		status := iamtypes.JobStatusTypeInProgress
		capped := false
		for page := 0; ; page++ {
			var out *iam.GetServiceLastAccessedDetailsOutput
			if err := lim.do(jobCtx, lim.get, func() (err error) {
				out, err = client.GetServiceLastAccessedDetails(jobCtx, &iam.GetServiceLastAccessedDetailsInput{JobId: gen.JobId, Marker: marker})
				return err
			}); err != nil {
				return row
			}
			status = out.JobStatus
			if status != iamtypes.JobStatusTypeCompleted {
				break
			}
			completed = out.JobCompletionDate
			for _, svc := range out.ServicesLastAccessed {
				services = append(services, toServiceAccess(svc))
			}
			if !out.IsTruncated || out.Marker == nil {
				break
			}
			if page+1 >= serviceAccessMaxPages {
				capped = true
				break
			}
			marker = out.Marker
		}
		switch status {
		case iamtypes.JobStatusTypeCompleted:
			sort.Slice(services, func(i, j int) bool { return services[i].ServiceNamespace < services[j].ServiceNamespace })
			row.Services, row.JobCompleted = services, completed
			row.Status = ServiceAccessComplete
			if capped {
				row.Status = ServiceAccessPartial
			}
			return row
		case iamtypes.JobStatusTypeFailed:
			row.Status = ServiceAccessFailed
			return row
		}
	}
}

func toServiceAccess(svc iamtypes.ServiceLastAccessed) ServiceAccess {
	item := ServiceAccess{
		ServiceNamespace: awsv2.ToString(svc.ServiceNamespace), ServiceName: awsv2.ToString(svc.ServiceName),
		LastAuthenticatedRegion: awsv2.ToString(svc.LastAuthenticatedRegion), LastAuthenticatedEntity: awsv2.ToString(svc.LastAuthenticatedEntity),
	}
	if svc.LastAuthenticated != nil {
		t := svc.LastAuthenticated.UTC()
		item.LastAuthenticated = &t
	}
	if svc.TotalAuthenticatedEntities != nil {
		item.TotalAuthenticatedEntities = int(*svc.TotalAuthenticatedEntities)
	}
	for _, act := range svc.TrackedActionsLastAccessed {
		ta := TrackedAction{ActionName: awsv2.ToString(act.ActionName), LastAccessedRegion: awsv2.ToString(act.LastAccessedRegion)}
		if act.LastAccessedTime != nil {
			t := act.LastAccessedTime.UTC()
			ta.LastAccessedTime = &t
		}
		item.TrackedActions = append(item.TrackedActions, ta)
	}
	return item
}

// isServiceLinkedRole matches AWS-owned service-linked roles by path.
func isServiceLinkedRole(role iamtypes.Role) bool {
	return strings.HasPrefix(awsv2.ToString(role.Path), "/aws-service-role/")
}

// StampServiceAccess records access advisor evidence on role assets. Call it only when collection was
// requested. A role with no row is not_collected. Absence from the service list is never "unused".
func StampServiceAccess(assets []models.AssetNode, rows []RoleServiceAccess) {
	byARN := make(map[string]RoleServiceAccess, len(rows))
	for _, row := range rows {
		byARN[row.RoleARN] = row
	}
	for i := range assets {
		if assets[i].AssetType != models.AssetIAMRole {
			continue
		}
		if assets[i].Properties == nil {
			assets[i].Properties = map[string]any{}
		}
		row, ok := byARN[assets[i].ARN]
		if !ok {
			assets[i].Properties["service_last_accessed_status"] = ServiceAccessNotCollected
			continue
		}
		assets[i].Properties["service_last_accessed_status"] = row.Status
		if row.JobCompleted != nil {
			assets[i].Properties["service_last_accessed_completed"] = row.JobCompleted.UTC().Format(time.RFC3339)
		}
		list := make([]map[string]any, 0, len(row.Services))
		for _, svc := range row.Services {
			item := map[string]any{"service_namespace": svc.ServiceNamespace, "service_name": svc.ServiceName}
			if svc.LastAuthenticated != nil {
				item["last_authenticated"] = svc.LastAuthenticated.UTC().Format(time.RFC3339)
			}
			if svc.LastAuthenticatedRegion != "" {
				item["last_authenticated_region"] = svc.LastAuthenticatedRegion
			}
			if len(svc.TrackedActions) > 0 {
				actions := make([]map[string]any, 0, len(svc.TrackedActions))
				for _, act := range svc.TrackedActions {
					a := map[string]any{"action_name": act.ActionName}
					if act.LastAccessedTime != nil {
						a["last_accessed_time"] = act.LastAccessedTime.UTC().Format(time.RFC3339)
					}
					actions = append(actions, a)
				}
				item["tracked_actions"] = actions
			}
			list = append(list, item)
		}
		assets[i].Properties["service_last_accessed"] = list
	}
}
