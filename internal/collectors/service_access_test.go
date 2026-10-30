package collectors

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/aws/smithy-go"

	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// fakeServiceAccessIAM scripts per-role Generate and Get behaviour. It records every call so tests
// can assert that only read-style access advisor calls are made.
type fakeServiceAccessIAM struct {
	roles       []iamtypes.Role
	generateErr map[string]error
	// pages[jobID] is the ordered list of Get responses; the last one repeats.
	pages map[string][]*iam.GetServiceLastAccessedDetailsOutput
	mu    sync.Mutex // roles are collected concurrently
	// wantGranularity, when set, makes Generate fail the test if another granularity is requested.
	wantGranularity iamtypes.AccessAdvisorUsageGranularityType
	calls           map[string]int
}

func (f *fakeServiceAccessIAM) ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	return &iam.ListRolesOutput{Roles: f.roles}, nil
}

func (f *fakeServiceAccessIAM) GenerateServiceLastAccessedDetails(_ context.Context, in *iam.GenerateServiceLastAccessedDetailsInput, _ ...func(*iam.Options)) (*iam.GenerateServiceLastAccessedDetailsOutput, error) {
	arn := awsv2.ToString(in.Arn)
	want := f.wantGranularity
	if want == "" {
		want = iamtypes.AccessAdvisorUsageGranularityTypeServiceLevel
	}
	if in.Granularity != want {
		panic("unexpected granularity " + string(in.Granularity))
	}
	if err := f.generateErr[arn]; err != nil {
		return nil, err
	}
	return &iam.GenerateServiceLastAccessedDetailsOutput{JobId: awsv2.String("job:" + arn)}, nil
}

func (f *fakeServiceAccessIAM) GetServiceLastAccessedDetails(_ context.Context, in *iam.GetServiceLastAccessedDetailsInput, _ ...func(*iam.Options)) (*iam.GetServiceLastAccessedDetailsOutput, error) {
	job := awsv2.ToString(in.JobId)
	f.mu.Lock()
	list := f.pages[job]
	idx := f.calls[job]
	f.calls[job]++
	f.mu.Unlock()
	if idx >= len(list) {
		idx = len(list) - 1
	}
	return list[idx], nil
}

func svc(ns, name string, last *time.Time) iamtypes.ServiceLastAccessed {
	return iamtypes.ServiceLastAccessed{ServiceNamespace: awsv2.String(ns), ServiceName: awsv2.String(name), LastAuthenticated: last}
}

func role(name string) iamtypes.Role {
	return iamtypes.Role{Arn: awsv2.String("arn:aws:iam::111111111111:role/" + name), RoleName: awsv2.String(name)}
}

func TestServiceAccessStatesAndNoWritePaths(t *testing.T) {
	prevSleep, prevTimeout := serviceAccessSleep, serviceAccessJobTimeout
	serviceAccessSleep = func(ctx context.Context, _ time.Duration) error {
		time.Sleep(time.Millisecond)
		return ctx.Err()
	}
	serviceAccessJobTimeout = 150 * time.Millisecond
	t.Cleanup(func() { serviceAccessSleep, serviceAccessJobTimeout = prevSleep, prevTimeout })
	used := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	done := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	arn := func(n string) string { return "job:arn:aws:iam::111111111111:role/" + n }
	completed := func(services ...iamtypes.ServiceLastAccessed) *iam.GetServiceLastAccessedDetailsOutput {
		return &iam.GetServiceLastAccessedDetailsOutput{JobStatus: iamtypes.JobStatusTypeCompleted, JobCompletionDate: &done, ServicesLastAccessed: services}
	}
	inProgress := &iam.GetServiceLastAccessedDetailsOutput{JobStatus: iamtypes.JobStatusTypeInProgress}
	f := &fakeServiceAccessIAM{
		roles:       []iamtypes.Role{role("Done"), role("Slow"), role("Never"), role("Failed"), role("Denied")},
		generateErr: map[string]error{"arn:aws:iam::111111111111:role/Denied": errors.New("AccessDenied")},
		calls:       map[string]int{},
		pages: map[string][]*iam.GetServiceLastAccessedDetailsOutput{
			arn("Done"):   {completed(svc("s3", "Amazon S3", &used), svc("iam", "AWS IAM", nil))},
			arn("Slow"):   {inProgress, inProgress, completed(svc("sts", "AWS STS", &used))},
			arn("Never"):  {inProgress},
			arn("Failed"): {{JobStatus: iamtypes.JobStatusTypeFailed}},
		},
	}
	rows, err := collectServiceAccessFromClient(context.Background(), "111111111111", f, newServiceAccessLimiter(4), ServiceAccessOptions{})
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]RoleServiceAccess{}
	for _, r := range rows {
		by[r.RoleARN[len("arn:aws:iam::111111111111:role/"):]] = r
	}
	if r := by["Done"]; r.Status != ServiceAccessComplete || len(r.Services) != 2 || r.JobCompleted == nil {
		t.Fatalf("done %+v", r)
	}
	// iam has no LastAuthenticated: IAM reported the service but no access in the window.
	for _, s := range by["Done"].Services {
		if s.ServiceNamespace == "iam" && s.LastAuthenticated != nil {
			t.Fatalf("iam should have no last access: %+v", s)
		}
		if s.ServiceNamespace == "s3" && (s.LastAuthenticated == nil || !s.LastAuthenticated.Equal(used)) {
			t.Fatalf("s3 date lost: %+v", s)
		}
	}
	if r := by["Slow"]; r.Status != ServiceAccessComplete || len(r.Services) != 1 {
		t.Fatalf("slow job must be polled to completion: %+v", r)
	}
	if r := by["Never"]; r.Status != ServiceAccessPartial || len(r.Services) != 0 {
		t.Fatalf("a job that never finishes is partial with no services: %+v", r)
	}
	if by["Failed"].Status != ServiceAccessFailed || by["Denied"].Status != ServiceAccessNotCollected {
		t.Fatalf("failed %+v denied %+v", by["Failed"], by["Denied"])
	}
}

func TestServiceAccessDisabledMakesNoCalls(t *testing.T) {
	cfg := config.Default()
	if cfg.Scan.ServiceLastAccessed {
		t.Fatal("service_last_accessed must default to false")
	}
	called := false
	prev := newIAMServiceAccessClient
	newIAMServiceAccessClient = func(awsv2.Config) IAMServiceAccessAPI { called = true; return &fakeServiceAccessIAM{} }
	defer func() { newIAMServiceAccessClient = prev }()
	sess := awsv2.Config{}
	if rows := CollectServiceLastAccessed(context.Background(), cfg, []Account{{ID: "1", Session: &sess}}); rows != nil || called {
		t.Fatalf("disabled collection must not create a client or return rows (called=%v rows=%v)", called, rows)
	}
}

func TestStampServiceAccessNeverInfersUnused(t *testing.T) {
	used := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	mk := func(n string) models.AssetNode {
		return models.AssetNode{ARN: "arn:aws:iam::1:role/" + n, AssetType: models.AssetIAMRole}
	}
	assets := []models.AssetNode{mk("A"), mk("B")}
	StampServiceAccess(assets, []RoleServiceAccess{{RoleARN: assets[0].ARN, Status: ServiceAccessComplete, Services: []ServiceAccess{{ServiceNamespace: "s3", ServiceName: "Amazon S3", LastAuthenticated: &used}}}})
	list, _ := assets[0].Properties["service_last_accessed"].([]map[string]any)
	if assets[0].Properties["service_last_accessed_status"] != ServiceAccessComplete || len(list) != 1 || list[0]["last_authenticated"] != "2026-09-01T00:00:00Z" {
		t.Fatalf("%v", assets[0].Properties)
	}
	if assets[1].Properties["service_last_accessed_status"] != ServiceAccessNotCollected || assets[1].Properties["service_last_accessed"] != nil {
		t.Fatalf("missing row must be not_collected: %v", assets[1].Properties)
	}
}

func TestServiceAccessOptionsDefaultsAndClamps(t *testing.T) {
	cfg := config.Default()
	o := serviceAccessOptions(cfg)
	if o.ActionLevel || o.SkipServiceLinked || o.Concurrency != 8 || o.AccountTimeout != 0 {
		t.Fatalf("defaults: %+v", o)
	}
	cfg.Scan.ServiceLastAccessedConcurrency = 500
	cfg.Scan.ServiceLastAccessedGranularity = "action"
	cfg.Scan.ServiceLastAccessedTimeoutSeconds = 30
	cfg.Scan.ServiceLastAccessedSkipServiceLinked = true
	o = serviceAccessOptions(cfg)
	if o.Concurrency != 16 || !o.ActionLevel || o.AccountTimeout != 30*time.Second || !o.SkipServiceLinked {
		t.Fatalf("clamped: %+v", o)
	}
}

// Service-linked roles are skipped by default, recorded as skipped (not "no access"), and make no API calls.
func TestServiceAccessSkipsServiceLinkedRolesWhenAsked(t *testing.T) {
	slr := iamtypes.Role{Arn: awsv2.String("arn:aws:iam::111111111111:role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS"), RoleName: awsv2.String("AWSServiceRoleForECS"), Path: awsv2.String("/aws-service-role/ecs.amazonaws.com/")}
	app := role("App")
	done := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	f := &fakeServiceAccessIAM{roles: []iamtypes.Role{slr, app}, calls: map[string]int{}, pages: map[string][]*iam.GetServiceLastAccessedDetailsOutput{
		"job:arn:aws:iam::111111111111:role/App": {{JobStatus: iamtypes.JobStatusTypeCompleted, JobCompletionDate: &done}},
	}}
	rows, _ := collectServiceAccessFromClient(context.Background(), "111111111111", f, newServiceAccessLimiter(2), ServiceAccessOptions{SkipServiceLinked: true})
	status := map[string]string{}
	for _, r := range rows {
		status[r.RoleARN] = r.Status
	}
	if status[awsv2.ToString(slr.Arn)] != ServiceAccessSkipped || status[awsv2.ToString(app.Arn)] != ServiceAccessComplete {
		t.Fatalf("%v", status)
	}
	if len(f.calls) != 1 {
		t.Fatalf("only the non service-linked role may start a job: %v", f.calls)
	}
}

func TestServiceAccessActionLevelParsesTrackedActions(t *testing.T) {
	at := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	done := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	svcOut := iamtypes.ServiceLastAccessed{ServiceNamespace: awsv2.String("iam"), ServiceName: awsv2.String("AWS IAM"),
		TrackedActionsLastAccessed: []iamtypes.TrackedActionLastAccessed{{ActionName: awsv2.String("PassRole"), LastAccessedTime: &at, LastAccessedRegion: awsv2.String("us-east-1")}, {ActionName: awsv2.String("AttachRolePolicy")}}}
	f := &fakeServiceAccessIAM{roles: []iamtypes.Role{role("App")}, calls: map[string]int{}, pages: map[string][]*iam.GetServiceLastAccessedDetailsOutput{
		"job:arn:aws:iam::111111111111:role/App": {{JobStatus: iamtypes.JobStatusTypeCompleted, JobCompletionDate: &done, ServicesLastAccessed: []iamtypes.ServiceLastAccessed{svcOut}}},
	}}
	f.wantGranularity = iamtypes.AccessAdvisorUsageGranularityTypeActionLevel
	rows, _ := collectServiceAccessFromClient(context.Background(), "111111111111", f, newServiceAccessLimiter(2), ServiceAccessOptions{ActionLevel: true})
	if len(rows) != 1 || len(rows[0].Services) != 1 || len(rows[0].Services[0].TrackedActions) != 2 {
		t.Fatalf("%+v", rows)
	}
	pr := rows[0].Services[0].TrackedActions[0]
	if pr.ActionName != "PassRole" || pr.LastAccessedTime == nil || !pr.LastAccessedTime.Equal(at) {
		t.Fatalf("%+v", pr)
	}
}

// An expired account budget leaves roles not_collected rather than inventing a result.
func TestServiceAccessTimeBudgetLeavesNotCollected(t *testing.T) {
	f := &fakeServiceAccessIAM{roles: []iamtypes.Role{role("App")}, calls: map[string]int{}, pages: map[string][]*iam.GetServiceLastAccessedDetailsOutput{
		"job:arn:aws:iam::111111111111:role/App": {{JobStatus: iamtypes.JobStatusTypeInProgress}},
	}}
	prev := serviceAccessSleep
	serviceAccessSleep = func(ctx context.Context, _ time.Duration) error { time.Sleep(2 * time.Millisecond); return ctx.Err() }
	defer func() { serviceAccessSleep = prev }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	rows, _ := collectServiceAccessFromClient(ctx, "111111111111", f, newServiceAccessLimiter(2), ServiceAccessOptions{})
	if len(rows) != 1 || rows[0].Status != ServiceAccessNotCollected || len(rows[0].Services) != 0 {
		t.Fatalf("%+v", rows)
	}
}

// Throttling errors are retried with backoff; a non-throttle error is not.
func TestServiceAccessRetriesThrottling(t *testing.T) {
	prev := serviceAccessSleep
	serviceAccessSleep = func(context.Context, time.Duration) error { return nil }
	defer func() { serviceAccessSleep = prev }()
	lim := newServiceAccessLimiter(2)
	attempts := 0
	err := lim.do(context.Background(), lim.gen, func() error {
		attempts++
		if attempts < 3 {
			return &smithy.GenericAPIError{Code: "Throttling", Message: "Rate exceeded"}
		}
		return nil
	})
	if err != nil || attempts != 3 {
		t.Fatalf("throttle retry: attempts=%d err=%v", attempts, err)
	}
	attempts = 0
	err = lim.do(context.Background(), lim.gen, func() error {
		attempts++
		return &smithy.GenericAPIError{Code: "AccessDenied", Message: "no"}
	})
	if err == nil || attempts != 1 {
		t.Fatalf("access denied must not be retried: attempts=%d err=%v", attempts, err)
	}
}

// A job waiting on AWS must not hold a slot: with one Generate slot and slow jobs, all roles still start.
func TestServiceAccessWaitingJobsDoNotHoldSlots(t *testing.T) {
	prevPoll, prevFirst := serviceAccessPollInterval, serviceAccessFirstPoll
	serviceAccessPollInterval, serviceAccessFirstPoll = 5*time.Millisecond, 5*time.Millisecond
	defer func() { serviceAccessPollInterval, serviceAccessFirstPoll = prevPoll, prevFirst }()
	f := &latencyIAM{roles: benchRoles(20), callLatency: time.Millisecond, jobDuration: 80 * time.Millisecond, created: map[string]time.Time{}}
	start := time.Now()
	rows, err := collectServiceAccessFromClient(context.Background(), "1", f, newServiceAccessLimiter(1), ServiceAccessOptions{})
	took := time.Since(start)
	if err != nil || len(rows) != 20 {
		t.Fatalf("rows %d err %v", len(rows), err)
	}
	// Serial hold-a-slot scheduling would need about 20 x 80ms = 1.6s. Overlapped waits finish near one job duration.
	if took > 700*time.Millisecond {
		t.Fatalf("jobs are not overlapping: took %v", took)
	}
}
