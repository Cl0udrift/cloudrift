package collectors

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// latencyIAM simulates access advisor timing: each call costs callLatency, and a job finishes
// jobDuration after Generate. Durations are scaled down from real AWS (seconds) so the benchmark runs quickly.
type latencyIAM struct {
	roles       []iamtypes.Role
	callLatency time.Duration
	jobDuration time.Duration
	mu          sync.Mutex
	created     map[string]time.Time
	calls       int
}

func (l *latencyIAM) ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	return &iam.ListRolesOutput{Roles: l.roles}, nil
}

func (l *latencyIAM) GenerateServiceLastAccessedDetails(_ context.Context, in *iam.GenerateServiceLastAccessedDetailsInput, _ ...func(*iam.Options)) (*iam.GenerateServiceLastAccessedDetailsOutput, error) {
	time.Sleep(l.callLatency)
	l.mu.Lock()
	l.calls++
	l.created[awsv2.ToString(in.Arn)] = time.Now()
	l.mu.Unlock()
	return &iam.GenerateServiceLastAccessedDetailsOutput{JobId: in.Arn}, nil
}

func (l *latencyIAM) GetServiceLastAccessedDetails(_ context.Context, in *iam.GetServiceLastAccessedDetailsInput, _ ...func(*iam.Options)) (*iam.GetServiceLastAccessedDetailsOutput, error) {
	time.Sleep(l.callLatency)
	l.mu.Lock()
	l.calls++
	started := l.created[awsv2.ToString(in.JobId)]
	l.mu.Unlock()
	if time.Since(started) < l.jobDuration {
		return &iam.GetServiceLastAccessedDetailsOutput{JobStatus: iamtypes.JobStatusTypeInProgress}, nil
	}
	return &iam.GetServiceLastAccessedDetailsOutput{JobStatus: iamtypes.JobStatusTypeCompleted}, nil
}

func benchRoles(n int) []iamtypes.Role {
	out := make([]iamtypes.Role, n)
	for i := range out {
		name := "R" + strconv.Itoa(i)
		out[i] = iamtypes.Role{Arn: awsv2.String("arn:aws:iam::111111111111:role/" + name), RoleName: awsv2.String(name)}
	}
	return out
}

// BenchmarkServiceAccessScheduling: 160 roles, 8 workers. Scaled timings: call 3ms, job 60ms, poll 30ms.
func BenchmarkServiceAccessScheduling(b *testing.B) {
	prevPoll, prevFirst := serviceAccessPollInterval, serviceAccessFirstPoll
	serviceAccessPollInterval, serviceAccessFirstPoll = 30*time.Millisecond, 30*time.Millisecond
	defer func() { serviceAccessPollInterval, serviceAccessFirstPoll = prevPoll, prevFirst }()
	for i := 0; i < b.N; i++ {
		f := &latencyIAM{roles: benchRoles(160), callLatency: 3 * time.Millisecond, jobDuration: 60 * time.Millisecond, created: map[string]time.Time{}}
		rows, err := collectServiceAccessFromClient(context.Background(), "111111111111", f, newServiceAccessLimiter(8), ServiceAccessOptions{})
		if err != nil || len(rows) != 160 {
			b.Fatalf("rows %d err %v", len(rows), err)
		}
		b.ReportMetric(float64(f.calls), "api_calls")
	}
}
