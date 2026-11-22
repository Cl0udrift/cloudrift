package collectors

import (
	"context"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

func ev(at time.Time, body string) cttypes.Event {
	return cttypes.Event{EventTime: awsv2.Time(at), CloudTrailEvent: awsv2.String(body)}
}

func TestParseAssumeEvents(t *testing.T) {
	t1 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	t2 := t1.Add(48 * time.Hour)
	role := `"requestParameters":{"roleArn":"arn:aws:iam::111111111111:role/Target"}`
	got := ParseAssumeEvents([]cttypes.Event{
		ev(t1, `{"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111111111111:user/chris"},`+role+`}`),
		ev(t2, `{"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111111111111:user/chris"},`+role+`}`),
		ev(t1, `{"userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::111111111111:assumed-role/Dev/session-9"},`+role+`}`),
		ev(t1, `{"userIdentity":{"type":"AWSService","invokedBy":"lambda.amazonaws.com"},`+role+`}`),
		ev(t1, `{"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111111111111:user/denied"},"errorCode":"AccessDenied",`+role+`}`),
		ev(t1, `not json`),
	})
	if len(got) != 3 {
		t.Fatalf("a failed call and a bad record are not assumptions; want 3 callers, got %+v", got)
	}
	by := map[string]ObservedAssumption{}
	for _, o := range got {
		by[o.Caller] = o
	}
	chris := by["arn:aws:iam::111111111111:user/chris"]
	if chris.Count != 2 || !chris.First.Equal(t1) || !chris.Last.Equal(t2) {
		t.Fatalf("counts and first/last seen must merge: %+v", chris)
	}
	if _, ok := by["arn:aws:iam::111111111111:role/Dev"]; !ok {
		t.Fatal("a role session must be reported as its role")
	}
	if by["lambda.amazonaws.com"].CallerType != "aws_service" {
		t.Fatal("a service caller must be named by its principal")
	}
}

type pagedTrail struct{ pages int }

func (p *pagedTrail) LookupEvents(_ context.Context, in *cloudtrail.LookupEventsInput, _ ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	p.pages++
	return &cloudtrail.LookupEventsOutput{Events: []cttypes.Event{{}, {}}, NextToken: awsv2.String("more")}, nil
}

func TestLookupStopsAtTheEventCapAndSaysSo(t *testing.T) {
	api := &pagedTrail{}
	events, truncated, err := lookupAssumeEvents(context.Background(), api, time.Now().AddDate(0, 0, -7), 4, time.Now().Add(time.Minute))
	if err != nil || !truncated || len(events) < 4 {
		t.Fatalf("hitting the cap must be reported as truncated, not as the whole history: %d events, truncated %v, %v", len(events), truncated, err)
	}
}

func TestObservedEdgesMergeRegions(t *testing.T) {
	t1 := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	rels := ObservedAssumptionEdges([]ObservedAssumption{
		{Caller: "c", Role: "r", Count: 2, First: t1, Last: t1.Add(time.Hour)},
		{Caller: "c", Role: "r", Count: 3, First: t1.Add(-time.Hour), Last: t1},
	}, 30, t1)
	if len(rels) != 1 || rels[0].Properties["count"] != 5 || rels[0].Properties["first_seen"] != t1.Add(-time.Hour).Format(time.RFC3339) {
		t.Fatalf("%+v", rels)
	}
}

func TestParseAssumeEventsKeepsDistinctSourceIPs(t *testing.T) {
	at := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	role := `"requestParameters":{"roleArn":"arn:aws:iam::111111111111:role/Target"}`
	user := `"userIdentity":{"type":"IAMUser","arn":"arn:aws:iam::111111111111:user/chris"}`
	got := ParseAssumeEvents([]cttypes.Event{
		ev(at, `{`+user+`,"sourceIPAddress":"203.0.113.7",`+role+`}`),
		ev(at, `{`+user+`,"sourceIPAddress":"203.0.113.7",`+role+`}`),
		ev(at, `{`+user+`,"sourceIPAddress":"198.51.100.9",`+role+`}`),
	})
	if len(got) != 1 || len(got[0].SourceIPs) != 2 || got[0].Count != 3 {
		t.Fatalf("want one caller, 3 calls, 2 distinct addresses: %+v", got)
	}
	rels := ObservedAssumptionEdges(got, 30, at)
	if ips, _ := rels[0].Properties["source_ips"].([]string); len(ips) != 2 {
		t.Fatalf("the edge must carry the addresses: %+v", rels[0].Properties)
	}
}
