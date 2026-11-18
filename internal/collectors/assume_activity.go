package collectors

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	cttypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// CloudTrailAPI is the one read-only call used to see who assumed a role. LookupEvents reads the 90-day management event
// history; it is rate limited (2 requests per second per account and Region) and returns 50 events per page.
type CloudTrailAPI interface {
	LookupEvents(context.Context, *cloudtrail.LookupEventsInput, ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

// ObservedAssumption is what the event history says about one caller and one role.
type ObservedAssumption struct {
	Caller, CallerType, Role string
	Count                    int
	First, Last              time.Time
}

type cloudTrailEvent struct {
	UserIdentity struct {
		Type      string `json:"type"`
		ARN       string `json:"arn"`
		AccountID string `json:"accountId"`
		InvokedBy string `json:"invokedBy"`
	} `json:"userIdentity"`
	RequestParameters struct {
		RoleArn string `json:"roleArn"`
	} `json:"requestParameters"`
	ErrorCode string `json:"errorCode"`
}

// callerOf names the caller of an AssumeRole event. A role session is reported as its role, so a caller can be matched to the
// role inventory; the role's path is not in a session ARN, so a role with a path is matched by name when joined.
func callerOf(e cloudTrailEvent) (caller, kind string) {
	id := e.UserIdentity
	switch id.Type {
	case "IAMUser":
		return id.ARN, "iam_user"
	case "AssumedRole":
		parts := strings.Split(id.ARN, ":") // arn:aws:sts::acct:assumed-role/Name/session
		if len(parts) >= 6 && strings.HasPrefix(parts[5], "assumed-role/") {
			segs := strings.Split(parts[5], "/")
			if len(segs) >= 2 {
				return "arn:aws:iam::" + parts[4] + ":role/" + segs[1], "iam_role"
			}
		}
	case "AWSService":
		return id.InvokedBy, "aws_service"
	case "AWSAccount":
		return "arn:aws:iam::" + id.AccountID + ":root", "account"
	case "Root":
		return id.ARN, "root"
	case "WebIdentityUser", "SAMLUser", "FederatedUser":
		return id.ARN, "federated"
	}
	return "", ""
}

// ParseAssumeEvents folds raw CloudTrail events into one record per caller and role. Failed calls are not assumptions.
func ParseAssumeEvents(events []cttypes.Event) []ObservedAssumption {
	type key struct{ caller, role string }
	agg := map[key]*ObservedAssumption{}
	for _, ev := range events {
		var e cloudTrailEvent
		if json.Unmarshal([]byte(awsv2.ToString(ev.CloudTrailEvent)), &e) != nil || e.ErrorCode != "" || e.RequestParameters.RoleArn == "" {
			continue
		}
		caller, kind := callerOf(e)
		if caller == "" {
			continue
		}
		at := awsv2.ToTime(ev.EventTime)
		k := key{caller, e.RequestParameters.RoleArn}
		o := agg[k]
		if o == nil {
			o = &ObservedAssumption{Caller: caller, CallerType: kind, Role: k.role, First: at, Last: at}
			agg[k] = o
		}
		o.Count++
		if at.Before(o.First) {
			o.First = at
		}
		if at.After(o.Last) {
			o.Last = at
		}
	}
	out := make([]ObservedAssumption, 0, len(agg))
	for _, o := range agg {
		out = append(out, *o)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Role != out[j].Role {
			return out[i].Role < out[j].Role
		}
		return out[i].Caller < out[j].Caller
	})
	return out
}

// lookupAssumeEvents pages through AssumeRole events inside the window, stopping at maxEvents or the deadline. truncated says
// the history was not read to its start.
func lookupAssumeEvents(ctx context.Context, api CloudTrailAPI, since time.Time, maxEvents int, deadline time.Time) (events []cttypes.Event, truncated bool, err error) {
	var token *string
	for {
		if time.Now().After(deadline) || len(events) >= maxEvents {
			return events, true, nil
		}
		out, err := api.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
			LookupAttributes: []cttypes.LookupAttribute{{AttributeKey: cttypes.LookupAttributeKeyEventName, AttributeValue: awsv2.String("AssumeRole")}},
			StartTime:        awsv2.Time(since), EndTime: awsv2.Time(time.Now()), NextToken: token,
		})
		if err != nil {
			return events, false, err
		}
		events = append(events, out.Events...)
		if out.NextToken == nil || *out.NextToken == "" {
			return events, false, nil
		}
		token = out.NextToken
		time.Sleep(550 * time.Millisecond) // LookupEvents allows 2 requests per second per account and Region
	}
}

// CollectAssumeRoleActivity reads who assumed which role from CloudTrail event history, per scanned account and Region, and
// returns one OBSERVED_ASSUME_ROLE edge per caller and role. It turns "can assume" into "did assume". It never changes an
// allow or deny decision. The window, the event cap and the time budget are bounded, and a Region that hit one is partial.
func CollectAssumeRoleActivity(ctx context.Context, cfg *config.Config, accounts []Account, now time.Time) ([]models.AssetNode, []models.Relationship, error) {
	mode, explicit, err := config.ResolveRegionMode(cfg)
	if err != nil {
		return nil, nil, err
	}
	days := cfg.Scan.AssumeRoleActivityDays
	if days <= 0 || days > 90 {
		days = 30
	}
	budget := time.Duration(cfg.Scan.AssumeRoleActivitySeconds) * time.Second
	if budget <= 0 {
		budget = 120 * time.Second
	}
	since := now.AddDate(0, 0, -days)
	var assets []models.AssetNode
	var mu sync.Mutex
	var all []ObservedAssumption
	for _, account := range accounts {
		if account.Session == nil {
			continue
		}
		var plan RegionDiscoveryResult
		if mode == config.RegionModeAuto {
			plan = describeAccountRegions(ctx, account)
		} else {
			plan = explicitRegionPlan(account.ID, mode, explicit)
		}
		if plan.Status != "succeeded" {
			continue
		}
		deadline := time.Now().Add(budget)
		var wg sync.WaitGroup
		for _, region := range plan.Selected {
			wg.Add(1)
			go func(region string) {
				defer wg.Done()
				regional := account.Session.Copy()
				regional.Region = region
				api := cloudtrail.NewFromConfig(regional)
				events, truncated, err := lookupAssumeEvents(ctx, api, since, 5000, deadline)
				mu.Lock()
				defer mu.Unlock()
				all = append(all, ParseAssumeEvents(events)...)
				switch {
				case err != nil:
					status, detail := serviceStatus(err)
					assets = append(assets, CollectionStatus(account.ID, region, "assume_activity", "regional", status, detail))
				case truncated:
					assets = append(assets, CollectionStatus(account.ID, region, "assume_activity", "regional", "partial", "stopped at the event cap or the time budget; older events were not read"))
				default:
					assets = append(assets, CollectionStatus(account.ID, region, "assume_activity", "regional", "succeeded", ""))
				}
			}(region)
		}
		wg.Wait()
	}
	return assets, ObservedAssumptionEdges(all, days, now), nil
}

// ObservedAssumptionEdges merges per-Region records (the same caller and role in two Regions) into one edge each.
func ObservedAssumptionEdges(obs []ObservedAssumption, days int, collected time.Time) []models.Relationship {
	type key struct{ caller, role string }
	merged := map[key]*ObservedAssumption{}
	for _, o := range obs {
		k := key{o.Caller, o.Role}
		m := merged[k]
		if m == nil {
			c := o
			merged[k] = &c
			continue
		}
		m.Count += o.Count
		if o.First.Before(m.First) {
			m.First = o.First
		}
		if o.Last.After(m.Last) {
			m.Last = o.Last
		}
	}
	var rels []models.Relationship
	for k, o := range merged {
		rels = append(rels, models.Relationship{
			SourceARN: k.caller, TargetARN: k.role, RelType: models.RelObservedAssumeRole,
			Properties: map[string]any{
				"count": o.Count, "first_seen": o.First.UTC().Format(time.RFC3339), "last_seen": o.Last.UTC().Format(time.RFC3339),
				"caller_type": o.CallerType, "window_days": days, "collected_at": collected.UTC().Format(time.RFC3339),
				"source_api": "cloudtrail:LookupEvents",
				"note":       "Seen in CloudTrail management event history inside the window. It shows the call was made; it is not an authorization decision, and a missing edge does not show the call was never made.",
			},
		})
	}
	sort.Slice(rels, func(i, j int) bool {
		if rels[i].TargetARN != rels[j].TargetARN {
			return rels[i].TargetARN < rels[j].TargetARN
		}
		return rels[i].SourceARN < rels[j].SourceARN
	})
	return rels
}
