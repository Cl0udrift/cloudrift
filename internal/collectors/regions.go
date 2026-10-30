package collectors

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/Zero0x00/cloudrift/internal/models"
	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

const (
	regionDiscoveryCollector = "region_discovery"
	optInNotRequired         = "opt-in-not-required"
	optInOptedIn             = "opted-in"
	optInNotOptedIn          = "not-opted-in"
)

// RegionAPI is the EC2 surface used to list Regions for one assumed account.
type RegionAPI interface {
	DescribeRegions(ctx context.Context, params *ec2.DescribeRegionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error)
}

// RegionObservation is one Region returned by DescribeRegions.
type RegionObservation struct {
	Name       string
	OptIn      string
	Applicable bool
	Partition  string
}

// RegionDiscoveryResult is the per-account outcome of enabled-Region discovery.
type RegionDiscoveryResult struct {
	AccountID    string
	Partition    string
	Status       string
	Timestamp    time.Time
	Mode         string
	Error        string
	Regions      []RegionObservation
	Selected     []string
	NotEnabled   []string
	UnknownOptIn []string
}

// DiscoverEnabledRegions calls DescribeRegions with the account session.
// Eligible Regions are opt-in-not-required and opted-in. not-opted-in and
// unknown opt-in statuses are retained and are not scanned. The endpoint
// Region is only the API host; a failed call does not become a workload Region.
func DiscoverEnabledRegions(ctx context.Context, accountID string, cfg awsv2.Config, client RegionAPI) RegionDiscoveryResult {
	result := RegionDiscoveryResult{
		AccountID: accountID,
		Partition: partitionOf(cfg.Region),
		Status:    "failed",
		Timestamp: time.Now().UTC(),
		Mode:      "auto",
	}
	if client == nil {
		result.Error = "endpoint"
		return result
	}
	endpoint := discoveryEndpoint(cfg.Region)
	out, err := client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		AllRegions: awsv2.Bool(true),
	}, func(o *ec2.Options) { o.Region = endpoint })
	if err != nil {
		result.Error = regionErrorCategory(err)
		return result
	}
	if out == nil || out.Regions == nil {
		result.Error = "empty"
		return result
	}
	seen := map[string]struct{}{}
	for _, region := range out.Regions {
		name := strings.TrimSpace(awsv2.ToString(region.RegionName))
		if name == "" {
			result.Error = "malformed"
			result.Regions = nil
			result.Selected = nil
			return result
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		part := partitionOf(name)
		if part != result.Partition {
			continue
		}
		opt := strings.TrimSpace(awsv2.ToString(region.OptInStatus))
		obs := RegionObservation{Name: name, OptIn: opt, Partition: part}
		switch opt {
		case optInNotRequired, optInOptedIn:
			obs.Applicable = true
			result.Selected = append(result.Selected, name)
		case optInNotOptedIn:
			result.NotEnabled = append(result.NotEnabled, name)
		default:
			result.UnknownOptIn = append(result.UnknownOptIn, name)
		}
		result.Regions = append(result.Regions, obs)
	}
	sort.Strings(result.Selected)
	sort.Strings(result.NotEnabled)
	sort.Strings(result.UnknownOptIn)
	sort.Slice(result.Regions, func(i, j int) bool { return result.Regions[i].Name < result.Regions[j].Name })
	result.Status = "succeeded"
	result.Error = ""
	return result
}

func discoveryEndpoint(sessionRegion string) string {
	switch partitionOf(sessionRegion) {
	case "aws-us-gov":
		if sessionRegion != "" {
			return sessionRegion
		}
		return "us-gov-west-1"
	case "aws-cn":
		if sessionRegion != "" {
			return sessionRegion
		}
		return "cn-north-1"
	default:
		if sessionRegion != "" {
			return sessionRegion
		}
		return "us-east-1"
	}
}

func partitionOf(region string) string {
	switch {
	case strings.HasPrefix(region, "us-gov-"):
		return "aws-us-gov"
	case strings.HasPrefix(region, "cn-"):
		return "aws-cn"
	default:
		return "aws"
	}
}

func regionErrorCategory(err error) string {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "cancelled"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "accessdenied"), strings.Contains(msg, "unauthorized"), strings.Contains(msg, "not authorized"):
		return "access_denied"
	case strings.Contains(msg, "expired"):
		return "expired"
	case strings.Contains(msg, "throttl"), strings.Contains(msg, "requestlimit"):
		return "throttled"
	case strings.Contains(msg, "endpointdisabled"), strings.Contains(msg, "could not resolve"):
		return "endpoint"
	default:
		return "endpoint"
	}
}

func explicitRegionPlan(accountID, mode string, regions []string) RegionDiscoveryResult {
	result := RegionDiscoveryResult{
		AccountID: accountID,
		Partition: "aws",
		Status:    "succeeded",
		Timestamp: time.Now().UTC(),
		Mode:      mode,
		Selected:  append([]string(nil), regions...),
	}
	if len(regions) > 0 {
		result.Partition = partitionOf(regions[0])
	}
	for _, region := range regions {
		if partitionOf(region) != result.Partition {
			result.Status = "failed"
			result.Error = "partition"
			result.Selected = nil
			return result
		}
		result.Regions = append(result.Regions, RegionObservation{
			Name: region, OptIn: "explicit", Applicable: true, Partition: result.Partition,
		})
	}
	return result
}

func regionDiscoveryAsset(result RegionDiscoveryResult) models.AssetNode {
	selected := strings.Join(result.Selected, ",")
	notEnabled := strings.Join(result.NotEnabled, ",")
	unknown := strings.Join(result.UnknownOptIn, ",")
	detail := result.Mode
	if result.Error != "" {
		detail = result.Error
	}
	node := CollectionStatus(result.AccountID, "", regionDiscoveryCollector, "account", result.Status, detail)
	origin := "configuration"
	if result.Mode == "auto" {
		origin = "ec2:DescribeRegions"
	}
	node.Properties["partition"] = result.Partition
	node.Properties["region_mode"] = result.Mode
	node.Properties["selected_regions"] = selected
	node.Properties["not_enabled"] = notEnabled
	node.Properties["unknown_opt_in"] = unknown
	node.Properties["error_category"] = result.Error
	node.Properties["discovered_at"] = result.Timestamp.UTC().Format(time.RFC3339)
	node.Properties["evidence_origin"] = origin
	return node
}

// Keep the EC2 type referenced so a SDK upgrade that drops Region fields fails here.
var _ = ec2types.Region{}
