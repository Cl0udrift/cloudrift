package collectors

import (
	"context"
	"errors"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type fakeRegions struct {
	out  *ec2.DescribeRegionsOutput
	err  error
	all  *bool
	host string
}

func (f *fakeRegions) DescribeRegions(_ context.Context, in *ec2.DescribeRegionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	opts := &ec2.Options{}
	for _, fn := range optFns {
		fn(opts)
	}
	f.all = in.AllRegions
	f.host = opts.Region
	return f.out, f.err
}

func region(name, opt string) ec2types.Region {
	return ec2types.Region{RegionName: awsv2.String(name), OptInStatus: awsv2.String(opt)}
}

func TestDiscoverEnabledRegions_OptInAndPartition(t *testing.T) {
	fake := &fakeRegions{out: &ec2.DescribeRegionsOutput{Regions: []ec2types.Region{
		region("us-east-1", optInNotRequired),
		region("us-west-2", optInOptedIn),
		region("af-south-1", optInNotOptedIn),
		region("ap-east-1", "something-new"),
		region("us-east-1", optInNotRequired),
		region("us-gov-west-1", optInNotRequired),
	}}}
	got := DiscoverEnabledRegions(context.Background(), "111111111111", awsv2.Config{Region: "us-east-1"}, fake)
	if got.Status != "succeeded" || got.Partition != "aws" || fake.host != "us-east-1" || fake.all == nil || !*fake.all {
		t.Fatalf("%+v host %s", got, fake.host)
	}
	if len(got.Selected) != 2 || got.Selected[0] != "us-east-1" || got.Selected[1] != "us-west-2" {
		t.Fatalf("selected %v", got.Selected)
	}
	if len(got.NotEnabled) != 1 || got.NotEnabled[0] != "af-south-1" {
		t.Fatalf("disabled %v", got.NotEnabled)
	}
	if len(got.UnknownOptIn) != 1 || got.UnknownOptIn[0] != "ap-east-1" {
		t.Fatalf("unknown %v", got.UnknownOptIn)
	}
}

func TestDiscoverEnabledRegions_GovCloudDoesNotSelectCommercial(t *testing.T) {
	fake := &fakeRegions{out: &ec2.DescribeRegionsOutput{Regions: []ec2types.Region{
		region("us-east-1", optInNotRequired),
		region("us-gov-west-1", optInNotRequired),
	}}}
	got := DiscoverEnabledRegions(context.Background(), "111", awsv2.Config{Region: "us-gov-west-1"}, fake)
	if got.Partition != "aws-us-gov" || fake.host != "us-gov-west-1" || len(got.Selected) != 1 || got.Selected[0] != "us-gov-west-1" {
		t.Fatalf("%+v host %s", got, fake.host)
	}
}

func TestDiscoverEnabledRegions_FailureDoesNotSelectDefault(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		out  *ec2.DescribeRegionsOutput
		want string
	}{
		{"denied", errors.New("AccessDenied"), nil, "access_denied"},
		{"expired", errors.New("ExpiredToken"), nil, "expired"},
		{"throttle", errors.New("Throttling"), nil, "throttled"},
		{"timeout", context.DeadlineExceeded, nil, "cancelled"},
		{"empty", nil, &ec2.DescribeRegionsOutput{}, "empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := DiscoverEnabledRegions(context.Background(), "111", awsv2.Config{Region: "us-east-1"}, &fakeRegions{out: tc.out, err: tc.err})
			if got.Status != "failed" || got.Error != tc.want || len(got.Selected) != 0 {
				t.Fatalf("%+v", got)
			}
		})
	}
}

func BenchmarkRegionPlanning(b *testing.B) {
	regions := make([]ec2types.Region, 0, 32)
	for i := 0; i < 32; i++ {
		regions = append(regions, region("us-east-1", optInNotRequired))
	}
	regions[0] = region("us-east-1", optInNotRequired)
	regions[1] = region("us-west-2", optInOptedIn)
	regions[2] = region("af-south-1", optInNotOptedIn)
	fake := &fakeRegions{out: &ec2.DescribeRegionsOutput{Regions: regions}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got := DiscoverEnabledRegions(context.Background(), "111111111111", awsv2.Config{Region: "us-east-1"}, fake)
		if got.Status != "succeeded" || len(got.Selected) != 2 {
			b.Fatalf("%+v", got)
		}
	}
}

func TestExplicitRegionPlan_RejectsMixedPartitions(t *testing.T) {
	got := explicitRegionPlan("111", "explicit", []string{"us-east-1", "us-gov-west-1"})
	if got.Status != "failed" || got.Error != "partition" || len(got.Selected) != 0 {
		t.Fatalf("%+v", got)
	}
	ok := explicitRegionPlan("111", "explicit", []string{"eu-west-1"})
	node := regionDiscoveryAsset(ok)
	if node.Properties["evidence_origin"] != "configuration" || node.Properties["selected_regions"] != "eu-west-1" {
		t.Fatalf("%+v", node.Properties)
	}
	if time.Since(ok.Timestamp) > time.Minute {
		t.Fatal("timestamp was not recorded")
	}
}
