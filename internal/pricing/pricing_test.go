package pricing

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	awspricing "github.com/aws/aws-sdk-go-v2/service/pricing"
)

type fakeAPI struct {
	calls int
	lists map[string][]string // by service code
}

func (f *fakeAPI) GetProducts(_ context.Context, in *awspricing.GetProductsInput, _ ...func(*awspricing.Options)) (*awspricing.GetProductsOutput, error) {
	f.calls++
	return &awspricing.GetProductsOutput{PriceList: f.lists[*in.ServiceCode]}, nil
}

func entry(family, usagetype, begin, usd string) string {
	return `{"product":{"productFamily":"` + family + `","attributes":{"usagetype":"` + usagetype + `"}},"terms":{"OnDemand":{"t":{"priceDimensions":{"d":{"unit":"x","beginRange":"` + begin + `","pricePerUnit":{"USD":"` + usd + `"}}}}}}}`
}

func TestPricesAreReadFromTheListAndCached(t *testing.T) {
	dir := t.TempDir()
	api := &fakeAPI{lists: map[string][]string{
		"AmazonEC2":     {entry("Storage", "EBS:VolumeUsage.gp3", "0", "0.08")},
		"AWSELB":        {entry("Load Balancer-Application", "LCUUsage", "0", "0.008"), entry("Load Balancer-Application", "Outposts-LoadBalancerUsage", "0", "0.9"), entry("Load Balancer-Application", "LoadBalancerUsage", "0", "0.0225")},
		"AmazonRoute53": {entry("DNS Zone", "Global-RRSets", "0", "0.0015"), entry("DNS Zone", "HostedZone", "0", "0.5")},
	}}
	p := NewWithAPI(api, dir)
	ctx := context.Background()
	if v, ok := p.EBSGBMonth(ctx, "us-east-1", "gp3"); !ok || v != 0.08 {
		t.Fatalf("ebs %v %v", v, ok)
	}
	if v, ok := p.LoadBalancerMonth(ctx, "us-east-1", "application"); !ok || v < 16.4 || v > 16.5 {
		t.Fatalf("an hourly price becomes a month of 730 hours, skipping traffic and Outposts entries: %v %v", v, ok)
	}
	if v, ok := p.HostedZoneMonth(ctx); !ok || v != 0.5 {
		t.Fatalf("zone %v %v", v, ok)
	}
	if _, ok := p.LoadBalancerMonth(ctx, "us-east-1", "gateway"); ok {
		t.Fatal("a gateway load balancer is not valued")
	}
	before := api.calls
	again := NewWithAPI(api, dir)
	if v, ok := again.EBSGBMonth(ctx, "us-east-1", "gp3"); !ok || v != 0.08 || api.calls != before {
		t.Fatalf("the second run must use the cache: %v calls %d->%d", v, before, api.calls)
	}
	if _, err := os.Stat(filepath.Join(dir, "price-cache.json")); err != nil {
		t.Fatal("cache file missing")
	}
}

func TestAMissingPriceIsUnavailableNotZeroAndNotCached(t *testing.T) {
	api := &fakeAPI{lists: map[string][]string{}}
	p := NewWithAPI(api, t.TempDir())
	if v, ok := p.EBSGBMonth(context.Background(), "us-east-1", "gp3"); ok || v != 0 {
		t.Fatal("no entry means no price")
	}
	api.lists["AmazonEC2"] = []string{entry("Storage", "x", "0", "0.1")}
	if v, ok := p.EBSGBMonth(context.Background(), "us-east-1", "gp3"); !ok || v != 0.1 {
		t.Fatal("a miss must not be remembered")
	}
}
