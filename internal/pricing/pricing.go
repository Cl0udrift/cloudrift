// Package pricing reads list prices from the AWS Price List API at scan time, and keeps them in a small cache beside
// the scans. No price is written into the code: a price that cannot be read is reported as unavailable, never
// replaced with a guess.
package pricing

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	awspricing "github.com/aws/aws-sdk-go-v2/service/pricing"
	pricingtypes "github.com/aws/aws-sdk-go-v2/service/pricing/types"
)

// HoursPerMonth is the month AWS uses to turn an hourly price into a monthly one.
const HoursPerMonth = 730

const (
	cacheFile = "price-cache.json"
	cacheTTL  = 30 * 24 * time.Hour
	maxPages  = 5
)

// Prices is what the unused-resource check needs. Every method says whether it found a price.
type Prices interface {
	// EBSGBMonth is the price of one GB-month of provisioned storage of a volume type (gp3, io2, ...).
	EBSGBMonth(ctx context.Context, region, volumeType string) (float64, bool)
	// LoadBalancerMonth is the fixed hourly charge of one load balancer for a month. It excludes traffic charges.
	LoadBalancerMonth(ctx context.Context, region, lbType string) (float64, bool)
	// HostedZoneMonth is the monthly price of one Route 53 hosted zone, at the first tier.
	HostedZoneMonth(ctx context.Context) (float64, bool)
	// Source says where the figures came from and when, for the finding to show.
	Source() string
}

// API is the part of the Price List client used here.
type API interface {
	GetProducts(context.Context, *awspricing.GetProductsInput, ...func(*awspricing.Options)) (*awspricing.GetProductsOutput, error)
}

// Live reads prices from the Price List API and caches each one for 30 days.
type Live struct {
	api      API
	cacheDir string
	mu       sync.Mutex
	prices   map[string]float64
	fetched  time.Time
	loaded   bool
}

// New builds a client. The Price List API is served from a few Regions; cfg is moved to one of them.
func New(cfg awsv2.Config, cacheDir string) *Live {
	cfg.Region = "us-east-1"
	return NewWithAPI(awspricing.NewFromConfig(cfg), cacheDir)
}

func NewWithAPI(api API, cacheDir string) *Live {
	return &Live{api: api, cacheDir: cacheDir, prices: map[string]float64{}}
}

func (l *Live) Source() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	when := l.fetched
	if when.IsZero() {
		when = time.Now()
	}
	return "AWS list price (Price List API), read " + when.UTC().Format("2006-01-02")
}

type cacheDoc struct {
	FetchedAt time.Time          `json:"fetched_at"`
	Prices    map[string]float64 `json:"prices"`
}

func (l *Live) load() {
	if l.loaded {
		return
	}
	l.loaded = true
	raw, err := os.ReadFile(filepath.Join(l.cacheDir, cacheFile))
	if err != nil {
		return
	}
	var d cacheDoc
	if json.Unmarshal(raw, &d) != nil || time.Since(d.FetchedAt) > cacheTTL {
		return
	}
	l.prices, l.fetched = d.Prices, d.FetchedAt
	if l.prices == nil {
		l.prices = map[string]float64{}
	}
}

func (l *Live) save() {
	if l.cacheDir == "" {
		return
	}
	raw, err := json.MarshalIndent(cacheDoc{FetchedAt: l.fetched, Prices: l.prices}, "", "  ")
	if err != nil {
		return
	}
	tmp := filepath.Join(l.cacheDir, cacheFile+".tmp")
	if os.WriteFile(tmp, raw, 0o600) == nil {
		_ = os.Rename(tmp, filepath.Join(l.cacheDir, cacheFile))
	}
}

// get returns a cached price or fetches it with fetch. A miss is not cached, so a later scan tries again.
func (l *Live) get(key string, fetch func() (float64, bool)) (float64, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.load()
	if p, ok := l.prices[key]; ok {
		return p, true
	}
	p, ok := fetch()
	if !ok {
		return 0, false
	}
	if l.fetched.IsZero() || time.Since(l.fetched) > cacheTTL {
		l.fetched = time.Now().UTC()
	}
	l.prices[key] = p
	l.save()
	return p, true
}

func filter(field, value string) pricingtypes.Filter {
	return pricingtypes.Filter{Type: pricingtypes.FilterTypeTermMatch, Field: awsv2.String(field), Value: awsv2.String(value)}
}

// products returns the matching price list entries, decoded.
func (l *Live) products(ctx context.Context, service string, filters ...pricingtypes.Filter) []product {
	var out []product
	var token *string
	for page := 0; page < maxPages; page++ {
		resp, err := l.api.GetProducts(ctx, &awspricing.GetProductsInput{ServiceCode: awsv2.String(service), Filters: filters, FormatVersion: awsv2.String("aws_v1"), NextToken: token})
		if err != nil {
			return out
		}
		for _, raw := range resp.PriceList {
			var p product
			if json.Unmarshal([]byte(raw), &p) == nil {
				out = append(out, p)
			}
		}
		if resp.NextToken == nil || *resp.NextToken == "" {
			break
		}
		token = resp.NextToken
	}
	return out
}

type product struct {
	Product struct {
		ProductFamily string            `json:"productFamily"`
		Attributes    map[string]string `json:"attributes"`
	} `json:"product"`
	Terms struct {
		OnDemand map[string]struct {
			PriceDimensions map[string]struct {
				Unit         string            `json:"unit"`
				BeginRange   string            `json:"beginRange"`
				Description  string            `json:"description"`
				PricePerUnit map[string]string `json:"pricePerUnit"`
			} `json:"priceDimensions"`
		} `json:"OnDemand"`
	} `json:"terms"`
}

// firstTierUSD is the on-demand USD price of the first pricing tier.
func (p product) firstTierUSD() (float64, bool) {
	for _, term := range p.Terms.OnDemand {
		for _, d := range term.PriceDimensions {
			if d.BeginRange != "" && d.BeginRange != "0" {
				continue
			}
			v, err := strconv.ParseFloat(d.PricePerUnit["USD"], 64)
			if err == nil && v > 0 {
				return v, true
			}
		}
	}
	return 0, false
}

func (l *Live) EBSGBMonth(ctx context.Context, region, volumeType string) (float64, bool) {
	volumeType = strings.ToLower(strings.TrimSpace(volumeType))
	return l.get("ebs|"+region+"|"+volumeType, func() (float64, bool) {
		for _, p := range l.products(ctx, "AmazonEC2", filter("productFamily", "Storage"), filter("volumeApiName", volumeType), filter("regionCode", region)) {
			if v, ok := p.firstTierUSD(); ok {
				return v, true
			}
		}
		return 0, false
	})
}

var lbFamily = map[string]string{"application": "Load Balancer-Application", "network": "Load Balancer-Network"}

func (l *Live) LoadBalancerMonth(ctx context.Context, region, lbType string) (float64, bool) {
	family, ok := lbFamily[strings.ToLower(lbType)]
	if !ok {
		return 0, false // gateway load balancers are priced differently and are not valued
	}
	return l.get("lb|"+region+"|"+strings.ToLower(lbType), func() (float64, bool) {
		for _, p := range l.products(ctx, "AWSELB", filter("productFamily", family), filter("regionCode", region)) {
			ut := p.Product.Attributes["usagetype"]
			if !strings.HasSuffix(ut, "LoadBalancerUsage") || strings.Contains(ut, "Outposts") || strings.Contains(ut, "TS-") {
				continue
			}
			if v, ok := p.firstTierUSD(); ok {
				return v * HoursPerMonth, true
			}
		}
		return 0, false
	})
}

func (l *Live) HostedZoneMonth(ctx context.Context) (float64, bool) {
	return l.get("r53|hostedzone", func() (float64, bool) {
		for _, p := range l.products(ctx, "AmazonRoute53", filter("productFamily", "DNS Zone")) {
			if p.Product.Attributes["usagetype"] != "HostedZone" {
				continue
			}
			if v, ok := p.firstTierUSD(); ok {
				return v, true
			}
		}
		return 0, false
	})
}

// Unavailable is a Prices that finds nothing, used when no credentials can reach the Price List API.
type Unavailable struct{ Reason string }

func (u Unavailable) EBSGBMonth(context.Context, string, string) (float64, bool) { return 0, false }
func (u Unavailable) LoadBalancerMonth(context.Context, string, string) (float64, bool) {
	return 0, false
}
func (u Unavailable) HostedZoneMonth(context.Context) (float64, bool) { return 0, false }
func (u Unavailable) Source() string {
	return fmt.Sprintf("prices unavailable (%s)", u.Reason)
}

// Lazy builds its price source on first use, so a scan with nothing to price never touches AWS for prices.
type Lazy struct {
	once  sync.Once
	build func() Prices
	inner Prices
}

func NewLazy(build func() Prices) *Lazy { return &Lazy{build: build} }

func (l *Lazy) get() Prices {
	l.once.Do(func() { l.inner = l.build() })
	return l.inner
}

func (l *Lazy) EBSGBMonth(ctx context.Context, region, volumeType string) (float64, bool) {
	return l.get().EBSGBMonth(ctx, region, volumeType)
}
func (l *Lazy) LoadBalancerMonth(ctx context.Context, region, lbType string) (float64, bool) {
	return l.get().LoadBalancerMonth(ctx, region, lbType)
}
func (l *Lazy) HostedZoneMonth(ctx context.Context) (float64, bool) {
	return l.get().HostedZoneMonth(ctx)
}
func (l *Lazy) Source() string { return l.get().Source() }
