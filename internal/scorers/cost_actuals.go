package scorers

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	cetypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"

	"github.com/Zero0x00/cloudrift/internal/collectors"
	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// Real money from the customer's own billing, used two ways: what an account spends in a month (the scale of what an
// administrator can reach) and what an unused resource actually cost over the last two weeks (replacing the
// list-price estimate). Both read Cost Explorer, which charges per request, so each scan makes a handful of calls and
// only when "attach account spend" is on.

// CEResourcesAPI is the resource-level call. It needs resource-level data switched on in the payer account.
type CEResourcesAPI interface {
	GetCostAndUsageWithResources(ctx context.Context, params *costexplorer.GetCostAndUsageWithResourcesInput, optFns ...func(*costexplorer.Options)) (*costexplorer.GetCostAndUsageWithResourcesOutput, error)
}

var newCEResourcesClient = func(cfg awsv2.Config) CEResourcesAPI { return costexplorer.NewFromConfig(cfg) }

const (
	maxCEPages       = 5
	topServicesKept  = 5
	resourceLookback = 14 // days: the most Cost Explorer keeps at resource level
)

// ServiceSpend is one service's spend within an account.
type ServiceSpend struct {
	Service string  `json:"service"`
	USD     float64 `json:"usd"`
}

// AccountSpendAssets reads each account's spend for the last full calendar month and returns it as scan evidence, so
// the dashboard can show it without calling AWS. Tax, credits and refunds are left out: they are not what the
// account runs. Nil when the setting is off or Cost Explorer cannot be read.
func AccountSpendAssets(ctx context.Context, cfg config.Config, accountIDs []string) []models.AssetNode {
	if !cfg.Cost.UseCUR || len(accountIDs) == 0 {
		return nil
	}
	awsCfg, err := loadAWSCfgForCE(ctx, cfg)
	if err != nil {
		warnCE("could not load AWS config for account spend", err)
		return []models.AssetNode{billingStatus("failed", "no credentials could be loaded for billing")}
	}
	assets, err := accountSpendFrom(ctx, newCostExplorerClient(awsCfg), accountIDs, ceNowUTC())
	if err != nil {
		return []models.AssetNode{billingStatus("failed", billingErrorText(err))}
	}
	return append(assets, billingStatus("succeeded", ""))
}

// billingStatus records whether billing could be read, as a collector like any other, so the dashboard can say so.
func billingStatus(status, detail string) models.AssetNode {
	return collectors.CollectionStatus("", "", "cost_explorer", "global", status, detail)
}

func billingErrorText(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "AccessDenied") || strings.Contains(msg, "not authorized"):
		return "Cost Explorer refused the request. The billing profile needs ce:GetCostAndUsage."
	case strings.Contains(msg, "security token") || strings.Contains(msg, "expired") || strings.Contains(msg, "UnrecognizedClient"):
		return "Cost Explorer rejected the credentials. Check the AWS profile the scan runs with."
	case strings.Contains(msg, "Missing Region"):
		return "Cost Explorer had no Region to call."
	}
	return "Cost Explorer request failed: " + msg
}

func accountSpendFrom(ctx context.Context, client CostExplorerAPI, accountIDs []string, now time.Time) ([]models.AssetNode, error) {
	end := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	start := end.AddDate(0, -1, 0)
	s, e := start.Format("2006-01-02"), end.Format("2006-01-02")
	filter := &cetypes.Expression{And: []cetypes.Expression{
		{Dimensions: &cetypes.DimensionValues{Key: cetypes.DimensionLinkedAccount, Values: accountIDs}},
		{Not: &cetypes.Expression{Dimensions: &cetypes.DimensionValues{Key: cetypes.DimensionRecordType, Values: []string{"Tax", "Credit", "Refund"}}}},
	}}
	spend := map[string]map[string]float64{}
	var token *string
	for page := 0; page < maxCEPages; page++ {
		out, err := client.GetCostAndUsage(ctx, &costexplorer.GetCostAndUsageInput{
			TimePeriod: &cetypes.DateInterval{Start: &s, End: &e}, Granularity: cetypes.GranularityMonthly, Metrics: []string{"UnblendedCost"}, Filter: filter,
			GroupBy:       []cetypes.GroupDefinition{{Type: cetypes.GroupDefinitionTypeDimension, Key: awsv2.String("LINKED_ACCOUNT")}, {Type: cetypes.GroupDefinitionTypeDimension, Key: awsv2.String("SERVICE")}},
			NextPageToken: token,
		})
		if err != nil {
			warnCE("account spend request failed", err)
			return nil, err
		}
		for _, r := range out.ResultsByTime {
			for _, g := range r.Groups {
				if len(g.Keys) < 2 || g.Metrics["UnblendedCost"].Amount == nil {
					continue
				}
				v, err := parseAmount(*g.Metrics["UnblendedCost"].Amount)
				if err != nil {
					continue
				}
				if spend[g.Keys[0]] == nil {
					spend[g.Keys[0]] = map[string]float64{}
				}
				spend[g.Keys[0]][g.Keys[1]] += v
			}
		}
		if out.NextPageToken == nil || *out.NextPageToken == "" {
			break
		}
		token = out.NextPageToken
	}
	var assets []models.AssetNode
	for _, acct := range accountIDs {
		services := spend[acct]
		var total float64
		list := make([]ServiceSpend, 0, len(services))
		for svc, v := range services {
			total += v
			list = append(list, ServiceSpend{Service: svc, USD: v})
		}
		sort.Slice(list, func(i, j int) bool { return list[i].USD > list[j].USD })
		if len(list) > topServicesKept {
			list = list[:topServicesKept]
		}
		top := make([]any, 0, len(list))
		for _, x := range list {
			top = append(top, map[string]any{"service": x.Service, "usd": x.USD})
		}
		assets = append(assets, models.AssetNode{
			ARN: "arn:cloudrift:account-spend:::" + acct, AssetType: models.AssetAccountSpend, Name: "spend " + acct, AccountID: acct, Region: "global",
			Properties: map[string]any{"monthly_usd": total, "period_start": s, "period_end": e, "top_services": top,
				"source": "AWS Cost Explorer, unblended cost without tax, credits and refunds, " + start.Format("January 2006")},
		})
	}
	return assets, nil
}

var moneyInTitle = regexp.MustCompile(`about \$[0-9][0-9,]*(\.[0-9]+)? a month`)

// wasteServices maps a kind of unused resource to the Cost Explorer service that bills it, and how the billed
// resource ID is matched to the finding.
var wasteServices = map[string]struct {
	service string
	match   func(f models.Finding, id string) bool
}{
	"unattached_volume": {"EC2 - Other", func(f models.Finding, id string) bool {
		v, _ := f.Evidence["volume_id"].(string)
		return v != "" && strings.Contains(id, v)
	}},
	"idle_load_balancer": {"Amazon Elastic Load Balancing", func(f models.Finding, id string) bool {
		if f.AffectedARN == "" {
			return false
		}
		suffix := f.AffectedARN
		if i := strings.Index(suffix, "loadbalancer/"); i >= 0 {
			suffix = suffix[i:]
		}
		return id == f.AffectedARN || strings.HasSuffix(id, suffix)
	}},
	"empty_hosted_zone": {"Amazon Route 53", func(f models.Finding, id string) bool {
		z, _ := f.Evidence["zone_id"].(string)
		return z != "" && strings.Contains(id, z)
	}},
}

// Actuals statuses recorded on each unused-resource finding.
const (
	ActualsOff        = "off"
	ActualsActual     = "actual"
	ActualsNoMatch    = "enabled_no_match"
	ActualsNotEnabled = "not_enabled"
	ActualsFailed     = "failed"
)

// EnrichWasteActuals replaces the list-price estimate of each unused resource with what it cost over the last
// 14 days, where Cost Explorer has resource-level data. Where it does not, the estimate stays and the finding says
// why, including that resource-level data is switched on in the payer account's Cost Explorer settings.
func EnrichWasteActuals(ctx context.Context, findings []models.Finding, cfg config.Config) []models.Finding {
	if !cfg.Cost.UseCUR || !hasWaste(findings) {
		return setActualsStatus(findings, ActualsOff, "")
	}
	awsCfg, err := loadAWSCfgForCE(ctx, cfg)
	if err != nil {
		warnCE("could not load AWS config for resource costs", err)
		return setActualsStatus(findings, ActualsFailed, "no credentials for Cost Explorer")
	}
	return enrichWasteActuals(ctx, newCEResourcesClient(awsCfg), findings, ceNowUTC())
}

func hasWaste(findings []models.Finding) bool {
	for _, f := range findings {
		if f.Module == models.ModuleUnusedResource {
			return true
		}
	}
	return false
}

func setActualsStatus(findings []models.Finding, status, detail string) []models.Finding {
	out := append([]models.Finding(nil), findings...)
	for i := range out {
		if out[i].Module != models.ModuleUnusedResource {
			continue
		}
		ev := map[string]any{}
		for k, v := range out[i].Evidence {
			ev[k] = v
		}
		ev["actuals_status"] = status
		if detail != "" {
			ev["actuals_detail"] = detail
		}
		out[i].Evidence = ev
	}
	return out
}

func enrichWasteActuals(ctx context.Context, client CEResourcesAPI, findings []models.Finding, now time.Time) []models.Finding {
	end := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	start := end.AddDate(0, 0, -resourceLookback)
	s, e := start.Format("2006-01-02"), end.Format("2006-01-02")

	// One request per service that has a finding.
	bySvc := map[string]map[string]float64{}
	for _, f := range findings {
		if f.Module != models.ModuleUnusedResource {
			continue
		}
		kind, _ := f.Evidence["waste_kind"].(string)
		w, ok := wasteServices[kind]
		if !ok || bySvc[w.service] != nil {
			continue
		}
		costs := map[string]float64{}
		var token *string
		for page := 0; page < maxCEPages; page++ {
			out, err := client.GetCostAndUsageWithResources(ctx, &costexplorer.GetCostAndUsageWithResourcesInput{
				TimePeriod: &cetypes.DateInterval{Start: &s, End: &e}, Granularity: cetypes.GranularityDaily, Metrics: []string{"UnblendedCost"},
				Filter:        &cetypes.Expression{Dimensions: &cetypes.DimensionValues{Key: cetypes.DimensionService, Values: []string{w.service}}},
				GroupBy:       []cetypes.GroupDefinition{{Type: cetypes.GroupDefinitionTypeDimension, Key: awsv2.String("RESOURCE_ID")}},
				NextPageToken: token,
			})
			if err != nil {
				status, detail := classifyCEError(err)
				return setActualsStatus(findings, status, detail)
			}
			for _, r := range out.ResultsByTime {
				for _, g := range r.Groups {
					if len(g.Keys) == 0 || g.Metrics["UnblendedCost"].Amount == nil {
						continue
					}
					if v, err := parseAmount(*g.Metrics["UnblendedCost"].Amount); err == nil {
						costs[g.Keys[0]] += v
					}
				}
			}
			if out.NextPageToken == nil || *out.NextPageToken == "" {
				break
			}
			token = out.NextPageToken
		}
		bySvc[w.service] = costs
	}

	out := append([]models.Finding(nil), findings...)
	matched := 0
	for i := range out {
		f := out[i]
		if f.Module != models.ModuleUnusedResource {
			continue
		}
		kind, _ := f.Evidence["waste_kind"].(string)
		w := wasteServices[kind]
		ev := map[string]any{}
		for k, v := range f.Evidence {
			ev[k] = v
		}
		ev["actuals_status"] = ActualsNoMatch
		var sum float64
		found := false
		for id, v := range bySvc[w.service] {
			if w.match != nil && w.match(f, id) {
				sum += v
				found = true
			}
		}
		if found && sum > 0 {
			monthly := sum * (365.25 / 12) / resourceLookback
			if est, ok := ev["monthly_cost_usd"].(float64); ok {
				ev["estimate_usd"] = est
			}
			ev["cost_source"], ev["actual_14d_usd"] = "actual", sum
			ev["monthly_cost_usd"], ev["yearly_cost_usd"] = monthly, monthly*12
			ev["price_source"] = "AWS Cost Explorer, resource-level, last 14 days"
			ev["cost_basis"] = "actual billing over the last 14 days, scaled to a month"
			ev["actuals_status"] = ActualsActual
			out[i].MonthlyDirectCost = monthly
			out[i].Title = moneyInTitle.ReplaceAllLiteralString(f.Title, "about "+money(monthly)+" a month")
			matched++
		}
		out[i].Evidence = ev
	}
	_ = matched
	return out
}

// classifyCEError turns a Cost Explorer error into a status and a sentence a person can act on.
func classifyCEError(err error) (string, string) {
	msg := err.Error()
	if strings.Contains(msg, "opt-in") || strings.Contains(msg, "Resource-level data granularity") {
		return ActualsNotEnabled, "Cost Explorer resource-level data is switched off. A payer-account administrator can turn it on in Cost Explorer settings."
	}
	if strings.Contains(msg, "AccessDenied") {
		return ActualsFailed, "Cost Explorer refused the request; the credentials need ce:GetCostAndUsageWithResources."
	}
	return ActualsFailed, fmt.Sprintf("Cost Explorer request failed: %v", err)
}
