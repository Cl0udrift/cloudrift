package scorers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/pricing"
)

// Resources that cost money to hold and do nothing. Each finding carries its monthly cost, priced from the AWS list
// price for that resource's size and Region, and says where the price came from. A resource that cannot be priced is
// still listed, without a cost, and is never counted in a total.

// wasteID is stable across scans, so the diff and the age counts follow one resource.
func wasteID(kind, arn string) string {
	h := sha256.Sum256([]byte(string(models.ModuleUnusedResource) + "|" + kind + "|" + arn))
	return hex.EncodeToString(h[:])[:12]
}

func str(a models.AssetNode, key string) string { s, _ := a.Properties[key].(string); return s }

func intProp(a models.AssetNode, key string) int64 { n, _ := toInt(a.Properties[key]); return n }

func boolProp(a models.AssetNode, key string) bool { b, _ := a.Properties[key].(bool); return b }

type wasteItem struct {
	kind, arn, region, account, name string
	title, impact, recommendation    string
	cmd                              string
	monthly                          float64
	priced                           bool
	evidence                         map[string]any
}

func (w wasteItem) finding(source string) models.Finding {
	ev := w.evidence
	ev["resource_type"], ev["waste_kind"], ev["evidence_level"] = w.kind, w.kind, "verified"
	ev["currency"], ev["price_source"] = "USD", source
	if w.priced {
		ev["monthly_cost_usd"], ev["yearly_cost_usd"] = w.monthly, w.monthly*12
		ev["cost_basis"] = "estimate from list price; actual billing can differ with discounts and usage"
	} else {
		ev["price_source"] = "unavailable"
	}
	return models.Finding{
		ID: wasteID(w.kind, w.arn), Title: w.title, Severity: models.SeverityInfo, Module: models.ModuleUnusedResource, Claimability: models.ClaimUnknown,
		AffectedARN: w.arn, AccountID: w.account, Hostname: w.name, MonthlyDirectCost: w.monthly,
		Impact: w.impact, Recommendation: w.recommendation, RemediationCmd: w.cmd, Evidence: ev,
	}
}

func money(v float64) string { return fmt.Sprintf("$%.2f", v) }

// ScoreUnusedResources finds unattached volumes, load balancers with nothing behind them, and hosted zones with no
// records, and prices each. p may be nil, which prices nothing.
func ScoreUnusedResources(ctx context.Context, assets []models.AssetNode, p pricing.Prices) []models.Finding {
	if p == nil {
		p = pricing.Unavailable{Reason: "no price source"}
	}
	// DNS names that point at each load balancer: deleting one that is still named leaves a dangling record.
	pointers := map[string][]string{}
	for _, a := range assets {
		if a.AssetType == models.AssetDNSRecord {
			if v, _ := a.Properties["value"].(string); v != "" {
				k := strings.ToLower(strings.TrimSuffix(v, "."))
				pointers[k] = append(pointers[k], a.Name)
			}
		}
	}
	var items []wasteItem
	for _, a := range assets {
		switch a.AssetType {
		case models.AssetEBSVolume:
			if str(a, "state") != "available" {
				continue
			}
			size, vt := intProp(a, "size_gb"), str(a, "volume_type")
			it := wasteItem{kind: "unattached_volume", arn: a.ARN, region: a.Region, account: a.AccountID, name: a.Name,
				evidence: map[string]any{"volume_id": a.Name, "size_gb": size, "volume_type": vt, "encrypted": boolProp(a, "encrypted"), "region": a.Region, "cost_scope": "storage only; provisioned IOPS and snapshots are not included"}}
			desc := fmt.Sprintf("%d GB %s", size, vt)
			if price, ok := p.EBSGBMonth(ctx, a.Region, vt); ok {
				it.monthly, it.priced = float64(size)*price, true
				it.evidence["price_per_gb_month"] = price
				it.title = fmt.Sprintf("Unattached volume %s (%s) costs about %s a month", a.Name, desc, money(it.monthly))
			} else {
				it.title = fmt.Sprintf("Unattached volume %s (%s) is billed but could not be priced", a.Name, desc)
			}
			it.impact = "The volume is attached to no instance but is billed for its full size every month."
			if !boolProp(a, "encrypted") {
				it.impact += " It is not encrypted, so whatever it holds is stored in the clear."
			}
			it.recommendation = "Check that nobody plans to reattach it. Keep a snapshot if the data might matter, then delete the volume."
			it.cmd = fmt.Sprintf("# 1. Keep a copy if the data might matter. A snapshot of unused data usually costs less than the volume.\naws ec2 create-snapshot --volume-id %s --region %s --description \"before deleting unattached volume\"\n\n# 2. Delete the volume once you are sure.\naws ec2 delete-volume --volume-id %s --region %s", a.Name, a.Region, a.Name, a.Region)
			items = append(items, it)
		case models.AssetLoadBalancer:
			if str(a, "state") != "active" || !boolProp(a, "targets_complete") || intProp(a, "registered_targets") != 0 {
				continue
			}
			lbt := str(a, "lb_type")
			names := pointers[strings.ToLower(strings.TrimSuffix(str(a, "dns_name"), "."))]
			sort.Strings(names)
			it := wasteItem{kind: "idle_load_balancer", arn: a.ARN, region: a.Region, account: a.AccountID, name: a.Name,
				evidence: map[string]any{"lb_type": lbt, "target_groups": intProp(a, "target_groups"), "registered_targets": 0, "region": a.Region, "dns_records_pointing": names, "cost_scope": "the fixed hourly charge only; traffic charges are not included"}}
			if price, ok := p.LoadBalancerMonth(ctx, a.Region, lbt); ok {
				it.monthly, it.priced = price, true
				it.title = fmt.Sprintf("Load balancer %s has no targets and costs about %s a month", a.Name, money(price))
			} else {
				it.title = fmt.Sprintf("Load balancer %s has no targets and is billed, but could not be priced", a.Name)
			}
			it.impact = "A load balancer with nothing registered behind it serves nobody but is billed every hour."
			it.recommendation = "Confirm it is not about to be used."
			it.cmd = fmt.Sprintf("aws elbv2 delete-load-balancer --load-balancer-arn %s --region %s", a.ARN, a.Region)
			if len(names) > 0 {
				it.impact += fmt.Sprintf(" %d DNS %s still point at it.", len(names), map[bool]string{true: "name", false: "names"}[len(names) == 1])
				it.recommendation += " Remove or repoint the DNS names that still point at it first: deleting it would leave them dangling, which can be taken over."
			}
			items = append(items, it)
		case models.AssetHostedZone:
			if intProp(a, "record_count") > 2 {
				continue
			}
			it := wasteItem{kind: "empty_hosted_zone", arn: a.ARN, region: "global", account: a.AccountID, name: a.Name,
				evidence: map[string]any{"zone_id": str(a, "zone_id"), "record_count": intProp(a, "record_count"), "private": boolProp(a, "private"), "cost_scope": "the first-tier hosted zone price; queries are not included"}}
			if price, ok := p.HostedZoneMonth(ctx); ok {
				it.monthly, it.priced = price, true
				it.title = fmt.Sprintf("Hosted zone %s has no records and costs about %s a month", a.Name, money(price))
			} else {
				it.title = fmt.Sprintf("Hosted zone %s has no records and is billed, but could not be priced", a.Name)
			}
			it.impact = "The zone holds only its default name server and start-of-authority records but is billed monthly. An empty zone for a domain you own can also be a leftover of a delegation someone could reuse."
			it.recommendation = "Check that no registrar still points the domain's name servers at this zone, then delete it."
			it.cmd = fmt.Sprintf("aws route53 delete-hosted-zone --id %s", str(a, "zone_id"))
			items = append(items, it)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].monthly != items[j].monthly {
			return items[i].monthly > items[j].monthly
		}
		return items[i].arn < items[j].arn
	})
	out := make([]models.Finding, 0, len(items))
	for _, it := range items {
		out = append(out, it.finding(p.Source()))
	}
	return out
}
