package handlers

import (
	"strings"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/business"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// Putting risk into money, the way a risk register does: how likely times what it costs, as a range, from values the
// customer entered. Cloudrift supplies only what it can see: what an identity can reach and how serious a finding is.

var adminReachCategories = map[string]bool{
	"user_administrative_access":                  true,
	"workload_runs_as_administrative_role":        true,
	"weak_credential_reaches_administrative_role": true,
	"privilege_escalation":                        true,
}

// dataStoreTypes are what a breach is counted against.
var dataStoreTypes = map[models.AssetType]bool{models.AssetS3Bucket: true, models.AssetRDSInstance: true, models.AssetSecret: true}

type lossRange struct{ low, high float64 }

func isAdminReach(f models.Finding) bool {
	if cat, _ := f.Evidence["issue_category"].(string); adminReachCategories[cat] {
		return true
	}
	if v, _ := f.Evidence["is_admin"].(bool); v {
		return true
	}
	return false
}

func isPublicBucket(f models.Finding) bool {
	public, _ := f.Evidence["is_public"].(bool)
	t, _ := f.Evidence["resource_type"].(string)
	return public && t == "s3_bucket"
}

func isTakeover(f models.Finding) bool {
	return f.Module == models.ModuleOrphanedEdge && (f.Claimability == models.ClaimReclaimable || f.Claimability == models.ClaimDangling)
}

// estimateLoss returns the estimate and, per affected ARN, the range for that identity or resource. A group it
// cannot put a number on is counted in NotEstimated, never given a guess.
func estimateLoss(findings []models.Finding, assets []models.AssetNode, l business.Loss) (schema.LossEstimate, map[string]lossRange) {
	est := schema.LossEstimate{Configured: l.Configured(), Currency: l.Currency, Items: []schema.LossItem{}}
	per := map[string]lossRange{}
	if !est.Configured {
		return est, per
	}
	stores := map[string]int{}
	for _, a := range assets {
		if dataStoreTypes[a.AssetType] {
			stores[a.AccountID]++
		}
	}
	type group struct {
		subject, account string
		sev              models.Severity
		admin, public    bool
		takeover         bool
	}
	groups := map[string]*group{}
	var order []string
	for _, f := range findings {
		sev := strings.ToLower(string(f.Severity))
		if sev != "critical" && sev != "high" {
			continue
		}
		key := f.AffectedARN
		if key == "" {
			key = f.ID
		}
		g := groups[key]
		if g == nil {
			g = &group{subject: subjectName(f), account: f.AccountID}
			groups[key] = g
			order = append(order, key)
		}
		if severityRank(models.Severity(sev)) > severityRank(g.sev) {
			g.sev = models.Severity(sev)
		}
		g.admin = g.admin || isAdminReach(f)
		g.public = g.public || isPublicBucket(f)
		g.takeover = g.takeover || isTakeover(f)
	}
	for _, key := range order {
		g := groups[key]
		like := l.LikelihoodHigh
		if g.sev == models.SeverityCritical {
			like = l.LikelihoodCritical
		}
		var impact business.Range
		var why string
		switch {
		case g.admin:
			n := stores[g.account]
			if n == 0 {
				est.NotEstimated++
				continue
			}
			impact = business.Range{Low: float64(n) * l.StoreCost.Low, High: float64(n) * l.StoreCost.High}
			why = plural(n, "data store", "data stores") + " in the account"
		case g.public:
			impact, why = l.StoreCost, "one exposed bucket"
		case g.takeover:
			impact, why = l.HostnameCost, "a hostname that can be taken over"
		default:
			est.NotEstimated++
			continue
		}
		if like.High <= 0 || impact.High <= 0 {
			est.NotEstimated++
			continue
		}
		r := lossRange{low: impact.Low * like.Low, high: impact.High * like.High}
		per[key] = r
		est.Low += r.low
		est.High += r.high
		est.Items = append(est.Items, schema.LossItem{Subject: g.subject, Low: r.low, High: r.high, Why: why})
	}
	return est, per
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return itoa(n) + " " + many
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
