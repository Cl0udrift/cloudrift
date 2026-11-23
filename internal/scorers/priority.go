package scorers

import (
	"math"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// maxBoost caps what any module's own evidence can add to a finding's severity points. Severity decides the order; the
// boost only separates findings of the same severity. Every module gets the same cap so no module outranks another just
// because it has more kinds of evidence, and dollar cost is not an input: a monthly price says nothing about harm.
const maxBoost = 15.0

// PriorityScore ranks findings for top-fix workflows. Higher is more urgent.
func PriorityScore(f models.Finding) float64 {
	return math.Round((severityPoints(f.Severity)+moduleBoost(f))*100) / 100
}

// moduleBoost is how much more urgent a finding is than others of its severity, from evidence its own module records:
// takeover state for an orphaned edge, trust signals for external access, and a running workload for an identity finding.
func moduleBoost(f models.Finding) float64 {
	switch f.Module {
	case models.ModuleOrphanedEdge:
		return math.Min(maxBoost, claimabilityPoints(f.Claimability)*0.4)
	case models.ModuleExternalAccess:
		return math.Min(maxBoost, externalExposurePoints(f)*0.3)
	}
	if w, ok := f.Evidence["workloads"].([]any); ok && len(w) > 0 {
		return 10 // something runs as this identity, so what it holds is in use
	}
	if w, ok := f.Evidence["workloads"].([]map[string]any); ok && len(w) > 0 {
		return 10
	}
	return 0
}

// PriorityReason builds a concise, explainable string for why a finding ranked highly.
func PriorityReason(f models.Finding) string {
	var parts []string
	switch strings.ToLower(string(f.Severity)) {
	case string(models.SeverityCritical):
		parts = append(parts, "Critical")
	case string(models.SeverityHigh):
		parts = append(parts, "High severity")
	case string(models.SeverityMedium):
		parts = append(parts, "Medium severity")
	}
	switch strings.ToLower(string(f.Claimability)) {
	case string(models.ClaimReclaimable):
		parts = append(parts, "reclaimable")
	case string(models.ClaimDangling):
		parts = append(parts, "dangling resource")
	case string(models.ClaimBroken):
		parts = append(parts, "broken claim")
	case string(models.ClaimEdgeObscured):
		parts = append(parts, "edge obscured")
	}
	if strings.EqualFold(string(f.Module), string(models.ModuleExternalAccess)) {
		var ext []string
		if evidenceAdminLike(f.Evidence) {
			ext = append(ext, "admin-like external trust")
		}
		if evidenceTrustVerdictStale(f.Evidence) {
			ext = append(ext, "stale trust review")
		}
		if strings.EqualFold(strings.TrimSpace(evidenceTrustClassification(f.Evidence)), "privileged") {
			ext = append(ext, "privileged access pattern")
		}
		if b, ok := boolEvidence(f.Evidence, "unknown_vendor"); ok && b {
			ext = append(ext, "unknown vendor")
		}
		if evidencePrincipalType(f.Evidence) == "" {
			ext = append(ext, "unknown principal type")
		}
		if len(ext) > 0 {
			parts = append(parts, "External: "+strings.Join(ext, ", "))
		} else {
			parts = append(parts, "External access")
		}
	}
	if len(parts) == 0 {
		return "Ranked by composite priority"
	}
	return strings.Join(parts, " · ")
}

// PriorityLess provides deterministic ordering for equal/close scores.
func PriorityLess(a, b models.Finding, scoreA, scoreB float64) bool {
	if scoreA != scoreB {
		return scoreA > scoreB
	}
	rankA := prioritySeverityRank(a.Severity)
	rankB := prioritySeverityRank(b.Severity)
	if rankA != rankB {
		return rankA > rankB
	}
	return a.ID < b.ID
}

func severityPoints(s models.Severity) float64 {
	switch strings.ToLower(string(s)) {
	case string(models.SeverityCritical):
		return 100
	case string(models.SeverityHigh):
		return 72
	case string(models.SeverityMedium):
		return 48
	case string(models.SeverityLow):
		return 28
	case string(models.SeverityInfo):
		return 12
	default:
		return 35
	}
}

func claimabilityPoints(c models.Claimability) float64 {
	switch strings.ToLower(string(c)) {
	case string(models.ClaimReclaimable):
		return 38
	case string(models.ClaimDangling):
		return 30
	case string(models.ClaimBroken):
		return 24
	case string(models.ClaimEdgeObscured):
		return 18
	case string(models.ClaimUnknown):
		return 6
	default:
		return 6
	}
}

func externalExposurePoints(f models.Finding) float64 {
	if !strings.EqualFold(string(f.Module), string(models.ModuleExternalAccess)) {
		return 0
	}
	pts := 10.0
	if evidenceAdminLike(f.Evidence) {
		pts += 22
	}
	if evidenceTrustVerdictStale(f.Evidence) {
		pts += 14
	}
	if strings.EqualFold(strings.TrimSpace(evidenceTrustClassification(f.Evidence)), "privileged") {
		pts += 12
	}
	if b, ok := boolEvidence(f.Evidence, "unknown_vendor"); ok && b {
		pts += 9
	}
	if evidencePrincipalType(f.Evidence) == "" {
		pts += 5
	}
	return math.Min(52, pts)
}

func prioritySeverityRank(s models.Severity) int {
	switch strings.ToLower(string(s)) {
	case string(models.SeverityCritical):
		return 5
	case string(models.SeverityHigh):
		return 4
	case string(models.SeverityMedium):
		return 3
	case string(models.SeverityLow):
		return 2
	case string(models.SeverityInfo):
		return 1
	default:
		return 0
	}
}

func evidenceTrustVerdictStale(evidence map[string]any) bool {
	return strings.EqualFold(strings.TrimSpace(strEvidence(evidence, "verdict")), "stale_review_now")
}

func evidenceTrustClassification(evidence map[string]any) string {
	pv, ok := evidence["permission_visibility"].(map[string]any)
	if !ok || pv == nil {
		return ""
	}
	return strings.TrimSpace(strEvidence(pv, "classification"))
}

func evidenceAdminLike(evidence map[string]any) bool {
	pv, ok := evidence["permission_visibility"].(map[string]any)
	if !ok || pv == nil {
		return false
	}
	cap, ok := pv["capabilities"].(map[string]any)
	if !ok || cap == nil {
		return false
	}
	b, ok := boolEvidence(cap, "admin_like")
	return ok && b
}

func evidencePrincipalType(evidence map[string]any) string {
	return strings.TrimSpace(strEvidence(evidence, "principal_type"))
}

func strEvidence(e map[string]any, key string) string {
	v, ok := e[key]
	if !ok || v == nil {
		return ""
	}
	s, ok := v.(string)
	if ok {
		return s
	}
	return ""
}

func boolEvidence(e map[string]any, key string) (bool, bool) {
	v, ok := e[key]
	if !ok || v == nil {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}
