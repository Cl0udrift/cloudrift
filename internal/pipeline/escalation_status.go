package pipeline

import (
	"fmt"

	"github.com/Zero0x00/cloudrift/internal/ciem"
	"github.com/Zero0x00/cloudrift/internal/collectors"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// escalationStatus records how far the scan-time escalation search got, in the same form as the collectors' status
// records, so the Coverage page and a reader of the scan can tell a clean result from an unfinished one.
func escalationStatus(s ciem.EscalationStats) models.AssetNode {
	status := "succeeded"
	if s.BudgetHit || s.NotSearched > 0 || s.Truncated > 0 {
		status = "partial"
	}
	detail := fmt.Sprintf("%d principals considered, %d searched, %d findings", s.Principals, s.Searched, s.Findings)
	if s.NotSearched > 0 {
		detail += fmt.Sprintf("; %d not reached within the %s budget", s.NotSearched, s.Budget)
	}
	if s.Truncated > 0 {
		detail += fmt.Sprintf("; %d searches hit a bound", s.Truncated)
	}
	if s.UnknownOnly > 0 {
		detail += fmt.Sprintf("; %d principals had hops left UNKNOWN for missing evidence", s.UnknownOnly)
	}
	if s.Capped > 0 {
		detail += fmt.Sprintf("; %d principal and technique pairs rolled up past the per-technique cap", s.Capped)
	}
	n := collectors.CollectionStatus("", "", "escalation_search", "global", status, detail)
	n.Properties["principals"], n.Properties["searched"], n.Properties["not_searched"] = s.Principals, s.Searched, s.NotSearched
	n.Properties["unknown_only"], n.Properties["capped"], n.Properties["findings"] = s.UnknownOnly, s.Capped, s.Findings
	return n
}
