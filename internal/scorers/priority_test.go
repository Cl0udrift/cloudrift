package scorers

import (
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestPriorityScoreSeverityContribution(t *testing.T) {
	base := models.Finding{Claimability: models.ClaimUnknown, MonthlyRiskCost: 0}
	critical := base
	critical.Severity = models.SeverityCritical
	medium := base
	medium.Severity = models.SeverityMedium
	if PriorityScore(critical) <= PriorityScore(medium) {
		t.Fatalf("critical should score above medium: %v <= %v", PriorityScore(critical), PriorityScore(medium))
	}
}

func TestPriorityScoreClaimabilityContribution(t *testing.T) {
	base := models.Finding{Severity: models.SeverityHigh, Module: models.ModuleOrphanedEdge, MonthlyRiskCost: 0}
	reclaim := base
	reclaim.Claimability = models.ClaimReclaimable
	unknown := base
	unknown.Claimability = models.ClaimUnknown
	if PriorityScore(reclaim) <= PriorityScore(unknown) {
		t.Fatalf("reclaimable should score above unknown: %v <= %v", PriorityScore(reclaim), PriorityScore(unknown))
	}
}

func TestPriorityScoreIgnoresDollarCost(t *testing.T) {
	base := models.Finding{Severity: models.SeverityMedium, Claimability: models.ClaimUnknown}
	cheap := base
	cheap.MonthlyRiskCost = 10
	dear := base
	dear.MonthlyRiskCost = 500
	if PriorityScore(dear) != PriorityScore(cheap) {
		t.Fatalf("a monthly price must not change priority: %v vs %v", PriorityScore(dear), PriorityScore(cheap))
	}
}

func TestPriorityScoreDoesNotFavourOneModule(t *testing.T) {
	// Severity decides. A boost is capped, so a lower severity can never outrank a higher one by evidence alone.
	orphan := models.Finding{Severity: models.SeverityMedium, Module: models.ModuleOrphanedEdge, Claimability: models.ClaimReclaimable}
	identity := models.Finding{Severity: models.SeverityHigh, Module: models.ModuleIAMEntitlement, Claimability: models.ClaimUnknown}
	if PriorityScore(identity) <= PriorityScore(orphan) {
		t.Fatalf("a High identity finding must outrank a Medium orphaned edge: %v <= %v", PriorityScore(identity), PriorityScore(orphan))
	}
	// At the same severity the modules differ by no more than the cap.
	highOrphan := models.Finding{Severity: models.SeverityHigh, Module: models.ModuleOrphanedEdge, Claimability: models.ClaimReclaimable}
	running := models.Finding{Severity: models.SeverityHigh, Module: models.ModuleIAMEntitlement, Evidence: map[string]any{"workloads": []any{map[string]any{"name": "i-1"}}}}
	if d := PriorityScore(highOrphan) - PriorityScore(running); d < -maxBoost || d > maxBoost {
		t.Fatalf("same severity must stay within the boost cap: %v", d)
	}
}

func TestPriorityScoreExternalExposureContribution(t *testing.T) {
	plain := models.Finding{
		ID:           "plain",
		Severity:     models.SeverityHigh,
		Module:       models.ModuleOrphanedEdge,
		Claimability: models.ClaimUnknown,
	}
	external := models.Finding{
		ID:           "ext",
		Severity:     models.SeverityHigh,
		Module:       models.ModuleExternalAccess,
		Claimability: models.ClaimUnknown,
		Evidence: map[string]any{
			"verdict":        "stale_review_now",
			"principal_type": "",
			"unknown_vendor": true,
			"permission_visibility": map[string]any{
				"classification": "privileged",
				"capabilities":   map[string]any{"admin_like": true},
			},
		},
	}
	if PriorityScore(external) <= PriorityScore(plain) {
		t.Fatalf("external signal-rich finding should score above plain finding: %v <= %v", PriorityScore(external), PriorityScore(plain))
	}
}

func TestPriorityLessDeterministicTieBreak(t *testing.T) {
	a := models.Finding{ID: "a", Severity: models.SeverityHigh, MonthlyRiskCost: 10}
	b := models.Finding{ID: "b", Severity: models.SeverityHigh, MonthlyRiskCost: 10}
	if !PriorityLess(a, b, 100, 100) {
		t.Fatal("expected lexicographic ID tie-break when all else equal")
	}
}
