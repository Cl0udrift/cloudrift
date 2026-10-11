package alerting

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/blastradius"
	"github.com/Zero0x00/cloudrift/internal/models"
)

type BlastSummaryProvider interface {
	FindingBlastSummary(ctx context.Context, scanID, findingID string, mode blastradius.BlastMode) (schema.BlastRadiusSummary, error)
}

type blastSummaryAdapter struct {
	svc *blastradius.Service
}

func newBlastSummaryAdapter(svc *blastradius.Service) BlastSummaryProvider {
	if svc == nil {
		return nil
	}
	return &blastSummaryAdapter{svc: svc}
}

func (a *blastSummaryAdapter) FindingBlastSummary(
	ctx context.Context,
	scanID, findingID string,
	mode blastradius.BlastMode,
) (schema.BlastRadiusSummary, error) {
	sum, _, _, _ := a.svc.FindingBlast(ctx, scanID, findingID, mode)
	return sum, nil
}

func (e *Evaluator) maybeEnrichAlertWithBlast(
	scanID string,
	mode blastradius.BlastMode,
	target *models.Finding,
	payload *AlertPayload,
	metadata map[string]any,
) *AlertBlastSummary {
	if e == nil || e.blast == nil || target == nil || strings.TrimSpace(target.ID) == "" || payload == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	sum, err := e.blast.FindingBlastSummary(ctx, scanID, target.ID, mode)
	if err != nil || !sum.GraphAvailable {
		if metadata != nil {
			metadata["blast_graph_available"] = false
		}
		return nil
	}
	bs := &AlertBlastSummary{
		ReachableResources: sum.ReachableResourceCount,
		ReachableAccounts:  sum.ReachableAccountsCount,
		EscalationPossible: sum.EscalationPossible,
		TopAccount:         firstOrEmpty(sum.TopImpactedAccounts),
		DominantMotif:      dominantMotifFromSummary(sum),
		ActionLabel:        strings.TrimSpace(sum.RecommendedActionLabel),
		PathValidity:       strings.TrimSpace(sum.PathValidity),
	}
	enriched := blastBullets(bs)
	// Keep alerts concise: preserve one base bullet and add up to two blast bullets.
	base := make([]string, 0, 3)
	if len(payload.Bullets) > 0 {
		base = append(base, payload.Bullets[0])
	}
	base = append(base, enriched...)
	payload.Bullets = cleanBullets(base)
	if bs.ActionLabel != "" {
		payload.ActionLabel = bs.ActionLabel
	}
	if metadata != nil {
		metadata["blast_graph_available"] = true
		metadata["blast_reachable_resources"] = bs.ReachableResources
		metadata["blast_reachable_accounts"] = bs.ReachableAccounts
		metadata["blast_escalation_possible"] = bs.EscalationPossible
		if bs.TopAccount != "" {
			metadata["blast_top_account"] = bs.TopAccount
		}
		if bs.DominantMotif != "" {
			metadata["blast_dominant_motif"] = bs.DominantMotif
		}
	}
	return bs
}

func dominantMotifFromSummary(sum schema.BlastRadiusSummary) string {
	if validity := strings.TrimSpace(sum.PathValidity); validity != "" && validity != "VALIDATED_POSSIBLE" {
		return ""
	}
	if motif := strings.TrimSpace(sum.DominantMotif); motif != "" {
		return strings.ToUpper(motif)
	}
	text := strings.ToLower(strings.TrimSpace(sum.RecommendedActionLabel + " " + sum.SummaryText))
	switch {
	case strings.Contains(text, "cross-account"):
		return "CROSS_ACCOUNT_ASSUME_ROLE"
	case strings.Contains(text, "external trust"):
		return "EXTERNAL_TRUST"
	case strings.Contains(text, "iam-write") || strings.Contains(text, "iam write"):
		return "IAM_WRITE"
	case strings.Contains(text, "trust"):
		return "ASSUME_ROLE"
	case strings.Contains(text, "resource-access") || strings.Contains(text, "reachability"):
		return "RESOURCE_ACCESS"
	default:
		return ""
	}
}

func blastBullets(bs *AlertBlastSummary) []string {
	if bs == nil {
		return nil
	}
	if validity := strings.TrimSpace(bs.PathValidity); validity != "" && validity != "VALIDATED_POSSIBLE" {
		return []string{
			"Topology shows " + itoa(bs.ReachableResources) + " confirmed resources across " + itoa(bs.ReachableAccounts) + " accounts. No validated attack path is established.",
		}
	}
	out := []string{
		"Can reach " + itoa(bs.ReachableResources) + " resources across " + itoa(bs.ReachableAccounts) + " accounts.",
	}
	switch bs.DominantMotif {
	case "CROSS_ACCOUNT_ASSUME_ROLE":
		out = append(out, "Cross-account role pivot detected.")
	case "EXTERNAL_TRUST":
		out = append(out, "External trust path into privileged scope detected.")
	case "IAM_WRITE":
		out = append(out, "IAM-write pivot capability detected.")
	case "ASSUME_ROLE":
		out = append(out, "Assume-role trust pivot detected.")
	case "RESOURCE_ACCESS":
		out = append(out, "Resource-access branch expands blast context.")
	}
	if bs.DominantMotif == "" && bs.EscalationPossible {
		out = append(out, "Privilege escalation remains plausible from this node set.")
	}
	return out
}

func firstOrEmpty(in []string) string {
	if len(in) == 0 {
		return ""
	}
	return strings.TrimSpace(in[0])
}

func itoa(v int) string {
	if v < 0 {
		v = 0
	}
	return strconv.Itoa(v)
}
