package alerting

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Zero0x00/cloudrift/internal/blastradius"
	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/scans"
	"github.com/Zero0x00/cloudrift/internal/scorers"
)

type Evaluator struct {
	outputDir  string
	appBaseURL string
	blast      BlastSummaryProvider
}

func NewEvaluator(outputDir, appBaseURL string, blastProvider ...BlastSummaryProvider) *Evaluator {
	base := strings.TrimRight(strings.TrimSpace(appBaseURL), "/")
	if base == "" {
		base = "http://127.0.0.1:8080"
	}
	var bp BlastSummaryProvider
	if len(blastProvider) > 0 {
		bp = blastProvider[0]
	}
	return &Evaluator{outputDir: outputDir, appBaseURL: base, blast: bp}
}

func (e *Evaluator) Evaluate(rule AlertRule, scanID string) (AlertEvaluationResult, error) {
	if !RuleAppliesToScan(rule, scanID) {
		return e.evalScopeScanSkipped(rule, scanID), nil
	}
	_, findings, err := scans.LoadScanArtifacts(e.outputDir, scanID)
	if err != nil {
		return AlertEvaluationResult{}, err
	}
	scoped := FilterFindingsByAccountScope(rule, findings)

	var res AlertEvaluationResult
	switch rule.Type {
	case RuleScanCompletion:
		res, err = e.evalScanCompletion(rule, scanID, scoped)
	case RuleNewCriticalFindings:
		res, err = e.evalNewCritical(rule, scanID, scoped)
	case RuleNewEscalationPaths:
		res, err = e.evalNewEscalation(rule, scanID, scoped)
	case RuleReclaimableThreshold:
		res, err = e.evalReclaimable(rule, scanID, scoped)
	case RuleStaleExternalPrivilegedRoles:
		res, err = e.evalStaleExternalPrivileged(rule, scanID, scoped)
	default:
		return AlertEvaluationResult{}, fmt.Errorf("unsupported alert rule type %q", rule.Type)
	}
	if err != nil {
		return res, err
	}
	enrichScopeMetadata(rule, len(findings), len(scoped), &res)
	mergeRoutingHints(rule, scoped, &res)
	return res, nil
}

func mergeRoutingHints(rule AlertRule, scoped []models.Finding, res *AlertEvaluationResult) {
	hints := routingHintAccountIDsFromFindings(scoped)
	if res.Context.Metadata == nil {
		res.Context.Metadata = map[string]any{}
	}
	if len(hints) > 0 {
		res.Context.Metadata["routing_hint_account_ids"] = hints
	}
}

func (e *Evaluator) evalScopeScanSkipped(rule AlertRule, scanID string) AlertEvaluationResult {
	n := len(normalizeScopeIDs(rule.Scope.ScanIDs))
	payload := AlertPayload{
		Title:    "Rule skipped (scan scope)",
		Severity: SeverityInfo,
		Summary:  fmt.Sprintf("Scan %s is not in this rule's allowed scan list (%d configured).", scanID, n),
		Bullets: cleanBullets([]string{
			"Add this scan to the rule's scan scope, or clear scan scope to evaluate every scan.",
			"Account scope (if any) is not evaluated when the scan is out of scope.",
		}),
		ActionLabel: "Edit alerting rules",
		ActionURL:   e.url("/alerting", map[string]string{"scan_id": scanID}),
	}
	return makeResult(rule, scanID, false, payload, 0, map[string]any{
		"scope_scan_excluded": true,
		"allowed_scans_count": n,
	})
}

func enrichScopeMetadata(rule AlertRule, before, after int, res *AlertEvaluationResult) {
	if res.Context.Metadata == nil {
		res.Context.Metadata = map[string]any{}
	}
	if ac := len(normalizeScopeIDs(rule.Scope.AccountIDs)); ac > 0 {
		res.Context.Metadata["scope_accounts_configured"] = ac
		res.Context.Metadata["findings_before_account_scope"] = before
		res.Context.Metadata["findings_after_account_scope"] = after
	}
	if sc := len(normalizeScopeIDs(rule.Scope.ScanIDs)); sc > 0 {
		res.Context.Metadata["scope_scans_configured"] = sc
	}
}

func (e *Evaluator) evalScanCompletion(rule AlertRule, scanID string, findings []models.Finding) (AlertEvaluationResult, error) {
	critical, high := severityCounts(findings)
	newCount, resolvedCount := 0, 0
	var prevRisk, currRisk float64
	currRisk = totalMonthlyRiskUSD(findings)
	if prev := e.previousScanID(scanID); prev != "" {
		_, oldFindings, err := scans.LoadScanArtifacts(e.outputDir, prev)
		if err == nil {
			newCount, resolvedCount = diffCounts(oldFindings, findings)
			prevRisk = totalMonthlyRiskUSD(oldFindings)
		}
	}

	bullets := []string{
		fmt.Sprintf("%d findings (%d critical / %d high).", len(findings), critical, high),
	}
	if newCount > 0 || resolvedCount > 0 {
		bullets = append(bullets, fmt.Sprintf("Delta vs prior scan: +%d new identities, -%d resolved.", newCount, resolvedCount))
	}
	if line := riskTrendLine(prevRisk, currRisk); line != "" {
		bullets = append(bullets, line)
	}
	bullets = append(bullets, topAccountBullet(findings))

	summary := fmt.Sprintf("Scan %s complete — prioritize critical/high items before they compound.", scanID)
	if critical > 0 {
		summary = fmt.Sprintf("Scan %s complete — %d critical finding(s) need ownership review.", scanID, critical)
	}

	payload := AlertPayload{
		Title:       "Scan completed",
		Severity:    SeverityInfo,
		Summary:     summary,
		Bullets:     cleanBullets(bullets),
		ActionLabel: "Open scan overview",
		ActionURL:   e.url("/overview", map[string]string{"scan_id": scanID, "view": "executive"}),
	}
	meta := map[string]any{
		"critical_count":     critical,
		"high_count":         high,
		"new_count":          newCount,
		"resolved_count":     resolvedCount,
		"modeled_risk_usd":   currRisk,
		"prior_modeled_risk": prevRisk,
	}
	res := makeResult(rule, scanID, true, payload, len(findings), meta)
	if top, ok := topFindingByPriority(filterCriticalHigh(findings)); ok {
		res.Context.BlastSummary = e.maybeEnrichAlertWithBlast(scanID, blastradius.ModeBlastRadius, &top, &res.Context.Payload, res.Context.Metadata)
	}
	return res, nil
}

func (e *Evaluator) evalNewCritical(rule AlertRule, scanID string, findings []models.Finding) (AlertEvaluationResult, error) {
	prev := e.previousScanID(scanID)
	if prev == "" {
		payload := AlertPayload{
			Title:       "New critical findings",
			Severity:    SeverityInfo,
			Summary:     "No baseline scan available yet for critical delta detection.",
			Bullets:     []string{"Run another scan to enable delta-based critical alerts."},
			ActionLabel: "Open findings",
			ActionURL:   e.url("/findings", map[string]string{"scan_id": scanID, "severity": "critical"}),
		}
		return makeResult(rule, scanID, false, payload, 0, map[string]any{"baseline_available": false}), nil
	}

	_, oldFindings, err := scans.LoadScanArtifacts(e.outputDir, prev)
	if err != nil {
		return AlertEvaluationResult{}, err
	}
	oldFindings = FilterFindingsByAccountScope(rule, oldFindings)
	oldIdx := map[string]struct{}{}
	for _, f := range oldFindings {
		oldIdx[diffIdentity(f)] = struct{}{}
	}

	newCritical := make([]models.Finding, 0)
	for _, f := range findings {
		if !strings.EqualFold(string(f.Severity), "critical") {
			continue
		}
		if _, ok := oldIdx[diffIdentity(f)]; ok {
			continue
		}
		newCritical = append(newCritical, f)
	}

	themes := topThemes(newCritical, 2)
	bullets := []string{
		fmt.Sprintf("%d new critical vs baseline %s.", len(newCritical), prev),
	}
	if top, ok := topFindingByPriority(newCritical); ok {
		own := ownerOneLiner(top)
		if own != "" {
			bullets = append(bullets, fmt.Sprintf("Highest-signal item: %s — owner %s.", shortenTitle(top.Title, 72), own))
		} else {
			bullets = append(bullets, fmt.Sprintf("Highest-signal item: %s.", shortenTitle(top.Title, 72)))
		}
		pr := scorers.PriorityReason(top)
		if len(pr) > 100 {
			pr = pr[:99] + "…"
		}
		if pr != "" {
			bullets = append(bullets, "Why it ranks first: "+pr+".")
		}
	} else if len(themes) > 0 {
		bullets = append(bullets, "Themes: "+strings.Join(themes, ", ")+".")
	}
	bullets = append(bullets, topAccountBullet(newCritical))

	summary := fmt.Sprintf("%d new critical introduced since the last scan — treat as incident triage, not backlog.", len(newCritical))
	if len(newCritical) == 1 {
		if top, ok := topFindingByPriority(newCritical); ok {
			if o := ownerOneLiner(top); o != "" {
				summary = fmt.Sprintf("New critical on %s: %s — confirm owner and blast radius.", o, shortenTitle(top.Title, 56))
			} else {
				summary = fmt.Sprintf("New critical: %s — confirm blast radius.", shortenTitle(top.Title, 64))
			}
		}
	}

	payload := AlertPayload{
		Title:       "New critical findings detected",
		Severity:    SeverityCritical,
		Summary:     summary,
		Bullets:     cleanBullets(bullets),
		ActionLabel: "Review critical findings",
		ActionURL:   e.url("/findings", map[string]string{"scan_id": scanID, "severity": "critical"}),
	}
	meta := map[string]any{
		"baseline_scan_id": prev,
		"theme_count":      len(themes),
	}
	if top, ok := topFindingByPriority(newCritical); ok {
		meta["top_priority_score"] = scorers.PriorityScore(top)
	}
	res := makeResult(rule, scanID, len(newCritical) > 0, payload, len(newCritical), meta)
	if top, ok := topFindingByPriority(newCritical); ok {
		res.Context.BlastSummary = e.maybeEnrichAlertWithBlast(scanID, blastradius.ModeAttackPath, &top, &res.Context.Payload, res.Context.Metadata)
	}
	return res, nil
}

// isEscalation reports a finding that says a principal can reach more access than it holds.
func isEscalation(f models.Finding) bool {
	category, _ := f.Evidence["issue_category"].(string)
	return category == "privilege_escalation"
}

// evalNewEscalation triggers on escalation paths the previous scan did not have. With no previous scan it
// does not trigger: a first scan has no baseline, so nothing in it is new.
func (e *Evaluator) evalNewEscalation(rule AlertRule, scanID string, findings []models.Finding) (AlertEvaluationResult, error) {
	url := e.url("/findings", map[string]string{"scan_id": scanID, "search": "privilege_escalation"})
	prev := e.previousScanID(scanID)
	if prev == "" {
		payload := AlertPayload{
			Title:       "New privilege-escalation paths",
			Severity:    SeverityInfo,
			Summary:     "No baseline scan available yet for escalation-path delta detection.",
			Bullets:     []string{"Run another scan to enable alerts on new escalation paths."},
			ActionLabel: "Open escalation paths",
			ActionURL:   url,
		}
		return makeResult(rule, scanID, false, payload, 0, map[string]any{"baseline_available": false}), nil
	}
	_, oldFindings, err := scans.LoadScanArtifacts(e.outputDir, prev)
	if err != nil {
		return AlertEvaluationResult{}, err
	}
	oldIdx := map[string]struct{}{}
	for _, f := range FilterFindingsByAccountScope(rule, oldFindings) {
		oldIdx[diffIdentity(f)] = struct{}{}
	}
	var fresh []models.Finding
	severity := SeverityWarning
	for _, f := range findings {
		if !isEscalation(f) {
			continue
		}
		if _, ok := oldIdx[diffIdentity(f)]; ok {
			continue
		}
		fresh = append(fresh, f)
		if s := strings.ToLower(string(f.Severity)); s == "high" || s == "critical" {
			severity = SeverityCritical
		}
	}
	bullets := []string{fmt.Sprintf("%d new escalation path(s) vs baseline %s.", len(fresh), prev)}
	summary := fmt.Sprintf("%d new privilege-escalation path(s) since the last scan.", len(fresh))
	if top, ok := topFindingByPriority(fresh); ok {
		bullets = append(bullets, "Highest-signal item: "+shortenTitle(top.Title, 80)+".")
		if len(fresh) == 1 {
			summary = "New escalation path: " + shortenTitle(top.Title, 80) + "."
		}
	}
	if len(fresh) > 0 {
		bullets = append(bullets, topAccountBullet(fresh))
	}
	payload := AlertPayload{
		Title:       "New privilege-escalation paths detected",
		Severity:    severity,
		Summary:     summary,
		Bullets:     cleanBullets(bullets),
		ActionLabel: "Review escalation paths",
		ActionURL:   url,
	}
	return makeResult(rule, scanID, len(fresh) > 0, payload, len(fresh), map[string]any{"baseline_scan_id": prev}), nil
}

func (e *Evaluator) evalReclaimable(rule AlertRule, scanID string, findings []models.Finding) (AlertEvaluationResult, error) {
	reclaimable := make([]models.Finding, 0)
	var reclaimRisk float64
	for _, f := range findings {
		if strings.EqualFold(string(f.Claimability), "reclaimable") {
			reclaimable = append(reclaimable, f)
			reclaimRisk += f.MonthlyRiskCost
		}
	}
	triggered := (rule.Threshold.CountMin > 0 && len(reclaimable) >= rule.Threshold.CountMin) ||
		(rule.Threshold.RiskCostUSDMin > 0 && reclaimRisk >= rule.Threshold.RiskCostUSDMin) ||
		(rule.Threshold.CountMin == 0 && rule.Threshold.RiskCostUSDMin == 0 && len(reclaimable) > 0)

	bullets := []string{
		fmt.Sprintf("%d reclaimable (~$%.0f/mo modeled).", len(reclaimable), reclaimRisk),
	}
	if top, ok := topFindingByPriority(reclaimable); ok {
		if o := ownerOneLiner(top); o != "" {
			bullets = append(bullets, fmt.Sprintf("Start with %s (%s).", shortenTitle(top.Title, 64), o))
		} else {
			bullets = append(bullets, fmt.Sprintf("Start with %s.", shortenTitle(top.Title, 72)))
		}
	}
	if line := topRemediationLine(reclaimable); line != "" {
		bullets = append(bullets, line)
	}
	bullets = append(bullets, topAccountBullet(reclaimable))

	summary := fmt.Sprintf("Reclaimable volume crossed your threshold on %s — idle spend and mis-claims add up.", scanID)
	if len(reclaimable) > 0 {
		summary = fmt.Sprintf("%d reclaimable on %s — close the highest-cost items first.", len(reclaimable), scanID)
	}

	payload := AlertPayload{
		Title:       "Reclaimable findings threshold reached",
		Severity:    SeverityWarning,
		Summary:     summary,
		Bullets:     cleanBullets(bullets),
		ActionLabel: "Review reclaimable fixes",
		ActionURL:   e.url("/findings", map[string]string{"scan_id": scanID, "claimability": "reclaimable"}),
	}
	meta := map[string]any{
		"count_min":            rule.Threshold.CountMin,
		"risk_cost_usd_min":    rule.Threshold.RiskCostUSDMin,
		"reclaimable_count":    len(reclaimable),
		"reclaimable_risk_usd": reclaimRisk,
	}
	res := makeResult(rule, scanID, triggered, payload, len(reclaimable), meta)
	if top, ok := topFindingByPriority(reclaimable); ok && top.MonthlyRiskCost >= 50 {
		res.Context.BlastSummary = e.maybeEnrichAlertWithBlast(scanID, blastradius.ModeBlastRadius, &top, &res.Context.Payload, res.Context.Metadata)
	}
	return res, nil
}

func (e *Evaluator) evalStaleExternalPrivileged(rule AlertRule, scanID string, findings []models.Finding) (AlertEvaluationResult, error) {
	matches := make([]models.Finding, 0)
	entityCounts := map[string]int{}
	for _, f := range findings {
		if !strings.EqualFold(string(f.Module), "external_access") {
			continue
		}
		if !evidenceTrustVerdictStale(f.Evidence) {
			continue
		}
		if !strings.EqualFold(evidenceTrustClassification(f.Evidence), "privileged") && !evidenceAdminLike(f.Evidence) {
			continue
		}
		matches = append(matches, f)
		entity := strings.TrimSpace(evidenceString(f.Evidence, "external_principal"))
		if entity == "" {
			entity = "unknown-principal"
		}
		entityCounts[entity]++
	}
	countMin := rule.Threshold.CountMin
	if countMin <= 0 {
		countMin = 1
	}
	triggered := len(matches) >= countMin
	topEntity := topMapKey(entityCounts)

	bullets := []string{
		fmt.Sprintf("%d stale privileged/admin-like external trust path(s).", len(matches)),
	}
	if topEntity != "" {
		bullets = append(bullets, fmt.Sprintf("Hot external principal: %s — review trust recency and scope.", topEntity))
	}
	if ac := topInternalAccountForFindings(matches); ac != "" {
		bullets = append(bullets, fmt.Sprintf("Most impacted AWS account: %s.", ac))
	}
	bullets = append(bullets, "Next: validate vendor, shrink roles, or revoke unused trust.")

	payload := AlertPayload{
		Title:       "Stale privileged external trust detected",
		Severity:    SeverityCritical,
		Summary:     fmt.Sprintf("%d stale privileged external role(s) — third-party access is the blast radius to cut first.", len(matches)),
		Bullets:     cleanBullets(bullets),
		ActionLabel: "Inspect external access",
		ActionURL:   e.url("/external-entities", map[string]string{"scan_id": scanID, "has_stale_role": "true", "has_privileged_role": "true"}),
	}
	meta := map[string]any{
		"count_min":   countMin,
		"top_entity":  topEntity,
		"match_count": len(matches),
	}
	res := makeResult(rule, scanID, triggered, payload, len(matches), meta)
	if top, ok := topFindingByPriority(matches); ok {
		res.Context.BlastSummary = e.maybeEnrichAlertWithBlast(scanID, blastradius.ModeAttackPath, &top, &res.Context.Payload, res.Context.Metadata)
	}
	return res, nil
}

func (e *Evaluator) previousScanID(current string) string {
	ids, err := scans.ListScanIDs(e.outputDir)
	if err != nil || len(ids) == 0 {
		return ""
	}
	type rec struct {
		id string
		ts string
	}
	recs := make([]rec, 0, len(ids))
	for _, id := range ids {
		meta, _, err := scans.LoadScanArtifacts(e.outputDir, id)
		if err != nil {
			continue
		}
		recs = append(recs, rec{id: id, ts: scans.SortTimestamp(meta).Format(timeLayout)})
	}
	sort.Slice(recs, func(i, j int) bool {
		if recs[i].ts == recs[j].ts {
			return recs[i].id < recs[j].id
		}
		return recs[i].ts > recs[j].ts
	})
	for i, r := range recs {
		if r.id == current && i+1 < len(recs) {
			return recs[i+1].id
		}
	}
	return ""
}

const timeLayout = "2006-01-02T15:04:05.999999999Z07:00"

func (e *Evaluator) url(path string, query map[string]string) string {
	if len(query) == 0 {
		return e.appBaseURL + path
	}
	keys := make([]string, 0, len(query))
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v := strings.TrimSpace(query[k])
		if v == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	if len(parts) == 0 {
		return e.appBaseURL + path
	}
	return e.appBaseURL + path + "?" + strings.Join(parts, "&")
}

func makeResult(rule AlertRule, scanID string, triggered bool, payload AlertPayload, count int, metadata map[string]any) AlertEvaluationResult {
	summary := payload.Summary
	if !triggered {
		summary = "Rule evaluated without trigger: " + payload.Summary
	}
	now := time.Now().UTC()
	return AlertEvaluationResult{
		RuleID:    rule.ID,
		RuleName:  rule.Name,
		RuleType:  rule.Type,
		ScanID:    scanID,
		Triggered: triggered,
		Summary:   summary,
		Context: AlertContext{
			ScanID:      scanID,
			RuleType:    rule.Type,
			SignalCount: count,
			Metadata:    metadata,
			Payload:     payload,
		},
		EvaluatedAt: now,
	}
}

func cleanBullets(bullets []string) []string {
	out := make([]string, 0, 3)
	for _, b := range bullets {
		b = strings.TrimSpace(b)
		if b == "" {
			continue
		}
		out = append(out, b)
		if len(out) == 3 {
			break
		}
	}
	return out
}

func severityCounts(findings []models.Finding) (critical int, high int) {
	for _, f := range findings {
		switch strings.ToLower(string(f.Severity)) {
		case "critical":
			critical++
		case "high":
			high++
		}
	}
	return critical, high
}

func topAccountBullet(findings []models.Finding) string {
	if len(findings) == 0 {
		return ""
	}
	counts := map[string]int{}
	for _, f := range findings {
		key := strings.TrimSpace(f.Team)
		if key == "" {
			key = strings.TrimSpace(f.AccountName)
		}
		if key == "" {
			key = strings.TrimSpace(f.AccountID)
		}
		if key == "" {
			key = "unknown-account"
		}
		counts[key]++
	}
	top := topMapKey(counts)
	if top == "" {
		return ""
	}
	return fmt.Sprintf("Top affected owner/account: %s.", top)
}

func topThemes(findings []models.Finding, limit int) []string {
	counts := map[string]int{}
	for _, f := range findings {
		key := strings.TrimSpace(strings.ToLower(f.Title))
		if key == "" {
			continue
		}
		counts[key]++
	}
	type kv struct {
		key string
		val int
	}
	list := make([]kv, 0, len(counts))
	for k, v := range counts {
		list = append(list, kv{key: k, val: v})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].val == list[j].val {
			return list[i].key < list[j].key
		}
		return list[i].val > list[j].val
	})
	out := make([]string, 0, limit)
	for _, item := range list {
		out = append(out, item.key)
		if len(out) == limit {
			break
		}
	}
	return out
}

func diffIdentity(f models.Finding) string {
	return strings.ToLower(strings.TrimSpace(f.Title)) + "|" + strings.ToLower(strings.TrimSpace(f.AffectedARN))
}

func diffCounts(oldFindings, newFindings []models.Finding) (newCount int, resolvedCount int) {
	oldIdx := map[string]struct{}{}
	for _, f := range oldFindings {
		oldIdx[diffIdentity(f)] = struct{}{}
	}
	newIdx := map[string]struct{}{}
	for _, f := range newFindings {
		newIdx[diffIdentity(f)] = struct{}{}
	}
	for key := range newIdx {
		if _, ok := oldIdx[key]; !ok {
			newCount++
		}
	}
	for key := range oldIdx {
		if _, ok := newIdx[key]; !ok {
			resolvedCount++
		}
	}
	return newCount, resolvedCount
}

func evidenceString(e map[string]any, key string) string {
	v, ok := e[key]
	if !ok || v == nil {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

func evidenceTrustVerdictStale(evidence map[string]any) bool {
	return strings.EqualFold(evidenceString(evidence, "verdict"), "stale_review_now")
}

func evidenceTrustClassification(evidence map[string]any) string {
	raw, ok := evidence["permission_visibility"]
	if !ok || raw == nil {
		return ""
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return ""
	}
	return evidenceString(m, "classification")
}

func evidenceAdminLike(evidence map[string]any) bool {
	raw, ok := evidence["permission_visibility"]
	if !ok || raw == nil {
		return false
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return false
	}
	capRaw, ok := m["capabilities"]
	if !ok || capRaw == nil {
		return false
	}
	cap, ok := capRaw.(map[string]any)
	if !ok {
		return false
	}
	v, ok := cap["admin_like"].(bool)
	return ok && v
}

func topMapKey(counts map[string]int) string {
	best := ""
	bestCount := 0
	for k, c := range counts {
		if c > bestCount || (c == bestCount && (best == "" || k < best)) {
			best = k
			bestCount = c
		}
	}
	return best
}

func filterCriticalHigh(findings []models.Finding) []models.Finding {
	out := make([]models.Finding, 0, len(findings))
	for _, f := range findings {
		if strings.EqualFold(string(f.Severity), "critical") || strings.EqualFold(string(f.Severity), "high") {
			out = append(out, f)
		}
	}
	return out
}
