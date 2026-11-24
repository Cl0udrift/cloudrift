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
	case RuleNewInternetExposure:
		res, err = e.evalNewExposure(rule, scanID)
	case RuleReclaimableThreshold:
		res, err = e.evalReclaimable(rule, scanID, scoped)
	case RuleStaleExternalPrivilegedRoles:
		res, err = e.evalStaleExternalPrivileged(rule, scanID, scoped)
	default:
		spec, ok := deltaSpecFor(rule.Type)
		if !ok {
			return AlertEvaluationResult{}, fmt.Errorf("unsupported alert rule type %q", rule.Type)
		}
		res, err = e.evalDelta(rule, scanID, spec, scoped)
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

// evalScanCompletion is the "what changed" digest. It does not fire when nothing changed since the previous scan,
// so a quiet scan stays quiet. The first scan has no baseline and always reports its totals.
func (e *Evaluator) evalScanCompletion(rule AlertRule, scanID string, findings []models.Finding) (AlertEvaluationResult, error) {
	critical, high := severityCounts(findings)
	prev := e.previousScanID(scanID)
	var fresh []models.Finding
	resolved := 0
	prevCritical, prevHigh := 0, 0
	if prev != "" {
		_, old, err := scans.LoadScanArtifacts(e.outputDir, prev)
		if err != nil {
			return AlertEvaluationResult{}, err
		}
		old = FilterFindingsByAccountScope(rule, old)
		prevCritical, prevHigh = severityCounts(old)
		oldIdx := map[string]struct{}{}
		for _, f := range old {
			oldIdx[diffIdentity(f)] = struct{}{}
		}
		curIdx := map[string]struct{}{}
		for _, f := range findings {
			curIdx[diffIdentity(f)] = struct{}{}
			if _, ok := oldIdx[diffIdentity(f)]; !ok {
				fresh = append(fresh, f)
			}
		}
		for k := range oldIdx {
			if _, ok := curIdx[k]; !ok {
				resolved++
			}
		}
	}
	totals := fmt.Sprintf("%d findings (%d critical, %d high).", len(findings), critical, high)
	payload := AlertPayload{
		Title:       "Scan finished",
		Severity:    SeverityInfo,
		ActionLabel: "Open scan overview",
		ActionURL:   e.url("/overview", map[string]string{"scan_id": scanID, "view": "executive"}),
	}
	meta := map[string]any{"critical_count": critical, "high_count": high, "new_count": len(fresh), "resolved_count": resolved}
	triggered := true
	switch {
	case prev == "":
		payload.Summary = fmt.Sprintf("First scan %s finished. %s", scanID, totals)
		payload.Items = e.topItems(scanID, filterCriticalHigh(findings))
	case len(fresh) == 0 && resolved == 0:
		triggered = false
		payload = quiet(payload, "Scan finished, no changes", fmt.Sprintf("Scan %s found the same findings as %s. %s", scanID, prev, totals))
	default:
		meta["baseline_scan_id"] = prev
		payload.Summary = fmt.Sprintf("Since scan %s: %d new, %d resolved. %s", prev, len(fresh), resolved, totals)
		payload.Items = e.topItems(scanID, fresh)
		payload.Bullets = cleanBullets([]string{
			fmt.Sprintf("Critical %d (was %d), high %d (was %d).", critical, prevCritical, high, prevHigh),
			topAccountBullet(fresh),
		})
		if critical > prevCritical {
			payload.Severity = SeverityCritical
		} else if high > prevHigh {
			payload.Severity = SeverityWarning
		}
	}
	res := makeResult(rule, scanID, triggered, payload, len(fresh), meta)
	if triggered {
		if top, ok := topFindingByPriority(filterCriticalHigh(fresh)); ok {
			res.Context.BlastSummary = e.maybeEnrichAlertWithBlast(scanID, blastradius.ModeBlastRadius, &top, &res.Context.Payload, res.Context.Metadata)
		}
	}
	return res, nil
}

func (e *Evaluator) evalNewCritical(rule AlertRule, scanID string, findings []models.Finding) (AlertEvaluationResult, error) {
	prev := e.previousScanID(scanID)
	if prev == "" {
		return e.baselineMissing(rule, scanID, "New critical findings", "/findings", map[string]string{"severity": "critical"}), nil
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
		Title:       fmt.Sprintf("%d new critical %s", len(newCritical), plural(len(newCritical), "finding", "findings")),
		Severity:    SeverityCritical,
		Summary:     summary,
		Bullets:     cleanBullets(bullets),
		Items:       e.topItems(scanID, newCritical),
		ActionLabel: "Review critical findings",
		ActionURL:   e.url("/findings", map[string]string{"scan_id": scanID, "severity": "critical"}),
	}
	if len(newCritical) == 0 {
		payload = quiet(payload, "No new critical findings", fmt.Sprintf("No new critical findings since scan %s.", prev))
		payload.Bullets = nil
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

func (e *Evaluator) evalReclaimable(rule AlertRule, scanID string, findings []models.Finding) (AlertEvaluationResult, error) {
	reclaimable := make([]models.Finding, 0)
	for _, f := range findings {
		if strings.EqualFold(string(f.Claimability), "reclaimable") {
			reclaimable = append(reclaimable, f)
		}
	}
	countMin := rule.Threshold.CountMin
	if countMin <= 0 {
		countMin = 1
	}
	triggered := len(reclaimable) >= countMin
	payload := AlertPayload{
		ActionLabel: "Review reclaimable fixes",
		ActionURL:   e.url("/findings", map[string]string{"scan_id": scanID, "claimability": "reclaimable"}),
	}
	if triggered {
		noun := plural(len(reclaimable), "finding", "findings")
		payload.Title = fmt.Sprintf("%d reclaimable %s", len(reclaimable), noun)
		payload.Severity = SeverityWarning
		payload.Summary = fmt.Sprintf("%d reclaimable %s on scan %s (your limit is %d). Each one is a dangling record or orphaned resource an attacker could claim.", len(reclaimable), noun, scanID, countMin)
		payload.Items = e.topItems(scanID, reclaimable)
		payload.Bullets = cleanBullets([]string{topRemediationLine(reclaimable), topAccountBullet(reclaimable)})
	} else {
		payload = quiet(payload, "Reclaimable findings below limit", fmt.Sprintf("%d reclaimable %s on scan %s; the limit is %d.", len(reclaimable), plural(len(reclaimable), "finding", "findings"), scanID, countMin))
	}
	meta := map[string]any{"count_min": countMin, "reclaimable_count": len(reclaimable)}
	res := makeResult(rule, scanID, triggered, payload, len(reclaimable), meta)
	if top, ok := topFindingByPriority(reclaimable); ok && triggered {
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
		Title:       fmt.Sprintf("%d stale privileged external %s", len(matches), plural(len(matches), "trust", "trusts")),
		Severity:    SeverityCritical,
		Summary:     fmt.Sprintf("%d external %s can still assume a privileged role but has not been used recently.", len(matches), plural(len(matches), "party", "parties")),
		Bullets:     cleanBullets(bullets),
		Items:       e.topItems(scanID, matches),
		ActionLabel: "Inspect external access",
		ActionURL:   e.url("/external-entities", map[string]string{"scan_id": scanID, "has_stale_role": "true", "has_privileged_role": "true"}),
	}
	if !triggered {
		payload = quiet(payload, "No stale privileged external trust", fmt.Sprintf("%d stale privileged external %s found; the limit is %d.", len(matches), plural(len(matches), "trust", "trusts"), countMin))
		payload.Bullets, payload.Items = nil, nil
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

// previousScanID is the newest earlier scan of the same accounts. A scan of another account is not a baseline.
func (e *Evaluator) previousScanID(current string) string {
	return scans.PreviousScanID(e.outputDir, current)
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
		summary = "Not triggered: " + payload.Summary
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

func diffIdentity(f models.Finding) string { return f.DiffKey() }

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
