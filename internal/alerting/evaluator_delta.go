package alerting

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/ciem"
	"github.com/Zero0x00/cloudrift/internal/inventory"
	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/scans"
	"github.com/Zero0x00/cloudrift/internal/scorers"
)

// Rules that fire on something that is new since the previous scan. Each is one entry of this table; evalDelta
// does the comparing and writes the message, so every delta rule reads the same way.
const (
	RuleNewInternetExposure RuleType = "new_internet_exposure"
	RuleNewPublicBucket     RuleType = "new_public_bucket"
	RuleNewConsoleNoMFA     RuleType = "new_console_users_without_mfa"
	RuleNewKeyIssues        RuleType = "new_access_key_issues"
	RuleNewAdminIdentities  RuleType = "new_admin_identities"
	RuleNewOrphanedEdge     RuleType = "new_orphaned_edge"
)

type deltaSpec struct {
	Type        RuleType
	Label       string
	Description string
	// Singular and Plural name the thing in sentences, e.g. "console user without MFA".
	Singular, Plural string
	Severity         Severity
	Match            func(models.Finding) bool
	Path             string
	Query            map[string]string
	ActionLabel      string
	Next             string
	// BumpOnHigh raises the alert to critical when a new item is high or critical.
	BumpOnHigh bool
}

func issueCategory(f models.Finding) string {
	c, _ := f.Evidence["issue_category"].(string)
	return c
}

func isCategory(cats ...string) func(models.Finding) bool {
	return func(f models.Finding) bool {
		c := issueCategory(f)
		for _, want := range cats {
			if c == want {
				return true
			}
		}
		return false
	}
}

var deltaSpecs = []deltaSpec{
	{
		Type: RuleNewOrphanedEdge, Label: "New takeover risks",
		Description: "Triggers when a DNS record, CloudFront origin or bucket reference newly points at something deleted or unclaimed (reclaimable) or that does not answer (dangling).",
		Singular:    "takeover risk", Plural: "takeover risks", Severity: SeverityWarning, BumpOnHigh: true,
		Match: func(f models.Finding) bool {
			return f.Module == models.ModuleOrphanedEdge && (f.Claimability == models.ClaimReclaimable || f.Claimability == models.ClaimDangling) &&
				(f.Severity == models.SeverityHigh || f.Severity == models.SeverityCritical)
		},
		Path: "/findings", Query: map[string]string{"module": "orphaned_edge"},
		ActionLabel: "Review takeover risks", Next: "Remove the reference, or recreate the resource in your own account. Each finding has the command.",
	},
	{
		Type: RuleNewEscalationPaths, Label: "New privilege-escalation paths",
		Description: "Triggers when a scan finds a privilege-escalation path (a principal that can reach more access) that the previous scan did not have.",
		Singular:    "privilege-escalation path", Plural: "privilege-escalation paths", Severity: SeverityWarning, BumpOnHigh: true,
		Match: isEscalation, Path: "/findings", Query: map[string]string{"search": "privilege_escalation"},
		ActionLabel: "Review escalation paths", Next: "Open each path to see which grant creates it.",
	},
	{
		Type: RuleNewPublicBucket, Label: "New public S3 buckets",
		Description: "Triggers when a bucket policy newly grants access to everyone.",
		Singular:    "public S3 bucket", Plural: "public S3 buckets", Severity: SeverityCritical,
		Match: func(f models.Finding) bool {
			public, _ := f.Evidence["is_public"].(bool)
			t, _ := f.Evidence["resource_type"].(string)
			return public && t == "s3_bucket"
		},
		Path: "/findings", Query: map[string]string{"module": "external_access"},
		ActionLabel: "Review public buckets", Next: "Check whether the bucket is meant to be public; if not, remove the public statement from its policy.",
	},
	{
		Type: RuleNewConsoleNoMFA, Label: "New console users without MFA",
		Description: "Triggers when an IAM user with a console password and no MFA device appears.",
		Singular:    "console user without MFA", Plural: "console users without MFA", Severity: SeverityWarning,
		Match: isCategory(ciem.CatUserNoMFA), Path: "/findings", Query: map[string]string{"search": ciem.CatUserNoMFA},
		ActionLabel: "Review users without MFA", Next: "Ask the user to enrol an MFA device or remove the console password.",
	},
	{
		Type: RuleNewKeyIssues, Label: "New access key issues",
		Description: "Triggers when a user has a newly found access key problem, such as an old or unused key.",
		Singular:    "access key issue", Plural: "access key issues", Severity: SeverityWarning,
		Match: isCategory(ciem.CatUserKeyHygiene), Path: "/findings", Query: map[string]string{"search": ciem.CatUserKeyHygiene},
		ActionLabel: "Review key issues", Next: "Rotate or delete the key named in each item.",
	},
	{
		Type: RuleNewAdminIdentities, Label: "New administrator identities",
		Description: "Triggers when a user or workload newly holds administrator access.",
		Singular:    "administrator identity", Plural: "administrator identities", Severity: SeverityCritical,
		Match: isCategory(ciem.CatUserAdministrative, ciem.CatWorkloadAdminRole),
		Path:  "/findings", Query: map[string]string{"search": "administrative"},
		ActionLabel: "Review administrators", Next: "Confirm each one needs full access, or replace it with a narrower policy.",
	},
}

func deltaSpecFor(t RuleType) (deltaSpec, bool) {
	for _, s := range deltaSpecs {
		if s.Type == t {
			return s, true
		}
	}
	return deltaSpec{}, false
}

// quiet turns a payload into the message for a run that found nothing to report.
func quiet(p AlertPayload, title, summary string) AlertPayload {
	p.Title, p.Summary, p.Severity = title, summary, SeverityInfo
	return p
}

// topItems returns up to three findings, highest priority first, each linking to its finding.
func (e *Evaluator) topItems(scanID string, findings []models.Finding) []AlertItem {
	sorted := append([]models.Finding(nil), findings...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return scorers.PriorityLess(sorted[i], sorted[j], scorers.PriorityScore(sorted[i]), scorers.PriorityScore(sorted[j]))
	})
	var out []AlertItem
	for _, f := range sorted {
		if len(out) == 3 {
			break
		}
		out = append(out, AlertItem{
			Title:  shortenTitle(f.Title, 90),
			Detail: joinNonEmpty(" · ", strings.ToUpper(string(f.Severity)), accountLabel(f)),
			URL:    e.url("/findings", map[string]string{"scan_id": scanID, "finding_id": f.ID}),
		})
	}
	return out
}

func accountLabel(f models.Finding) string {
	if f.AccountName != "" {
		return f.AccountName
	}
	return f.AccountID
}

func joinNonEmpty(sep string, parts ...string) string {
	var keep []string
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			keep = append(keep, p)
		}
	}
	return strings.Join(keep, sep)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// baselineMissing is the result of a delta rule on a first scan. It is said out loud so a quiet rule is not mistaken
// for a clean scan.
func (e *Evaluator) baselineMissing(rule AlertRule, scanID, label, path string, query map[string]string) AlertEvaluationResult {
	q := map[string]string{"scan_id": scanID}
	for k, v := range query {
		q[k] = v
	}
	payload := AlertPayload{
		Title:       label + ": no previous scan yet",
		Severity:    SeverityInfo,
		Summary:     "This is the first scan, so nothing can be called new yet. This rule starts working on the next scan.",
		ActionLabel: "Open findings",
		ActionURL:   e.url(path, q),
	}
	return makeResult(rule, scanID, false, payload, 0, map[string]any{"baseline_available": false})
}

func (e *Evaluator) evalDelta(rule AlertRule, scanID string, spec deltaSpec, findings []models.Finding) (AlertEvaluationResult, error) {
	q := map[string]string{"scan_id": scanID}
	for k, v := range spec.Query {
		q[k] = v
	}
	prev := e.previousScanID(scanID)
	if prev == "" {
		return e.baselineMissing(rule, scanID, spec.Label, spec.Path, spec.Query), nil
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
	severity := spec.Severity
	for _, f := range findings {
		if !spec.Match(f) {
			continue
		}
		if _, ok := oldIdx[diffIdentity(f)]; ok {
			continue
		}
		fresh = append(fresh, f)
		if s := strings.ToLower(string(f.Severity)); spec.BumpOnHigh && (s == "high" || s == "critical") {
			severity = SeverityCritical
		}
	}
	payload := AlertPayload{ActionLabel: spec.ActionLabel, ActionURL: e.url(spec.Path, q)}
	meta := map[string]any{"baseline_scan_id": prev}
	if len(fresh) == 0 {
		payload = quiet(payload, "No new "+spec.Plural, fmt.Sprintf("No new %s since scan %s.", spec.Plural, prev))
		return makeResult(rule, scanID, false, payload, 0, meta), nil
	}
	noun := plural(len(fresh), spec.Singular, spec.Plural)
	payload.Title = fmt.Sprintf("%d new %s", len(fresh), noun)
	payload.Severity = severity
	payload.Summary = fmt.Sprintf("%d %s appeared since scan %s.", len(fresh), noun, prev)
	payload.Items = e.topItems(scanID, fresh)
	payload.Bullets = cleanBullets([]string{topAccountBullet(fresh), spec.Next})
	return makeResult(rule, scanID, true, payload, len(fresh), meta), nil
}

// evalNewExposure compares what can be reached from the internet in this scan against the previous one.
func (e *Evaluator) evalNewExposure(rule AlertRule, scanID string) (AlertEvaluationResult, error) {
	label := "New internet-reachable resources"
	query := map[string]string{"scan_id": scanID, "internet_facing": "true"}
	prev := e.previousScanID(scanID)
	if prev == "" {
		return e.baselineMissing(rule, scanID, label, "/inventory", map[string]string{"internet_facing": "true"}), nil
	}
	allowed := normalizeScopeIDs(rule.Scope.AccountIDs)
	inScope := func(acct string) bool {
		if len(allowed) == 0 {
			return true
		}
		for _, a := range allowed {
			if a == acct {
				return true
			}
		}
		return false
	}
	reach := func(id string) (map[string]models.AssetNode, error) {
		assets, err := scans.LoadAssets(e.outputDir, id)
		if err != nil {
			return nil, err
		}
		rels, err := scans.LoadRelationships(e.outputDir, id)
		if err != nil {
			return nil, err
		}
		byARN := map[string]models.AssetNode{}
		for _, a := range assets {
			byARN[a.ARN] = a
		}
		out := map[string]models.AssetNode{}
		for arn, ex := range inventory.Exposures(assets, rels) {
			if a, ok := byARN[arn]; ok && ex.Internet && inScope(a.AccountID) {
				out[arn] = a
			}
		}
		return out, nil
	}
	now, err := reach(scanID)
	if err != nil {
		return AlertEvaluationResult{}, err
	}
	before, err := reach(prev)
	if err != nil {
		return AlertEvaluationResult{}, err
	}
	var fresh []models.AssetNode
	for arn, a := range now {
		if _, ok := before[arn]; !ok {
			fresh = append(fresh, a)
		}
	}
	sort.Slice(fresh, func(i, j int) bool { return fresh[i].ARN < fresh[j].ARN })
	payload := AlertPayload{ActionLabel: "Review exposed resources", ActionURL: e.url("/inventory", query)}
	meta := map[string]any{"baseline_scan_id": prev, "reachable_now": len(now)}
	if len(fresh) == 0 {
		payload = quiet(payload, "No new internet-reachable resources", fmt.Sprintf("Nothing new can be reached from the internet since scan %s (%d reachable now).", prev, len(now)))
		return makeResult(rule, scanID, false, payload, 0, meta), nil
	}
	noun := plural(len(fresh), "resource", "resources")
	payload.Title = fmt.Sprintf("%d new internet-reachable %s", len(fresh), noun)
	payload.Severity = SeverityCritical
	payload.Summary = fmt.Sprintf("%d %s can now be reached from the internet since scan %s.", len(fresh), noun, prev)
	for i, a := range fresh {
		if i == 3 {
			break
		}
		payload.Items = append(payload.Items, AlertItem{
			Title:  fmt.Sprintf("%s (%s)", a.Name, strings.ReplaceAll(string(a.AssetType), "_", " ")),
			Detail: joinNonEmpty(" · ", a.AccountID, a.Region),
			URL:    e.url("/inventory", query),
		})
	}
	payload.Bullets = cleanBullets([]string{"Check the security group rule or public setting that opened it."})
	return makeResult(rule, scanID, true, payload, len(fresh), meta), nil
}
