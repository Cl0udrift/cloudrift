package handlers

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/ciem"
	"github.com/Zero0x00/cloudrift/internal/inventory"
	"github.com/Zero0x00/cloudrift/internal/models"
)

const adminCategory = "administrative_wildcard"

func hasAdmin(broad []string) bool {
	for _, b := range broad {
		if b == adminCategory {
			return true
		}
	}
	return false
}

// callerFacts is what the access page shows about an identity beside the route that gives it access.
type callerFacts struct {
	admin          bool
	usage          string
	consoleNoMFA   bool
	keyIssues      int
	lastActivity   string
	findings       int
	maxSeverity    string
	externalTrust  bool
	consoleNoMFAOK bool
}

// identityFacts indexes every user and role by ARN. Users come from the principal list; roles from the role summary,
// computed once per request.
func identityFacts(scanID string, assets []models.AssetNode, rels []models.Relationship, findings []models.Finding, only map[string]bool) map[string]callerFacts {
	out := map[string]callerFacts{}
	for _, p := range ciem.ListPrincipals(scanID, assets, rels, time.Now()) {
		if only != nil && !only[p.ARN] {
			continue
		}
		worst, refs := principalFindings(p.ARN, findings)
		out[p.ARN] = callerFacts{
			admin: hasAdmin(p.BroadCandidates), usage: p.Usage,
			consoleNoMFA: p.Kind == "user" && p.CredentialsCollected && p.Console && !p.MFA, consoleNoMFAOK: p.CredentialsCollected,
			keyIssues: p.KeyIssues, lastActivity: p.LastActivity, findings: len(refs), maxSeverity: worst,
		}
	}
	for _, a := range assets {
		if a.AssetType != models.AssetIAMRole || (only != nil && !only[a.ARN]) {
			continue
		}
		item := ciem.SummarizeRole(a, assets, rels)
		worst, refs := principalFindings(a.ARN, findings)
		usage := "role"
		if item.WorkloadCount > 0 {
			usage = "workload"
		}
		ext := false
		for _, c := range item.Classifications {
			if c == ciem.ClassExternalDelegated {
				ext = true
			}
		}
		out[a.ARN] = callerFacts{admin: hasAdmin(item.BroadCandidates), usage: usage, findings: len(refs), maxSeverity: worst, externalTrust: ext}
	}
	return out
}

// via names the group and policy that give a caller its access, so callers that share a route can be grouped.
func via(c schema.RoleAssumer) string {
	if len(c.Paths) == 0 {
		return ""
	}
	var parts []string
	for _, s := range c.Paths[0].Steps {
		if s.Kind == "group" || s.Kind == "policy" || s.Kind == "trust" {
			parts = append(parts, s.Label)
		}
	}
	return strings.Join(parts, " / ")
}

// enrichCallers adds who each caller is and how risky it already looks, then orders them: specific grants first, then
// administrators, so a narrow permission is not buried among expected administrator access.
func enrichCallers(callers []schema.RoleAssumer, facts map[string]callerFacts) {
	for i := range callers {
		f := facts[callers[i].ARN]
		callers[i].Admin, callers[i].Usage, callers[i].ConsoleNoMFA = f.admin, f.usage, f.consoleNoMFA
		callers[i].KeyIssues, callers[i].LastActivity, callers[i].FindingCount, callers[i].MaxSeverity = f.keyIssues, f.lastActivity, f.findings, f.maxSeverity
		callers[i].Via = via(callers[i])
	}
	sort.SliceStable(callers, func(i, j int) bool {
		if callers[i].Admin != callers[j].Admin {
			return !callers[i].Admin
		}
		if callers[i].Self != callers[j].Self {
			return !callers[i].Self
		}
		return false
	})
}

// accessIndex is everything the access page derives from one scan, computed once: who each identity is, why it is worth
// asking about, and the ready questions. Building it costs about a second per few thousand identities, so it is cached.
type accessIndex struct {
	facts       map[string]callerFacts
	hints       map[string]string
	suggestions []schema.AccessSuggestion
}

func buildAccessIndex(scanID string, assets []models.AssetNode, rels []models.Relationship, findings []models.Finding) *accessIndex {
	facts := identityFacts(scanID, assets, rels, findings, nil)
	groupAdmin := map[string]bool{}
	for _, p := range ciem.ListPrincipals(scanID, assets, rels, time.Now()) {
		if p.Kind == "group" && hasAdmin(p.BroadCandidates) {
			groupAdmin[p.ARN] = true
		}
	}
	return &accessIndex{facts: facts, hints: targetHints(facts, groupAdmin, assets), suggestions: accessSuggestions(facts, groupAdmin, assets)}
}

var accessCache = struct {
	sync.Mutex
	m     map[string]*accessIndex
	order []string
}{m: map[string]*accessIndex{}}

// accessIndexFor returns the cached index for a scan. A scan is written once and never edited, so its id with the sizes of
// what was loaded is a sufficient key; a rescan is a new scan id.
func accessIndexFor(scanID string, assets []models.AssetNode, rels []models.Relationship, findings []models.Finding) *accessIndex {
	key := fmt.Sprintf("%s/%d/%d/%d", scanID, len(assets), len(rels), len(findings))
	accessCache.Lock()
	if idx, ok := accessCache.m[key]; ok {
		accessCache.Unlock()
		return idx
	}
	accessCache.Unlock()
	idx := buildAccessIndex(scanID, assets, rels, findings)
	accessCache.Lock()
	defer accessCache.Unlock()
	accessCache.m[key] = idx
	accessCache.order = append(accessCache.order, key)
	if len(accessCache.order) > 4 {
		delete(accessCache.m, accessCache.order[0])
		accessCache.order = accessCache.order[1:]
	}
	return idx
}

// targetHints says why each identity is worth asking about. AWS-owned roles are marked so they can be left out.
func targetHints(facts map[string]callerFacts, groupAdmin map[string]bool, assets []models.AssetNode) map[string]string {
	out := map[string]string{}
	for _, a := range assets {
		f := facts[a.ARN]
		switch {
		case a.AssetType == models.AssetIAMGroup && groupAdmin[a.ARN]:
			out[a.ARN] = "Administrator access"
		case f.admin:
			out[a.ARN] = "Administrator access"
		case f.externalTrust:
			out[a.ARN] = "Trusts an outside account"
		case f.consoleNoMFA:
			out[a.ARN] = "Console without MFA"
		case f.maxSeverity != "":
			out[a.ARN] = "Has " + f.maxSeverity + " finding"
		case inventory.IsAWSManaged(a):
			out[a.ARN] = "AWS-managed"
		}
	}
	return out
}

func hintRank(h string) int {
	switch h {
	case "Administrator access":
		return 0
	case "Trusts an outside account":
		return 1
	case "Console without MFA":
		return 2
	case "":
		return 4
	case "AWS-managed":
		return 5
	}
	return 3
}

// accessSuggestions builds up to eight ready questions from what this scan holds, riskiest first.
func accessSuggestions(facts map[string]callerFacts, groupAdmin map[string]bool, assets []models.AssetNode) []schema.AccessSuggestion {
	var out []schema.AccessSuggestion
	add := func(a models.AssetNode, kind, action, title, why string) {
		out = append(out, schema.AccessSuggestion{Title: title, Why: why, ARN: a.ARN, Action: action, TargetName: a.Name, Kind: kind})
	}
	byName := func(kind models.AssetType, pred func(models.AssetNode) bool) []models.AssetNode {
		var list []models.AssetNode
		for _, a := range assets {
			if a.AssetType == kind && pred(a) && !inventory.IsAWSManaged(a) {
				list = append(list, a)
			}
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
		return list
	}
	for _, r := range byName(models.AssetIAMRole, func(a models.AssetNode) bool { return facts[a.ARN].admin }) {
		add(r, "role", "sts:AssumeRole", "Who can assume "+r.Name+"?", "It holds administrator access")
	}
	for _, r := range byName(models.AssetIAMRole, func(a models.AssetNode) bool { return facts[a.ARN].externalTrust && !facts[a.ARN].admin }) {
		add(r, "role", "sts:AssumeRole", "Who can assume "+r.Name+"?", "Its trust policy names an outside account")
	}
	for _, u := range byName(models.AssetIAMUser, func(a models.AssetNode) bool { return facts[a.ARN].admin }) {
		add(u, "user", "iam:CreateAccessKey", "Who can create an access key for "+u.Name+"?", "It is an administrator, so a new key would be administrator access")
	}
	for _, u := range byName(models.AssetIAMUser, func(a models.AssetNode) bool { return facts[a.ARN].consoleNoMFA && !facts[a.ARN].admin }) {
		add(u, "user", "iam:UpdateLoginProfile", "Who can change "+u.Name+"'s console password?", "It signs in with a password and no MFA")
	}
	for _, g := range byName(models.AssetIAMGroup, func(a models.AssetNode) bool { return groupAdmin[a.ARN] }) {
		add(g, "group", "iam:AddUserToGroup", "Who can add users to "+g.Name+"?", "Its members get administrator access")
	}
	for _, b := range byName(models.AssetS3Bucket, func(a models.AssetNode) bool { return ciem.BucketLooksLikeLogs(a) }) {
		add(b, "bucket", "s3:DeleteObject", "Who can delete objects in "+strings.TrimPrefix(b.ARN, "arn:aws:s3:::")+"?", "Its name suggests audit logs; deleting them hides activity")
	}
	for _, sec := range byName(models.AssetSecret, func(models.AssetNode) bool { return true }) {
		add(sec, "secret", "secretsmanager:GetSecretValue", "Who can read the secret "+sec.Name+"?", "A secret holds a credential or key")
	}
	// Keep a spread: two of each kind of question before filling the rest.
	seen := map[string]int{}
	var picked, rest []schema.AccessSuggestion
	for _, s := range out {
		if seen[s.Action] < 2 {
			seen[s.Action]++
			picked = append(picked, s)
		} else {
			rest = append(rest, s)
		}
	}
	picked = append(picked, rest...)
	if len(picked) > 8 {
		picked = picked[:8]
	}
	if picked == nil {
		picked = []schema.AccessSuggestion{}
	}
	return picked
}

// GetAccessSuggestions returns ready questions for the access page, built from what the scan holds.
func GetAccessSuggestions(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scanID, _, assets, rels, findings, ok := loadInventoryScan(w, r, outputDir)
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"scan_id": scanID, "items": accessIndexFor(scanID, assets, rels, findings).suggestions})
	}
}
