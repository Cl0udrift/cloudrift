package scorers

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// EntitlementCandidate is one sensitive pattern or evidence gap from a collected
// identity policy. It references the policy asset. It does not copy the document
// and it is not an authorization decision.
type EntitlementCandidate struct {
	ScanID                 string
	RoleARN                string
	Category               string
	PolicyType             string
	PolicyARN              string
	PolicyVersion          string
	StatementID            string
	StatementIndex         int
	Effect                 string
	Actions                []string
	NotActions             []string
	Resources              []string
	NotResources           []string
	Conditions             map[string]any
	EvidenceState          string
	ConditionStatus        string
	VersionVerification    string
	RetrievalStatus        string
	DocumentFingerprint    string
	EvidenceFingerprint    string
	Eligible               bool
	EvaluationAvailability string
	ActionSensitivity      string
	ResourceBreadth        string
	ExposureClass          string
	AssessmentVersion      string
	Note                   string
}

const AssessmentVersion = "4f-final.2"

// ExtractEntitlementCandidates is the shared document-backed contract for identity
// profiles and scan-time declared-exposure findings. Policy names are ignored.
func ExtractEntitlementCandidates(scanID string, role models.AssetNode, assets []models.AssetNode, rels []models.Relationship) []EntitlementCandidate {
	var out []EntitlementCandidate
	seen := map[string]struct{}{}
	add := func(item EntitlementCandidate) {
		item.ScanID = scanID
		item.RoleARN = role.ARN
		item.AssessmentVersion = AssessmentVersion
		item.EvaluationAvailability = "not_evaluated"
		item.Eligible = eligibleCandidate(item)
		if item.EvidenceFingerprint == "" {
			item.EvidenceFingerprint = candidateFingerprint(item)
		}
		if _, ok := seen[item.EvidenceFingerprint]; ok {
			return
		}
		seen[item.EvidenceFingerprint] = struct{}{}
		out = append(out, item)
	}
	sources := resolvePolicyConflicts(policySources(scanID, role, assets, rels))
	if !hasInlineSource(sources) {
		for i, raw := range stringSliceProperty(role.Properties, "inline_policy_documents") {
			verification := models.PolicyVersionUnverified
			if flag, ok := role.Properties["inline_policy_version_verification"].(string); ok && flag != "" {
				verification = flag
			}
			sources = append(sources, policySource{
				PolicyType: models.PolicyTypeInline, PolicyARN: "inline:" + role.ARN + ":" + strconv.Itoa(i),
				Document: raw, Status: models.PolicyRetrievalOK, Verification: verification,
			})
		}
	}
	for _, source := range sources {
		addSource(add, role, source)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.PolicyARN != b.PolicyARN {
			return a.PolicyARN < b.PolicyARN
		}
		if a.StatementIndex != b.StatementIndex {
			return a.StatementIndex < b.StatementIndex
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		return a.EvidenceFingerprint < b.EvidenceFingerprint
	})
	return out
}

type policySource struct {
	PolicyType   string
	PolicyARN    string
	Version      string
	Document     string
	Status       string
	Verification string
	Fingerprint  string
	Stale        bool
	Conflict     bool
}

func policySources(scanID string, role models.AssetNode, assets []models.AssetNode, rels []models.Relationship) []policySource {
	attached := map[string]struct{}{}
	for _, rel := range rels {
		if rel.RelType != models.RelPolicyAttachedTo || rel.SourceARN != role.ARN {
			continue
		}
		if rel.ScanID != "" && scanID != "" && rel.ScanID != scanID {
			continue
		}
		attached[rel.TargetARN] = struct{}{}
	}
	var out []policySource
	for _, asset := range assets {
		if asset.AssetType != models.AssetIAMPolicy {
			continue
		}
		if asset.ScanID != "" && scanID != "" && asset.ScanID != scanID {
			continue
		}
		linked := propertyString(asset.Properties, "attached_role_arn") == role.ARN
		if _, ok := attached[asset.ARN]; ok {
			linked = true
		}
		if !linked {
			continue
		}
		policyType := propertyString(asset.Properties, "policy_type")
		switch {
		case policyType == models.PolicyTypeInline:
			policyType = models.PolicyTypeInline
		case strings.Contains(asset.ARN, ":iam::aws:policy/"):
			policyType = "aws_managed"
		default:
			policyType = "customer_managed"
		}
		status := propertyString(asset.Properties, "retrieval_status")
		if status == "" {
			status = models.PolicyRetrievalOK
		}
		verification := propertyString(asset.Properties, "policy_version_verification")
		if verification == "" {
			if policyType == models.PolicyTypeInline && status == models.PolicyRetrievalOK {
				verification = models.PolicyVersionNotApplicable
			} else {
				verification = models.PolicyVersionUnverified
			}
		}
		stale := false
		if current, ok := asset.Properties["policy_version_current"].(bool); ok && !current {
			stale = true
		}
		version := propertyString(asset.Properties, "policy_version_id")
		if verification == models.PolicyVersionVerified && policyType != models.PolicyTypeInline && version == "" {
			verification = models.PolicyVersionMissing // verified claim without a version id is not verified evidence
		}
		out = append(out, policySource{
			PolicyType: policyType, PolicyARN: asset.ARN,
			Version:  version,
			Document: propertyString(asset.Properties, "policy_document"),
			Status:   status, Verification: verification, Stale: stale,
			Fingerprint: propertyString(asset.Properties, "policy_document_fingerprint"),
		})
	}
	return out
}

func hasInlineSource(sources []policySource) bool {
	for _, source := range sources {
		if source.PolicyType == models.PolicyTypeInline {
			return true
		}
	}
	return false
}

func addSource(add func(EntitlementCandidate), role models.AssetNode, source policySource) {
	base := EntitlementCandidate{
		PolicyType: source.PolicyType, PolicyARN: source.PolicyARN, PolicyVersion: source.Version,
		VersionVerification: source.Verification, RetrievalStatus: source.Status,
		DocumentFingerprint: source.Fingerprint,
	}
	if source.Conflict {
		base.EvidenceState = models.EvidenceUnknown
		base.Note = "Duplicate observations disagree on the policy document. Neither document is used as a confident Allow."
		add(base)
		return
	}
	if source.Stale || source.Verification == models.PolicyVersionMismatch || source.Verification == models.PolicyVersionIndeterminate || source.Verification == models.PolicyVersionMissing {
		base.EvidenceState = models.EvidenceUnknown
		base.Note = "Policy version provenance is not sufficient for a declared exposure finding."
		add(base)
		return
	}
	if source.Status == models.PolicyRetrievalMalformed {
		base.EvidenceState = models.EvidenceUnknown
		base.Note = "The policy document could not be normalized."
		add(base)
		return
	}
	if source.Status == models.PolicyRetrievalMissing || strings.TrimSpace(source.Document) == "" {
		base.EvidenceState = models.EvidenceUnknown
		base.VersionVerification = models.PolicyVersionMissing
		base.Note = "The policy attachment was collected without a default-version document. A missing document is not an empty policy."
		add(base)
		return
	}
	statements, err := models.NormalizeIdentityPolicy(source.PolicyARN, source.PolicyType, role.AccountID, source.Document)
	if err != nil {
		base.EvidenceState = models.EvidenceUnknown
		base.Note = "The policy document could not be normalized."
		add(base)
		return
	}
	for index, stmt := range statements {
		item := base
		item.StatementID = stmt.StatementID
		item.StatementIndex = index
		item.Effect = stmt.Effect
		item.Actions = stmt.Action
		item.NotActions = stmt.NotAction
		item.Resources = stmt.Resource
		item.NotResources = stmt.NotResource
		item.Conditions = stmt.Condition
		if !strings.EqualFold(stmt.Effect, "Allow") {
			item.EvidenceState = models.EvidenceDeny
			item.Note = "Explicit Deny is retained as evidence. It is not an Allow candidate and it is not evaluated authorization."
			add(item)
			continue
		}
		if len(stmt.NotAction) > 0 || len(stmt.NotResource) > 0 {
			item.EvidenceState = models.EvidenceUnsupported
			item.ConditionStatus = "unsupported"
			item.Note = "NotAction or NotResource keeps the statement out of ordinary Allow classification."
			add(item)
			continue
		}
		item.ConditionStatus = conditionClass(stmt.Condition)
		item.ResourceBreadth = resourceBreadth(stmt.Resource)
		shapes := actionShapes(stmt.Action, item.ResourceBreadth)
		if len(shapes) == 0 {
			continue
		}
		item.EvidenceState = models.EvidenceDeclared
		item.ExposureClass = "unconditional"
		item.Note = "Declared from the collected policy document. This is not evaluated authorization."
		switch item.ConditionStatus {
		case "unsupported":
			item.EvidenceState = models.EvidenceUnsupported
			item.ExposureClass = "unsupported"
			item.Note = "The statement has an unsupported condition. It stays uncertain and it is not validated access."
		case "conditional":
			item.EvidenceState = models.EvidenceConditional
			item.ExposureClass = "conditional"
			item.Note = "The statement has a supported condition. The condition is not assumed to be satisfied, and this is not evaluated authorization."
		}
		if !broadBreadth(item.ResourceBreadth) && item.ExposureClass != "unsupported" {
			item.ExposureClass = "narrow"
			item.Note = "The action is sensitive and the resource scope is narrower than a service-wide or global wildcard. It is visible and it is not a broad-exposure finding."
		}
		if source.Verification == models.PolicyVersionUnverified && (item.EvidenceState == models.EvidenceDeclared || item.EvidenceState == models.EvidenceConditional) {
			item.Note = "The document is in the stored snapshot. Version verification was not recorded, so this is not a confirmed declared-exposure finding."
		}
		for _, shape := range shapes {
			next := item
			next.Category = shape.category
			next.ActionSensitivity = shape.sensitivity
			add(next)
		}
	}
}

type actionShape struct {
	category    string
	sensitivity string
}

// Representative sensitive actions. A pattern classifies a category when it matches
// one of them under IAM wildcard rules (case-insensitive, * and ?).
var (
	s3ReadActions   = []string{"s3:getobject", "s3:getobjectversion"}
	s3WriteActions  = []string{"s3:putobject"}
	s3DeleteActions = []string{"s3:deleteobject", "s3:deleteobjectversion"}
)

func actionShapes(actions []string, breadth string) []actionShape {
	lower := lowerValues(actions)
	broad := broadBreadth(breadth)
	pick := func(broadName, narrowName, sensitivity string) actionShape {
		category := narrowName
		if broad {
			category = broadName
		}
		return actionShape{category: category, sensitivity: sensitivity}
	}
	matchesAny := func(targets ...string) bool {
		for _, pattern := range lower {
			for _, target := range targets {
				if globMatch(pattern, target) {
					return true
				}
			}
		}
		return false
	}
	var out []actionShape
	adminAll := containsValue(lower, "*") || containsValue(lower, "*:*")
	if adminAll || containsValue(lower, "iam:*") {
		out = append(out, pick("administrative_wildcard", "administrative_scoped", "administrative_wildcard"))
	}
	if adminAll {
		return out
	}
	if containsValue(lower, "s3:*") {
		out = append(out, pick("broad_s3_access", "s3_wildcard", "s3_wildcard"))
	} else {
		if matchesAny(s3ReadActions...) {
			out = append(out, actionShape{category: "s3_read", sensitivity: "s3_read"})
		}
		if matchesAny(s3WriteActions...) {
			out = append(out, actionShape{category: "s3_write", sensitivity: "s3_write"})
		}
		if matchesAny(s3DeleteActions...) {
			out = append(out, actionShape{category: "s3_delete", sensitivity: "s3_delete"})
		}
	}
	if matchesAny("sts:assumerole") {
		out = append(out, pick("broad_assume_role", "assume_role", "assume_role"))
	}
	if !containsValue(lower, "iam:*") {
		if matchesAny("iam:passrole") {
			out = append(out, pick("broad_passrole", "pass_role", "pass_role"))
		}
		if matchesAny("iam:attachrolepolicy") {
			out = append(out, pick("iam_policy_modification", "iam_policy_modification_scoped", "iam_policy_modification"))
		}
	}
	return out
}

// globMatch implements IAM action wildcard matching on lowercase inputs.
func globMatch(pattern, value string) bool {
	p, v := 0, 0
	star, mark := -1, 0
	for v < len(value) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == value[v]):
			p++
			v++
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, v
			p++
		case star >= 0:
			p = star + 1
			mark++
			v = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

func broadBreadth(breadth string) bool {
	return breadth == "global_wildcard" || breadth == "service_or_account_wide"
}

func resourceBreadth(resources []string) string {
	if len(resources) == 0 {
		return "unknown"
	}
	best := "explicit"
	for _, resource := range resources {
		next := oneResourceBreadth(resource)
		if breadthRank(next) > breadthRank(best) {
			best = next
		}
	}
	return best
}

func oneResourceBreadth(resource string) string {
	value := strings.ToLower(strings.TrimSpace(resource))
	if value == "*" {
		return "global_wildcard"
	}
	if value == "" {
		return "unknown"
	}
	if !strings.ContainsAny(value, "*?") {
		return "explicit"
	}
	if serviceOrAccountWide(value) {
		return "service_or_account_wide"
	}
	return "prefix"
}

func serviceOrAccountWide(value string) bool {
	parts := strings.SplitN(value, ":", 6)
	if len(parts) < 6 || parts[0] != "arn" {
		return strings.Trim(value, "*?") == ""
	}
	resource := parts[5]
	for _, token := range strings.FieldsFunc(resource, func(r rune) bool {
		return r == '/' || r == '*' || r == '?'
	}) {
		switch token {
		case "", "role", "user", "group", "policy", "instance-profile":
		default:
			return false
		}
	}
	return true
}

func breadthRank(breadth string) int {
	switch breadth {
	case "global_wildcard":
		return 4
	case "service_or_account_wide":
		return 3
	case "prefix":
		return 2
	case "explicit":
		return 1
	default:
		return 0
	}
}

func eligibleCandidate(item EntitlementCandidate) bool {
	if !eligibleVersion(item.VersionVerification) {
		return false
	}
	if item.EvidenceState != models.EvidenceDeclared && item.EvidenceState != models.EvidenceConditional {
		return false
	}
	return broadBreadth(item.ResourceBreadth)
}

func resolvePolicyConflicts(sources []policySource) []policySource {
	grouped := map[string][]policySource{}
	var order []string
	for _, source := range sources {
		if _, ok := grouped[source.PolicyARN]; !ok {
			order = append(order, source.PolicyARN)
		}
		grouped[source.PolicyARN] = append(grouped[source.PolicyARN], source)
	}
	out := make([]policySource, 0, len(order))
	for _, arn := range order {
		group := grouped[arn]
		docs := map[string]struct{}{}
		for _, source := range group {
			// Version, verification and status are material provenance, not only the document.
			docs[strings.Join([]string{strings.TrimSpace(source.Document), source.Version, source.Verification, source.Status}, "\x00")] = struct{}{}
		}
		if len(docs) > 1 {
			chosen := group[0]
			chosen.Conflict = true
			chosen.Document = ""
			out = append(out, chosen)
			continue
		}
		out = append(out, group[0])
	}
	return out
}

func eligibleVersion(verification string) bool {
	return verification == models.PolicyVersionVerified || verification == models.PolicyVersionNotApplicable
}

// candidateFingerprint covers every material input, including the exact condition,
// and is independent of action/resource ordering inside a statement.
func candidateFingerprint(item EntitlementCandidate) string {
	cond, _ := json.Marshal(item.Conditions) // map keys marshal sorted
	sum := sha256.Sum256([]byte(strings.Join([]string{
		item.RoleARN, item.PolicyARN, item.PolicyVersion, item.StatementID, strconv.Itoa(item.StatementIndex),
		item.Category, item.Effect, item.EvidenceState, item.ResourceBreadth, item.ConditionStatus,
		item.VersionVerification, item.RetrievalStatus, item.DocumentFingerprint,
		sortedJoin(item.Actions), sortedJoin(item.NotActions), sortedJoin(item.Resources), sortedJoin(item.NotResources),
		string(cond),
	}, "|")))
	return hex.EncodeToString(sum[:8])
}

func sortedJoin(values []string) string {
	cp := append([]string(nil), values...)
	sort.Strings(cp)
	return strings.Join(cp, ",")
}

func conditionClass(condition map[string]any) string {
	if len(condition) == 0 {
		return "none"
	}
	for operator := range condition {
		base := operator
		if i := strings.Index(base, ":"); i >= 0 {
			base = base[:i]
		}
		base = strings.TrimSuffix(base, "IfExists")
		switch base {
		case "StringEquals", "StringNotEquals", "ArnEquals", "ArnLike", "Bool", "Null":
		default:
			return "unsupported"
		}
	}
	return "conditional"
}

func propertyString(props map[string]any, key string) string {
	if props == nil {
		return ""
	}
	value, _ := props[key].(string)
	return value
}

func lowerValues(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, strings.ToLower(strings.TrimSpace(value)))
	}
	return out
}

func containsValue(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
