package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Zero0x00/cloudrift/internal/collectors"
	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/scans"
)

const (
	syntheticDataOrigin = "synthetic-demo"
	demoAcctCore        = "111111111111"
	demoAcctData        = "222222222222"
)

// demoOptions selects additive security fixtures. Empty scenario and profile
// legacy reproduce the original demo scan.
type demoOptions struct {
	Scenario                string
	Profile                 string
	Seed                    int
	IncludeSecurityFixtures bool
	Dense                   bool
}

// DemoScenario describes one reusable fixture. Expected behavior is documentation
// for tests; it is not written into scan assets or authorization results.
type DemoScenario struct {
	ID          string
	Title       string
	Description string
	Category    string
	Expected    string
}

func securityScenarioCatalog() []DemoScenario {
	return []DemoScenario{
		{ID: "iam-01", Title: "Administrative role", Category: "iam", Description: "Identity policy allows action * on resource * with observed boundary, session, SCP, and RCP absence.", Expected: "Supported concrete requests are evaluated from the document. Catalog-only actions stay unsupported."},
		{ID: "iam-02", Title: "Administrator with explicit Deny", Category: "iam", Description: "Broad Allow plus an explicit Deny for one object.", Expected: "The matching request is denied."},
		{ID: "iam-03", Title: "Administrator with missing SCP", Category: "iam", Description: "Administrative identity document with SCP evidence missing.", Expected: "No validated allow while SCP evidence is required and missing."},
		{ID: "iam-04", Title: "Restricted administrator", Category: "iam", Description: "Object read allow and an SCP deny for iam:*.", Expected: "GetObject is distinct from the denied IAM action."},
		{ID: "iam-05", Title: "Permissions boundary", Category: "iam", Description: "Boundary document allows only s3:GetObject.", Expected: "The boundary is evaluated."},
		{ID: "iam-05b", Title: "Boundary document unavailable", Category: "iam", Description: "Boundary ARN is present and the document was not retrieved.", Expected: "The request stays unknown."},
		{ID: "iam-06", Title: "Conditional policy", Category: "iam", Description: "StringEquals on aws:RequestedRegion. The scan stores the condition, not a decision.", Expected: "Satisfied, unsatisfied, and missing context are supplied by the analyzer request."},
		{ID: "iam-07", Title: "Cross-account AssumeRole", Category: "iam", Description: "Caller identity allow and target trust allow.", Expected: "Assumption is evaluated when both documents match."},
		{ID: "iam-08", Title: "Trust without caller authorization", Category: "iam", Description: "Target trust allows the caller. The caller has no AssumeRole allow.", Expected: "No validated AssumeRole."},
		{ID: "iam-09", Title: "Target trust explicit Deny", Category: "iam", Description: "Caller allow and target trust deny.", Expected: "The assumption is denied."},
		{ID: "iam-10-denied", Title: "Policy retrieval AccessDenied", Category: "iam", Description: "GetPolicy was denied.", Expected: "Failure is not confirmed absence."},
		{ID: "iam-10-missing", Title: "Missing managed policy version", Category: "iam", Description: "The policy version document was not returned.", Expected: "Failure is not confirmed absence."},
		{ID: "iam-10-malformed", Title: "Malformed policy document", Category: "iam", Description: "The retrieved document is not a policy.", Expected: "The policy stays malformed."},
		{ID: "iam-10-empty", Title: "Empty policy inventory", Category: "iam", Description: "List calls succeeded and returned no policies.", Expected: "Confirmed empty inventory is distinct from a retrieval failure."},
		{ID: "iam-session-missing", Title: "Missing session policy", Category: "iam", Description: "Identity allow with no session observation.", Expected: "An assumed session is not confirmed absence."},
		{ID: "s3-01", Title: "Same-account object read", Category: "s3", Description: "Identity allow, complete controls, and a collected object.", Expected: "GetObject is evaluated for that object."},
		{ID: "s3-02", Title: "Cross-account object read", Category: "s3", Description: "Caller identity allow and a matching bucket policy allow.", Expected: "Both documents are required."},
		{ID: "s3-03", Title: "Explicit bucket-policy Deny", Category: "s3", Description: "Bucket policy deny for GetObject.", Expected: "The deny matches that action."},
		{ID: "s3-04", Title: "No bucket policy", Category: "s3", Description: "GetBucketPolicy returned NoSuchBucketPolicy.", Expected: "Absence is confirmed for that observation."},
		{ID: "s3-05", Title: "Bucket-policy AccessDenied", Category: "s3", Description: "GetBucketPolicy was denied.", Expected: "The document is missing, not absent."},
		{ID: "s3-06", Title: "BucketOwnerEnforced", Category: "s3", Description: "Ownership controls report BucketOwnerEnforced.", Expected: "Object ACLs are not applicable under the modeled rule."},
		{ID: "s3-07", Title: "Incomplete object ownership", Category: "s3", Description: "Ownership controls were not observed.", Expected: "ACL-dependent access is not validated."},
		{ID: "s3-08", Title: "SSE-S3", Category: "s3", Description: "Bucket encryption is AES256.", Expected: "A customer KMS key policy is not required for that observation."},
		{ID: "s3-09", Title: "SSE-KMS", Category: "s3", Description: "Bucket encryption is aws:kms and no key policy was collected.", Expected: "KMS authorization stays unresolved."},
		{ID: "s3-10", Title: "Bucket without object inventory", Category: "s3", Description: "The bucket was collected and no object was.", Expected: "Object scope stays possible, not confirmed."},
		{ID: "s3-11", Title: "Block Public Access", Category: "s3", Description: "Bucket BPA is confirmed absent. Account BPA was not collected.", Expected: "The bucket observation does not prove the account configuration."},
		{ID: "s3-12", Title: "Multiple actions", Category: "s3", Description: "GetObject and PutObject allow, DeleteObject deny, on one object.", Expected: "Each action is evaluated on its own."},
		{ID: "inventory", Title: "Unsupported service inventory", Category: "inventory", Description: "EC2, Lambda, Secrets Manager, RDS, network, and KMS placeholders.", Expected: "No validated decision is emitted for unsupported actions."},
	}
}

func knownScenario(id string) bool {
	for _, item := range securityScenarioCatalog() {
		if item.ID == id {
			return true
		}
	}
	for _, item := range attackScenarioIDs() {
		if item == id {
			return true
		}
	}
	for _, item := range ciemScenarioIDs() {
		if item == id {
			return true
		}
	}
	for _, item := range identityScenarioIDs() {
		if item == id {
			return true
		}
	}
	for _, item := range workloadScenarioIDs() {
		if item == id {
			return true
		}
	}
	for _, item := range containerScenarioIDs() {
		if item == id {
			return true
		}
	}
	return false
}

func ciemScenarioIDs() []string {
	return []string{
		"ciem-broad", "ciem-stale", "ciem-multi", "ciem-bucket", "ciem-chain", "ciem-scp", "ciem-scope",
		"ciem-scp-union", "ciem-scp-ancestor", "ciem-scp-deny", "ciem-scp-gap", "ciem-scp-implicit",
		"ciem-rcp-cross", "ciem-rcp-assume", "ciem-mgmt", "ciem-scp-moved",
	}
}

func attackScenarioIDs() []string {
	return []string{
		"attack-chain", "attack-trust-deny", "attack-no-caller", "attack-caller-session",
		"attack-target-session", "attack-mfa", "attack-external-id", "attack-cross",
		"attack-cycle", "attack-multipath", "attack-history-open", "attack-history-closed",
		"attack-no-read", "attack-federated", "attack-missing-scp",
	}
}

func securityScenarioIDs(profile, scenario string, include bool) []string {
	if scenario != "" && scenario != "all" && scenario != "history" {
		return []string{scenario}
	}
	small := []string{"iam-01", "iam-02", "s3-01", "s3-04"}
	switch strings.ToLower(profile) {
	case "small":
		return small
	case "medium", "stress":
		return allSecurityScenarioIDs()
	}
	if include || scenario == "all" {
		return allSecurityScenarioIDs()
	}
	return nil
}

func allSecurityScenarioIDs() []string {
	out := make([]string, 0, len(securityScenarioCatalog()))
	for _, item := range securityScenarioCatalog() {
		out = append(out, item.ID)
	}
	return out
}

func wantsHistory(opt demoOptions) bool {
	if opt.Scenario == "history" {
		return true
	}
	switch strings.ToLower(opt.Profile) {
	case "medium", "stress":
		return true
	default:
		return false
	}
}

func generateDemoScanWithOptions(outputDir string, t time.Time, fixedScanID string, opt demoOptions) (string, error) {
	if opt.Seed <= 0 {
		opt.Seed = 1
	}
	if opt.Scenario != "" && opt.Scenario != "all" && opt.Scenario != "history" && !knownScenario(opt.Scenario) {
		return "", fmt.Errorf("unknown demo scenario %q", opt.Scenario)
	}
	baseID := fixedScanID
	if baseID == "" {
		baseID = "demo-" + t.UTC().Format(demoDirTimestampFormat)
	}
	if opt.Scenario == "history" {
		return writeHistoryScans(outputDir, t, baseID, opt.Seed)
	}
	focused := opt.Scenario != "" && opt.Scenario != "all" && strings.EqualFold(opt.Profile, "legacy") && !opt.IncludeSecurityFixtures
	if focused {
		return writeFocusedScenario(outputDir, t, baseID, opt.Scenario, opt.Seed)
	}
	ids := securityScenarioIDs(opt.Profile, opt.Scenario, opt.IncludeSecurityFixtures)
	path, err := generateDemoScan(outputDir, t, fixedScanID, opt.Dense)
	if err != nil {
		return "", err
	}
	if len(ids) == 0 {
		return path, nil
	}
	if err := mergeSecurityFixtures(path, ids, opt); err != nil {
		return "", err
	}
	if wantsHistory(opt) {
		if _, err := writeHistoryScans(outputDir, t, baseID, opt.Seed); err != nil {
			return "", err
		}
	}
	return path, nil
}

func writeFocusedScenario(outputDir string, t time.Time, scanID, scenario string, seed int) (string, error) {
	if !scans.IsSafeScanID(scanID) {
		return "", fmt.Errorf("invalid --scan-id %q", scanID)
	}
	assets, rels, err := securityScenario(scanID, scenario)
	if err != nil {
		return "", err
	}
	if scenario == "inventory" {
		// Inventory stays bounded. Stress nodes are added only by the stress profile.
	}
	path, err := writeScenarioScan(outputDir, scanID, t, scenario, seed, assets, rels)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(scenario, "ciem-") || strings.HasPrefix(scenario, "id-") || strings.HasPrefix(scenario, "wl-") || strings.HasPrefix(scenario, "ecs-") || strings.HasPrefix(scenario, "eks-") || strings.HasPrefix(scenario, "irsa-") || strings.HasPrefix(scenario, "ct-") || scenario == "share-ecs-lambda" {
		if err := attachCIEMFindings(path, scenario); err != nil {
			return "", err
		}
	}
	return path, nil
}

func mergeSecurityFixtures(scanPath string, ids []string, opt demoOptions) error {
	scanID := filepath.Base(scanPath)
	var assets []models.AssetNode
	var rels []models.Relationship
	for _, id := range ids {
		nextAssets, nextRels, err := securityScenario(scanID, id)
		if err != nil {
			return err
		}
		assets = append(assets, nextAssets...)
		rels = append(rels, nextRels...)
	}
	if strings.EqualFold(opt.Profile, "stress") {
		for _, role := range stressRoles(scanID, opt.Seed) {
			assets = append(assets, role)
			rels = append(rels, ownedBy(scanID, role))
		}
	}
	assets = dedupeAssets(assets)
	rels = dedupeRels(rels)
	if err := writeJSONFile(filepath.Join(scanPath, "assets", "security_fixtures.json"), assets); err != nil {
		return err
	}
	relPath := filepath.Join(scanPath, "relationships.json")
	b, err := os.ReadFile(relPath)
	if err != nil {
		return err
	}
	var existing []models.Relationship
	if err := json.Unmarshal(b, &existing); err != nil {
		return err
	}
	if err := writeJSONFile(relPath, dedupeRels(append(existing, rels...))); err != nil {
		return err
	}
	metaPath := filepath.Join(scanPath, "scan-metadata.json")
	var meta models.ScanSnapshot
	b, err = os.ReadFile(metaPath)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &meta); err != nil {
		return err
	}
	meta.Synthetic = true
	meta.DataOrigin = syntheticDataOrigin
	meta.ScenarioID = strings.ToLower(opt.Profile)
	if opt.IncludeSecurityFixtures && meta.ScenarioID == "legacy" {
		meta.ScenarioID = "security-fixtures"
	}
	meta.DemoSeed = opt.Seed
	return writeJSONFile(metaPath, meta)
}

func writeHistoryScans(outputDir string, t time.Time, baseID string, seed int) (string, error) {
	type hist struct {
		suffix   string
		scenario string
	}
	items := []hist{
		{suffix: "history-broad", scenario: "history-a"},
		{suffix: "history-restricted", scenario: "history-b"},
		{suffix: "history-deny", scenario: "history-c"},
		{suffix: "history-trust", scenario: "history-d"},
		{suffix: "history-trust-removed", scenario: "history-d-removed"},
		{suffix: "history-evidence-missing", scenario: "history-e-missing"},
		{suffix: "history-evidence-present", scenario: "history-e-present"},
	}
	var first string
	for _, item := range items {
		scanID := baseID + "-" + item.suffix
		assets, rels, err := securityScenario(scanID, item.scenario)
		if err != nil {
			return "", err
		}
		path, err := writeScenarioScan(outputDir, scanID, t, item.scenario, seed, assets, rels)
		if err != nil {
			return "", err
		}
		if first == "" {
			first = path
		}
	}
	return first, nil
}

func writeScenarioScan(outputDir, scanID string, t time.Time, scenario string, seed int, assets []models.AssetNode, rels []models.Relationship) (string, error) {
	if !scans.IsSafeScanID(scanID) {
		return "", fmt.Errorf("invalid scan id %q", scanID)
	}
	scanPath := filepath.Join(outputDir, scanID)
	if err := os.MkdirAll(filepath.Join(scanPath, "assets"), 0o755); err != nil {
		return "", err
	}
	accounts := map[string]struct{}{}
	for _, asset := range assets {
		if asset.AccountID != "" {
			accounts[asset.AccountID] = struct{}{}
		}
	}
	accountIDs := make([]string, 0, len(accounts))
	for id := range accounts {
		accountIDs = append(accountIDs, id)
	}
	sort.Strings(accountIDs)
	meta := models.ScanSnapshot{
		ScanID:      scanID,
		Timestamp:   t.UTC(),
		AccountIDs:  accountIDs,
		ToolVersion: version,
		Synthetic:   true,
		DataOrigin:  syntheticDataOrigin,
		ScenarioID:  scenario,
		DemoSeed:    seed,
	}
	if err := writeJSONFile(filepath.Join(scanPath, "scan-metadata.json"), meta); err != nil {
		return "", err
	}
	if err := writeJSONFile(filepath.Join(scanPath, "findings.json"), []models.Finding{}); err != nil {
		return "", err
	}
	if err := writeJSONFile(filepath.Join(scanPath, "relationships.json"), rels); err != nil {
		return "", err
	}
	if err := writeJSONFile(filepath.Join(scanPath, "assets", "security_fixtures.json"), assets); err != nil {
		return "", err
	}
	return scanPath, nil
}

func securityScenario(scanID, scenario string) ([]models.AssetNode, []models.Relationship, error) {
	if assets, rels, ok := containerScenario(scanID, scenario); ok {
		return assets, rels, nil
	}
	var assets []models.AssetNode
	var rels []models.Relationship
	add := func(role models.AssetNode, policies []collectors.IdentityPolicyInput, extra ...models.AssetNode) {
		role.ScanID = scanID
		assets = append(assets, role)
		assets = append(assets, extra...)
		nodes, edges := collectors.BuildIdentityPolicyEvidence(role, policies)
		for i := range nodes {
			nodes[i].ScanID = scanID
		}
		for i := range edges {
			edges[i].ScanID = scanID
		}
		assets = append(assets, nodes...)
		rels = append(rels, edges...)
		rels = append(rels, models.Relationship{
			SourceARN: role.ARN, TargetARN: "account:" + role.AccountID, RelType: models.RelOwnedBy, ScanID: scanID,
		})
	}
	switch scenario {
	case "iam-01":
		role := secRole(scanID, demoAcctCore, "SecAdminRole", map[string]any{
			"attached_policy_names": []string{"AdministratorAccess"},
		})
		bucket, object := completeObject(scanID, demoAcctCore, "sec-admin", "readme.txt", nil)
		add(role, []collectors.IdentityPolicyInput{managedAdmin(allowStar())}, bucket, object)
	case "iam-02":
		objectARN := objectARN("sec-deny", "readme.txt")
		role := secRole(scanID, demoAcctCore, "SecAdminDenyRole", nil)
		bucket, object := completeObject(scanID, demoAcctCore, "sec-deny", "readme.txt", nil)
		add(role, []collectors.IdentityPolicyInput{inline("SecAdminDeny", allowAndDeny(objectARN))}, bucket, object)
	case "iam-03":
		role := secRole(scanID, demoAcctCore, "SecAdminMissingSCP", map[string]any{
			"attached_policy_names": []string{"AdministratorAccess"},
			"scp_status":            "missing",
			"scp_evidence":          "demo observation: organizations:ListPoliciesForTarget was not permitted; SCP documents are missing",
		})
		bucket, object := completeObject(scanID, demoAcctCore, "sec-missing-scp", "readme.txt", nil)
		add(role, []collectors.IdentityPolicyInput{managedAdmin(allowStar())}, bucket, object)
	case "iam-04":
		objectARN := objectARN("sec-restricted", "readme.txt")
		role := secRole(scanID, demoAcctCore, "SecRestrictedRole", map[string]any{
			"scp_status":             "present",
			"scp_evidence":           "demo observation: SCP attachments were recorded for the root, OU, and account",
			"scp_coverage":           "COMPLETE_FOR_SUPPORTED_SCOPE",
			"scp_hierarchy_complete": true,
			"scp_attachments": []map[string]any{
				orgAttachment("SERVICE_CONTROL_POLICY", "p-root", "root", "r-root", allowStar()),
				orgAttachment("SERVICE_CONTROL_POLICY", "p-ou", "organizational_unit", "ou-sec", allowStar()),
				orgAttachment("SERVICE_CONTROL_POLICY", "p-acct", "account", demoAcctCore, denyIAM()),
			},
		})
		bucket, object := completeObject(scanID, demoAcctCore, "sec-restricted", "readme.txt", nil)
		target := secRole(scanID, demoAcctCore, "SecRestrictedTarget", nil)
		add(role, []collectors.IdentityPolicyInput{inline("SecRestricted", allowGetAndAttach(objectARN))}, bucket, object, target)
		rels = append(rels, ownedBy(scanID, target))
	case "iam-05":
		objectARN := objectARN("sec-boundary", "readme.txt")
		role := secRole(scanID, demoAcctCore, "SecBoundaryRole", map[string]any{
			"permissions_boundary_status":   "present",
			"permissions_boundary_arn":      "arn:aws:iam::" + demoAcctCore + ":policy/SecBoundary",
			"permissions_boundary_evidence": "demo observation: iam:GetPolicyVersion returned the permissions boundary document",
			"permissions_boundary_document": allowGet(objectARN),
		})
		bucket, object := completeObject(scanID, demoAcctCore, "sec-boundary", "readme.txt", nil)
		add(role, []collectors.IdentityPolicyInput{inline("SecBoundaryIdentity", allowStar())}, bucket, object)
	case "iam-05b":
		role := secRole(scanID, demoAcctCore, "SecBoundaryUnread", map[string]any{
			"permissions_boundary_status":   "present",
			"permissions_boundary_arn":      "arn:aws:iam::" + demoAcctCore + ":policy/SecBoundaryUnread",
			"permissions_boundary_evidence": "demo observation: iam:ListRoles returned a boundary ARN and the policy document was not retrieved",
		})
		bucket, object := completeObject(scanID, demoAcctCore, "sec-boundary-unread", "readme.txt", nil)
		add(role, []collectors.IdentityPolicyInput{inline("SecBoundaryUnreadIdentity", allowStar())}, bucket, object)
	case "iam-06":
		objectARN := objectARN("sec-conditional", "readme.txt")
		role := secRole(scanID, demoAcctCore, "SecConditionalRole", nil)
		bucket, object := completeObject(scanID, demoAcctCore, "sec-conditional", "readme.txt", nil)
		add(role, []collectors.IdentityPolicyInput{inline("SecConditional", allowGetRegion(objectARN))}, bucket, object)
	case "iam-07":
		caller := secRole(scanID, demoAcctCore, "SecAssumeCaller", nil)
		targetARN := roleARN(demoAcctData, "SecAssumeTarget")
		target := secRole(scanID, demoAcctData, "SecAssumeTarget", map[string]any{
			"trust_policy_document": trustAllow(caller.ARN),
		})
		add(caller, []collectors.IdentityPolicyInput{inline("SecAssumeCaller", allowAssume(targetARN))}, target)
		rels = append(rels, ownedBy(scanID, target))
	case "iam-08":
		caller := secRole(scanID, demoAcctCore, "SecTrustOnlyCaller", map[string]any{
			"policy_inventory_evidence": "demo observation: iam:ListRolePolicies and iam:ListAttachedRolePolicies returned no policies",
		})
		target := secRole(scanID, demoAcctData, "SecTrustOnlyTarget", map[string]any{
			"trust_policy_document": trustAllow(caller.ARN),
		})
		add(caller, nil, target)
		rels = append(rels, ownedBy(scanID, target))
	case "iam-09":
		caller := secRole(scanID, demoAcctCore, "SecTrustDenyCaller", nil)
		targetARN := roleARN(demoAcctData, "SecTrustDenyTarget")
		target := secRole(scanID, demoAcctData, "SecTrustDenyTarget", map[string]any{
			"trust_policy_document": trustDeny(caller.ARN),
		})
		add(caller, []collectors.IdentityPolicyInput{inline("SecTrustDenyCaller", allowAssume(targetARN))}, target)
		rels = append(rels, ownedBy(scanID, target))
	case "iam-10-denied":
		role := secRole(scanID, demoAcctCore, "SecRetrievalDenied", map[string]any{
			"policy_retrieval_status": models.PolicyRetrievalPartial,
			"attached_policy_names":   []string{"AdministratorAccess"},
		})
		bucket, object := completeObject(scanID, demoAcctCore, "sec-retrieval-denied", "readme.txt", nil)
		add(role, []collectors.IdentityPolicyInput{{
			ARN: "arn:aws:iam::aws:policy/AdministratorAccess", Name: "AdministratorAccess", PolicyType: models.PolicyTypeManaged,
			RetrievalStatus: models.PolicyRetrievalMissing, Document: "",
		}}, bucket, object)
		roleNote(&assets, "arn:aws:iam::aws:policy/AdministratorAccess", "retrieval_evidence", "demo observation: iam:GetPolicy was denied")
	case "iam-10-missing":
		role := secRole(scanID, demoAcctCore, "SecRetrievalMissingVersion", map[string]any{
			"policy_retrieval_status": models.PolicyRetrievalPartial,
		})
		bucket, object := completeObject(scanID, demoAcctCore, "sec-retrieval-missing", "readme.txt", nil)
		add(role, []collectors.IdentityPolicyInput{{
			ARN: "arn:aws:iam::" + demoAcctCore + ":policy/SecMissingVersion", Name: "SecMissingVersion", PolicyType: models.PolicyTypeManaged,
			RetrievalStatus: models.PolicyRetrievalMissing,
		}}, bucket, object)
		roleNote(&assets, "arn:aws:iam::"+demoAcctCore+":policy/SecMissingVersion", "retrieval_evidence", "demo observation: iam:GetPolicyVersion returned no policy document")
	case "iam-10-malformed":
		role := secRole(scanID, demoAcctCore, "SecRetrievalMalformed", map[string]any{
			"policy_retrieval_status": models.PolicyRetrievalPartial,
		})
		bucket, object := completeObject(scanID, demoAcctCore, "sec-retrieval-malformed", "readme.txt", nil)
		add(role, []collectors.IdentityPolicyInput{{
			ARN: "arn:aws:iam::" + demoAcctCore + ":policy/SecMalformed", Name: "SecMalformed", PolicyType: models.PolicyTypeManaged,
			RetrievalStatus: models.PolicyRetrievalMalformed, Document: "{not-json",
		}}, bucket, object)
	case "iam-10-empty":
		role := secRole(scanID, demoAcctCore, "SecEmptyInventory", map[string]any{
			"policy_inventory_evidence": "demo observation: iam:ListRolePolicies and iam:ListAttachedRolePolicies returned no policies",
		})
		bucket, object := completeObject(scanID, demoAcctCore, "sec-empty-inventory", "readme.txt", nil)
		add(role, nil, bucket, object)
	case "iam-session-missing":
		role := secRole(scanID, demoAcctCore, "SecSessionMissing", nil)
		delete(role.Properties, "session_policy_status")
		delete(role.Properties, "session_policy_evidence")
		bucket, object := completeObject(scanID, demoAcctCore, "sec-session", "readme.txt", nil)
		add(role, []collectors.IdentityPolicyInput{inline("SecSessionMissing", allowGet(objectARN("sec-session", "readme.txt")))}, bucket, object)
	case "s3-01":
		assets, rels = s3IdentityScenario(scanID, "SecSameReader", "sec-same", "readme.txt", demoAcctCore, allowGet(objectARN("sec-same", "readme.txt")), nil)
	case "s3-02":
		caller := secRole(scanID, demoAcctCore, "SecCrossReader", nil)
		bucket, object := completeObject(scanID, demoAcctData, "sec-foreign", "secret.txt", map[string]any{
			"bucket_policy_status":   "present",
			"bucket_policy_evidence": "demo observation: s3:GetBucketPolicy returned a policy document",
			"bucket_policy_document": bucketAllow(caller.ARN, objectARN("sec-foreign", "secret.txt")),
			"rcp_status":             "confirmed_absent",
			"rcp_evidence":           "demo observation: no resource control policy applies to the bucket account",
		})
		add(caller, []collectors.IdentityPolicyInput{inline("SecCrossReader", allowGet(objectARN("sec-foreign", "secret.txt")))}, bucket, object)
	case "s3-03":
		caller := secRole(scanID, demoAcctCore, "SecBucketDenyReader", nil)
		arn := objectARN("sec-bucket-deny", "readme.txt")
		bucket, object := completeObject(scanID, demoAcctCore, "sec-bucket-deny", "readme.txt", map[string]any{
			"bucket_policy_status":   "present",
			"bucket_policy_evidence": "demo observation: s3:GetBucketPolicy returned a policy document",
			"bucket_policy_document": bucketDeny(caller.ARN, arn),
		})
		add(caller, []collectors.IdentityPolicyInput{inline("SecBucketDenyReader", allowGet(arn))}, bucket, object)
	case "s3-04":
		assets, rels = s3IdentityScenario(scanID, "SecNoBucketPolicy", "sec-no-policy", "readme.txt", demoAcctCore, allowGet(objectARN("sec-no-policy", "readme.txt")), nil)
	case "s3-05":
		assets, rels = s3IdentityScenario(scanID, "SecBucketPolicyDenied", "sec-policy-denied", "readme.txt", demoAcctCore, allowGet(objectARN("sec-policy-denied", "readme.txt")), map[string]any{
			"bucket_policy_status":   "missing",
			"bucket_policy_evidence": "demo observation: s3:GetBucketPolicy was denied",
		})
	case "s3-06":
		assets, rels = s3IdentityScenario(scanID, "SecOwnerEnforced", "sec-owner-enforced", "readme.txt", demoAcctCore, allowGet(objectARN("sec-owner-enforced", "readme.txt")), nil)
	case "s3-07":
		assets, rels = s3IdentityScenario(scanID, "SecOwnershipMissing", "sec-ownership-missing", "readme.txt", demoAcctCore, allowGet(objectARN("sec-ownership-missing", "readme.txt")), map[string]any{
			"object_ownership":          "",
			"object_ownership_evidence": "",
		})
	case "s3-08":
		assets, rels = s3IdentityScenario(scanID, "SecSSES3", "sec-sse-s3", "readme.txt", demoAcctCore, allowGet(objectARN("sec-sse-s3", "readme.txt")), nil)
	case "s3-09":
		assets, rels = s3IdentityScenario(scanID, "SecSSEKMS", "sec-sse-kms", "readme.txt", demoAcctCore, allowGet(objectARN("sec-sse-kms", "readme.txt")), map[string]any{
			"bucket_encryption":          "aws:kms",
			"bucket_encryption_evidence": "demo observation: s3:GetBucketEncryption returned aws:kms",
			"kms_key_arn":                "arn:aws:kms:us-east-1:" + demoAcctCore + ":key/sec-demo",
		})
	case "s3-10":
		role := secRole(scanID, demoAcctCore, "SecBucketOnly", nil)
		bucket := completeBucket(scanID, demoAcctCore, "sec-no-objects", nil)
		add(role, []collectors.IdentityPolicyInput{inline("SecBucketOnly", allowGet(objectARN("sec-no-objects", "readme.txt")))}, bucket)
	case "s3-11":
		assets, rels = s3IdentityScenario(scanID, "SecBPAPartial", "sec-bpa", "readme.txt", demoAcctCore, allowGet(objectARN("sec-bpa", "readme.txt")), map[string]any{
			"account_public_access_block":          "missing",
			"account_public_access_block_evidence": "demo observation: account-level s3:GetPublicAccessBlock was not collected",
		})
	case "s3-12":
		arn := objectARN("sec-actions", "readme.txt")
		role := secRole(scanID, demoAcctCore, "SecMultiAction", nil)
		bucket, object := completeObject(scanID, demoAcctCore, "sec-actions", "readme.txt", nil)
		add(role, []collectors.IdentityPolicyInput{inline("SecMultiAction", multiAction(arn))}, bucket, object)
	case "inventory":
		role := secRole(scanID, demoAcctCore, "SecInventoryObserver", map[string]any{
			"policy_inventory_evidence": "demo observation: iam:ListRolePolicies and iam:ListAttachedRolePolicies returned no policies",
		})
		add(role, nil, inventoryFixtures(scanID)...)
		rels = append(rels, ownedBy(scanID, secRole(scanID, demoAcctCore, "SecLambdaExecution", nil)))
		unresolved := models.AssetNode{
			ARN: "arn:aws:ec2:us-east-1:" + demoAcctCore + ":subnet/subnet-missing", AssetType: "unresolved_reference",
			Name: "subnet-missing", AccountID: demoAcctCore, Region: "us-east-1", ScanID: scanID,
			Properties: map[string]any{"resolution_status": "unresolved", "resolution_reason": "referenced by a security group and not collected"},
		}
		assets = append(assets, unresolved)
		rels = append(rels, models.Relationship{
			SourceARN: "arn:aws:ec2:us-east-1:" + demoAcctCore + ":security-group/sg-sec-demo",
			TargetARN: unresolved.ARN, RelType: models.RelPointsTo, ScanID: scanID,
			Properties: map[string]any{"evidence": "inventory reference only; network reachability was not evaluated"},
		})
	case "history-a":
		role := secRole(scanID, demoAcctCore, "SecHistoryRole", nil)
		bucket, object := completeObject(scanID, demoAcctCore, "sec-history", "notes.txt", nil)
		add(role, []collectors.IdentityPolicyInput{inline("SecHistory", allowStar())}, bucket, object)
	case "history-b":
		arn := objectARN("sec-history", "notes.txt")
		role := secRole(scanID, demoAcctCore, "SecHistoryRole", nil)
		bucket, object := completeObject(scanID, demoAcctCore, "sec-history", "notes.txt", nil)
		add(role, []collectors.IdentityPolicyInput{inline("SecHistory", allowGet(arn))}, bucket, object)
	case "history-c":
		arn := objectARN("sec-history", "notes.txt")
		role := secRole(scanID, demoAcctCore, "SecHistoryRole", nil)
		bucket, object := completeObject(scanID, demoAcctCore, "sec-history", "notes.txt", nil)
		add(role, []collectors.IdentityPolicyInput{inline("SecHistory", allowAndDeny(arn))}, bucket, object)
	case "history-d":
		caller := secRole(scanID, demoAcctCore, "SecHistoryCaller", nil)
		targetARN := roleARN(demoAcctData, "SecHistoryTarget")
		target := secRole(scanID, demoAcctData, "SecHistoryTarget", map[string]any{"trust_policy_document": trustAllow(caller.ARN)})
		add(caller, []collectors.IdentityPolicyInput{inline("SecHistoryCaller", allowAssume(targetARN))}, target)
		rels = append(rels, ownedBy(scanID, target))
	case "history-d-removed":
		caller := secRole(scanID, demoAcctCore, "SecHistoryCaller", nil)
		targetARN := roleARN(demoAcctData, "SecHistoryTarget")
		target := secRole(scanID, demoAcctData, "SecHistoryTarget", nil)
		add(caller, []collectors.IdentityPolicyInput{inline("SecHistoryCaller", allowAssume(targetARN))}, target)
		rels = append(rels, ownedBy(scanID, target))
	case "history-e-missing":
		role := secRole(scanID, demoAcctCore, "SecHistoryRole", map[string]any{
			"policy_retrieval_status": models.PolicyRetrievalMissing,
		})
		bucket, object := completeObject(scanID, demoAcctCore, "sec-history", "notes.txt", nil)
		add(role, nil, bucket, object)
	case "history-e-present":
		arn := objectARN("sec-history", "notes.txt")
		role := secRole(scanID, demoAcctCore, "SecHistoryRole", nil)
		bucket, object := completeObject(scanID, demoAcctCore, "sec-history", "notes.txt", nil)
		add(role, []collectors.IdentityPolicyInput{inline("SecHistory", allowGet(arn))}, bucket, object)
	case "attack-chain":
		assets, rels = attackPair(scanID, demoAcctCore, demoAcctCore, "SecChainCaller", "SecChainTarget", "sec-chain", "readme.txt", trustAllow(roleARN(demoAcctCore, "SecChainCaller")), allowGet(objectARN("sec-chain", "readme.txt")), nil)
	case "attack-trust-deny":
		assets, rels = attackPair(scanID, demoAcctCore, demoAcctCore, "SecDenyCaller", "SecDenyTarget", "sec-attack-deny", "readme.txt", trustDeny(roleARN(demoAcctCore, "SecDenyCaller")), allowGet(objectARN("sec-attack-deny", "readme.txt")), nil)
	case "attack-no-caller":
		caller := secRole(scanID, demoAcctCore, "SecUnauthCaller", map[string]any{
			"policy_inventory_evidence": "demo observation: iam:ListRolePolicies and iam:ListAttachedRolePolicies returned no policies",
		})
		target := secRole(scanID, demoAcctCore, "SecUnauthTarget", map[string]any{"trust_policy_document": trustAllow(caller.ARN)})
		add(caller, nil, target)
		rels = append(rels, ownedBy(scanID, target))
	case "attack-caller-session":
		caller := secRole(scanID, demoAcctCore, "SecNoSessionCaller", nil)
		delete(caller.Properties, "session_policy_status")
		delete(caller.Properties, "session_policy_evidence")
		target := secRole(scanID, demoAcctCore, "SecNoSessionTarget", map[string]any{"trust_policy_document": trustAllow(caller.ARN)})
		bucket, object := completeObject(scanID, demoAcctCore, "sec-no-session", "readme.txt", nil)
		add(caller, []collectors.IdentityPolicyInput{inline("SecNoSessionCaller", allowAssume(target.ARN))}, target, bucket, object)
		attachIdentity(scanID, target, inline("SecNoSessionTarget", allowGet(object.ARN)), &assets, &rels)
		rels = append(rels, ownedBy(scanID, target))
	case "attack-target-session":
		target := secRole(scanID, demoAcctCore, "SecOpenTarget", map[string]any{"trust_policy_document": trustAllow(roleARN(demoAcctCore, "SecOpenCaller"))})
		delete(target.Properties, "session_policy_status")
		delete(target.Properties, "session_policy_evidence")
		assets, rels = attackPairWithTarget(scanID, secRole(scanID, demoAcctCore, "SecOpenCaller", nil), target, "sec-open-target", "readme.txt", allowGet(objectARN("sec-open-target", "readme.txt")))
	case "attack-mfa":
		callerARN := roleARN(demoAcctCore, "SecMFACaller")
		target := secRole(scanID, demoAcctCore, "SecMFATarget", map[string]any{
			"trust_policy_document": trustAllowCondition(callerARN, `"Bool":{"aws:MultiFactorAuthPresent":"true"}`),
		})
		assets, rels = attackPairWithTarget(scanID, secRole(scanID, demoAcctCore, "SecMFACaller", nil), target, "sec-mfa", "readme.txt", allowGet(objectARN("sec-mfa", "readme.txt")))
	case "attack-external-id":
		callerARN := roleARN(demoAcctCore, "SecExtCaller")
		target := secRole(scanID, demoAcctCore, "SecExtTarget", map[string]any{
			"trust_policy_document": trustAllowCondition(callerARN, `"StringEquals":{"sts:ExternalId":"chain-external-id"}`),
		})
		assets, rels = attackPairWithTarget(scanID, secRole(scanID, demoAcctCore, "SecExtCaller", nil), target, "sec-external", "readme.txt", allowGet(objectARN("sec-external", "readme.txt")))
	case "attack-cross":
		target := secRole(scanID, demoAcctData, "SecCrossTarget", map[string]any{"trust_policy_document": trustAllow(roleARN(demoAcctCore, "SecCrossCaller"))})
		caller := secRole(scanID, demoAcctCore, "SecCrossCaller", nil)
		bucket, object := completeObject(scanID, demoAcctData, "sec-cross-chain", "secret.txt", map[string]any{
			"bucket_policy_status": "present", "bucket_policy_evidence": "demo observation: s3:GetBucketPolicy returned a policy document",
			"bucket_policy_document": bucketAllow(target.ARN, objectARN("sec-cross-chain", "secret.txt")),
		})
		add(caller, []collectors.IdentityPolicyInput{inline("SecCrossCaller", allowAssume(target.ARN))}, target, bucket, object)
		attachIdentity(scanID, target, inline("SecCrossTarget", allowGet(object.ARN)), &assets, &rels)
		rels = append(rels, ownedBy(scanID, target))
	case "attack-cycle":
		caller := secRole(scanID, demoAcctCore, "SecCycleA", map[string]any{"trust_policy_document": trustAllow(roleARN(demoAcctCore, "SecCycleB"))})
		target := secRole(scanID, demoAcctCore, "SecCycleB", map[string]any{"trust_policy_document": trustAllow(caller.ARN)})
		add(caller, []collectors.IdentityPolicyInput{inline("SecCycleA", allowAssume(target.ARN))}, target)
		attachIdentity(scanID, target, inline("SecCycleB", allowAssume(caller.ARN)), &assets, &rels)
		rels = append(rels, ownedBy(scanID, target))
	case "attack-multipath":
		objectRef := objectARN("sec-multi", "readme.txt")
		bARN := roleARN(demoAcctCore, "SecMultiB")
		cARN := roleARN(demoAcctCore, "SecMultiC")
		aARN := roleARN(demoAcctCore, "SecMultiA")
		roleB := secRole(scanID, demoAcctCore, "SecMultiB", map[string]any{"trust_policy_document": trustAllowEither(aARN, cARN)})
		roleC := secRole(scanID, demoAcctCore, "SecMultiC", map[string]any{"trust_policy_document": trustAllow(aARN)})
		roleA := secRole(scanID, demoAcctCore, "SecMultiA", nil)
		bucket, object := completeObject(scanID, demoAcctCore, "sec-multi", "readme.txt", nil)
		add(roleA, []collectors.IdentityPolicyInput{inline("SecMultiA", allowAssumeTwo(bARN, cARN))}, roleB, roleC, bucket, object)
		attachIdentity(scanID, roleB, inline("SecMultiB", allowGet(objectRef)), &assets, &rels)
		attachIdentity(scanID, roleC, inline("SecMultiC", allowAssume(bARN)), &assets, &rels)
		rels = append(rels, ownedBy(scanID, roleB), ownedBy(scanID, roleC))
	case "attack-history-open":
		assets, rels = attackPair(scanID, demoAcctCore, demoAcctCore, "SecAttackHistCaller", "SecAttackHistTarget", "sec-attack-hist", "notes.txt", trustAllow(roleARN(demoAcctCore, "SecAttackHistCaller")), allowGet(objectARN("sec-attack-hist", "notes.txt")), nil)
	case "attack-history-closed":
		assets, rels = attackPair(scanID, demoAcctCore, demoAcctCore, "SecAttackHistCaller", "SecAttackHistTarget", "sec-attack-hist", "notes.txt", trustDeny(roleARN(demoAcctCore, "SecAttackHistCaller")), allowGet(objectARN("sec-attack-hist", "notes.txt")), nil)
	case "attack-no-read":
		target := secRole(scanID, demoAcctCore, "SecBlindTarget", map[string]any{
			"trust_policy_document":     trustAllow(roleARN(demoAcctCore, "SecBlindCaller")),
			"policy_inventory_evidence": "demo observation: iam:ListRolePolicies and iam:ListAttachedRolePolicies returned no policies",
		})
		caller := secRole(scanID, demoAcctCore, "SecBlindCaller", nil)
		bucket, object := completeObject(scanID, demoAcctCore, "sec-blind", "readme.txt", nil)
		add(caller, []collectors.IdentityPolicyInput{inline("SecBlindCaller", allowAssume(target.ARN))}, target, bucket, object)
		rels = append(rels, ownedBy(scanID, target))
	case "attack-federated":
		target := secRole(scanID, demoAcctCore, "SecFedTarget", map[string]any{
			"trust_policy_document": trustFederated("arn:aws:iam::" + demoAcctCore + ":oidc-provider/example.invalid"),
		})
		caller := secRole(scanID, demoAcctCore, "SecFedCaller", nil)
		add(caller, []collectors.IdentityPolicyInput{inline("SecFedCaller", allowAssume(target.ARN))}, target)
		rels = append(rels, ownedBy(scanID, target))
	case "ciem-broad", "ciem-stale", "ciem-multi", "ciem-chain":
		assets, rels = ciemRoleScenario(scanID, scenario)
	case "ciem-bucket":
		assets, rels = ciemBucketScenario(scanID)
	case "ciem-scp":
		assets, rels = ciemSCPScenario(scanID)
	case "ciem-scope":
		assets, rels = ciemScopeScenario(scanID)
	case "id-narrow", "id-admin", "id-same-trust", "id-cross-trust", "id-trust-no-caller", "id-assume-ok", "id-trust-deny", "id-boundary", "id-scp", "id-rcp", "id-missing-org", "id-missing-session", "id-shared-policy", "id-mixed", "id-service", "id-slr", "id-wildcard", "id-multipath", "id-admin-no-path", "id-hist-a", "id-hist-b":
		assets, rels = identityScenario(scanID, scenario)
	case "wl-ec2-map", "wl-ec2-none", "wl-ec2-names", "wl-ec2-denied", "wl-ec2-share", "wl-lambda-scoped", "wl-lambda-admin", "wl-lambda-missing", "wl-lambda-trust", "wl-missing-scp", "wl-deny", "wl-assume", "wl-shared-resource", "wl-hist-a", "wl-hist-b", "wl-attach-a", "wl-attach-b", "wl-org-gap", "wl-org-unknown":
		assets, rels = workloadScenario(scanID, scenario)
	case "ciem-scp-union", "ciem-scp-ancestor", "ciem-scp-deny", "ciem-scp-gap", "ciem-scp-implicit", "ciem-scp-moved":
		assets, rels = ciemOrgScenario(scanID, scenario)
	case "ciem-rcp-cross", "ciem-rcp-assume", "ciem-mgmt":
		assets, rels = ciemRCPScenario(scanID, scenario)
	case "attack-missing-scp":
		caller := secRole(scanID, demoAcctCore, "SecSCPCaller", map[string]any{
			"scp_status": "missing", "scp_evidence": "demo observation: organizations:ListPoliciesForTarget was not permitted; SCP documents are missing",
		})
		target := secRole(scanID, demoAcctCore, "SecSCPTarget", map[string]any{"trust_policy_document": trustAllow(caller.ARN)})
		add(caller, []collectors.IdentityPolicyInput{inline("SecSCPCaller", allowAssume(target.ARN))}, target)
		rels = append(rels, ownedBy(scanID, target))
	default:
		return nil, nil, fmt.Errorf("unknown demo scenario %q", scenario)
	}
	for i := range assets {
		if assets[i].ScanID == "" {
			assets[i].ScanID = scanID
		}
	}
	sort.Slice(assets, func(i, j int) bool { return assets[i].ARN < assets[j].ARN })
	sort.Slice(rels, func(i, j int) bool {
		if rels[i].SourceARN == rels[j].SourceARN {
			if rels[i].RelType == rels[j].RelType {
				return rels[i].TargetARN < rels[j].TargetARN
			}
			return rels[i].RelType < rels[j].RelType
		}
		return rels[i].SourceARN < rels[j].SourceARN
	})
	return assets, rels, nil
}

func s3IdentityScenario(scanID, roleName, bucket, key, account, policy string, bucketExtra map[string]any) ([]models.AssetNode, []models.Relationship) {
	role := secRole(scanID, account, roleName, nil)
	b, object := completeObject(scanID, account, bucket, key, bucketExtra)
	var assets []models.AssetNode
	var rels []models.Relationship
	role.ScanID = scanID
	assets = append(assets, role, b, object)
	nodes, edges := collectors.BuildIdentityPolicyEvidence(role, []collectors.IdentityPolicyInput{inline(roleName, policy)})
	for i := range nodes {
		nodes[i].ScanID = scanID
	}
	for i := range edges {
		edges[i].ScanID = scanID
	}
	assets = append(assets, nodes...)
	rels = append(rels, edges...)
	rels = append(rels, ownedBy(scanID, role))
	sort.Slice(assets, func(i, j int) bool { return assets[i].ARN < assets[j].ARN })
	return assets, rels
}

func secRole(scanID, account, name string, extra map[string]any) models.AssetNode {
	props := map[string]any{
		"path":                          "/",
		"resolution_status":             "collected",
		"policy_retrieval_status":       models.PolicyRetrievalOK,
		"permissions_boundary_status":   "confirmed_absent",
		"permissions_boundary_evidence": "demo observation: iam:ListRoles returned this role with no permissions boundary",
		"session_policy_status":         "confirmed_absent",
		"session_policy_evidence":       "demo observation: the recorded session has no session policy document",
		"scp_status":                    "confirmed_absent",
		"scp_evidence":                  "demo observation: no service control policy document applies to this account",
		"rcp_status":                    "confirmed_absent",
		"rcp_evidence":                  "demo observation: no resource control policy document applies to this account",
		"data_origin":                   syntheticDataOrigin,
	}
	for k, v := range extra {
		if v == "" {
			delete(props, k)
			continue
		}
		props[k] = v
	}
	return models.AssetNode{
		ARN: roleARN(account, name), AssetType: models.AssetIAMRole, Name: name,
		AccountID: account, Region: "global", ScanID: scanID, Properties: props,
	}
}

func completeBucket(scanID, account, name string, extra map[string]any) models.AssetNode {
	props := map[string]any{
		"resolution_status":                    "collected",
		"bucket_policy_status":                 "confirmed_absent",
		"bucket_policy_evidence":               "demo observation: s3:GetBucketPolicy returned NoSuchBucketPolicy",
		"object_ownership":                     "BucketOwnerEnforced",
		"object_ownership_evidence":            "demo observation: s3:GetBucketOwnershipControls returned BucketOwnerEnforced",
		"bucket_encryption":                    "AES256",
		"bucket_encryption_evidence":           "demo observation: s3:GetBucketEncryption returned AES256",
		"bucket_public_access_block":           "confirmed_absent",
		"bucket_public_access_block_evidence":  "demo observation: s3:GetPublicAccessBlock returned NoSuchPublicAccessBlockConfiguration; account-level configuration is recorded separately",
		"account_public_access_block":          "confirmed_absent",
		"account_public_access_block_evidence": "demo observation: s3:GetAccountPublicAccessBlock returned no account configuration",
		"data_origin":                          syntheticDataOrigin,
	}
	for k, v := range extra {
		if v == "" {
			delete(props, k)
			continue
		}
		props[k] = v
	}
	return models.AssetNode{
		ARN: "arn:aws:s3:::" + name, AssetType: models.AssetS3Bucket, Name: name,
		AccountID: account, Region: "us-east-1", ScanID: scanID, Properties: props,
	}
}

func completeObject(scanID, account, bucket, key string, extra map[string]any) (models.AssetNode, models.AssetNode) {
	return completeBucket(scanID, account, bucket, extra), models.AssetNode{
		ARN: objectARN(bucket, key), AssetType: models.AssetS3Object, Name: key,
		AccountID: account, Region: "us-east-1", ScanID: scanID,
		Properties: map[string]any{
			"resolution_status": "collected",
			"object_key":        key,
			"bucket_name":       bucket,
			"data_origin":       syntheticDataOrigin,
		},
	}
}

func inventoryFixtures(scanID string) []models.AssetNode {
	type item struct {
		arn, kind, name, region string
	}
	items := []item{
		{"arn:aws:ec2:us-east-1:" + demoAcctCore + ":instance/i-sec-demo", "ec2_instance", "sec-demo", "us-east-1"},
		{"arn:aws:ec2:us-east-1:" + demoAcctCore + ":instance-profile/sec-demo", "instance_profile", "sec-demo", "us-east-1"},
		{"arn:aws:lambda:us-east-1:" + demoAcctCore + ":function:sec-demo", "lambda_function", "sec-demo", "us-east-1"},
		{"arn:aws:secretsmanager:us-east-1:" + demoAcctCore + ":secret:sec-demo", "secretsmanager_secret", "sec-demo", "us-east-1"},
		{"arn:aws:rds:us-east-1:" + demoAcctCore + ":db:sec-demo", "rds_db_instance", "sec-demo", "us-east-1"},
		{"arn:aws:ec2:us-east-1:" + demoAcctCore + ":security-group/sg-sec-demo", "security_group", "sg-sec-demo", "us-east-1"},
		{"arn:aws:ec2:us-east-1:" + demoAcctCore + ":subnet/subnet-sec-demo", "subnet", "subnet-sec-demo", "us-east-1"},
		{"arn:aws:ec2:us-east-1:" + demoAcctCore + ":vpc/vpc-sec-demo", "vpc", "vpc-sec-demo", "us-east-1"},
		{"arn:aws:kms:us-east-1:" + demoAcctCore + ":key/sec-demo-inventory", "kms_key", "sec-demo", "us-east-1"},
	}
	out := make([]models.AssetNode, 0, len(items)+1)
	exec := secRole(scanID, demoAcctCore, "SecLambdaExecution", map[string]any{
		"evaluation_support":        "unsupported",
		"policy_inventory_evidence": "demo observation: iam:ListRolePolicies and iam:ListAttachedRolePolicies returned no policies",
	})
	out = append(out, exec)
	for _, item := range items {
		out = append(out, models.AssetNode{
			ARN: item.arn, AssetType: models.AssetType(item.kind), Name: item.name,
			AccountID: demoAcctCore, Region: item.region, ScanID: scanID,
			Properties: map[string]any{
				"resolution_status":    "collected",
				"evaluation_support":   "unsupported",
				"data_origin":          syntheticDataOrigin,
				"network_reachability": "not_evaluated",
			},
		})
	}
	return out
}

func stressRoles(scanID string, seed int) []models.AssetNode {
	count := 16 + (seed % 3)
	if count > 24 {
		count = 24
	}
	out := make([]models.AssetNode, 0, count)
	for i := 1; i <= count; i++ {
		out = append(out, secRole(scanID, demoAcctCore, fmt.Sprintf("StressRole%02d", i), map[string]any{
			"evaluation_support":        "unsupported",
			"policy_inventory_evidence": "demo observation: stress fixture with no policy documents",
		}))
	}
	return out
}

func ownedBy(scanID string, role models.AssetNode) models.Relationship {
	return models.Relationship{SourceARN: role.ARN, TargetARN: "account:" + role.AccountID, RelType: models.RelOwnedBy, ScanID: scanID}
}

func roleNote(assets *[]models.AssetNode, arn, key, value string) {
	for i := range *assets {
		if (*assets)[i].ARN == arn {
			if (*assets)[i].Properties == nil {
				(*assets)[i].Properties = map[string]any{}
			}
			(*assets)[i].Properties[key] = value
		}
	}
}

func dedupeAssets(in []models.AssetNode) []models.AssetNode {
	seen := map[string]int{}
	var out []models.AssetNode
	for _, asset := range in {
		if i, ok := seen[asset.ARN]; ok {
			out[i] = asset
			continue
		}
		seen[asset.ARN] = len(out)
		out = append(out, asset)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ARN < out[j].ARN })
	return out
}

func dedupeRels(in []models.Relationship) []models.Relationship {
	seen := map[string]struct{}{}
	var out []models.Relationship
	for _, rel := range in {
		key := rel.SourceARN + "\n" + string(rel.RelType) + "\n" + rel.TargetARN
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, rel)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SourceARN == out[j].SourceARN {
			if out[i].RelType == out[j].RelType {
				return out[i].TargetARN < out[j].TargetARN
			}
			return out[i].RelType < out[j].RelType
		}
		return out[i].SourceARN < out[j].SourceARN
	})
	return out
}

func roleARN(account, name string) string {
	return "arn:aws:iam::" + account + ":role/" + name
}

func objectARN(bucket, key string) string {
	return "arn:aws:s3:::" + bucket + "/" + key
}

func inline(name, document string) collectors.IdentityPolicyInput {
	return collectors.IdentityPolicyInput{Name: name, PolicyType: models.PolicyTypeInline, Document: document, RetrievalStatus: models.PolicyRetrievalOK, VersionID: "inline"}
}

func managedAdmin(document string) collectors.IdentityPolicyInput {
	return collectors.IdentityPolicyInput{
		ARN: "arn:aws:iam::aws:policy/AdministratorAccess", Name: "AdministratorAccess",
		PolicyType: models.PolicyTypeManaged, VersionID: "v1", Document: document, RetrievalStatus: models.PolicyRetrievalOK,
	}
}

func allowStar() string {
	return `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`
}

func allowGet(resource string) string {
	return fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"%s"}}`, resource)
}

func allowAndDeny(resource string) string {
	return fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"s3:GetObject","Resource":"%s"}]}`, resource)
}

func orgAttachment(kind, id, level, target, document string) map[string]any {
	return map[string]any{
		"policy_id": id, "policy_type": kind, "attachment_level": level, "attachment_target": target,
		"document": document, "retrieved_at": "2026-01-01T00:00:00Z", "evaluation_support": "supported_statement_language",
	}
}

func denyIAM() string {
	return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"iam:*","Resource":"*"}]}`
}

func allowGetAndAttach(resource string) string {
	return fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"%s"},{"Effect":"Allow","Action":"iam:AttachRolePolicy","Resource":"*"}]}`, resource)
}

func allowGetRegion(resource string) string {
	return fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"%s","Condition":{"StringEquals":{"aws:RequestedRegion":"us-east-1"}}}}`, resource)
}

func allowAssume(target string) string {
	return fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"%s"}}`, target)
}

func trustAllow(principal string) string {
	return fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"%s"},"Action":"sts:AssumeRole"}}`, principal)
}

func trustAllowEither(a, b string) string {
	return fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"%s"},"Action":"sts:AssumeRole"},{"Effect":"Allow","Principal":{"AWS":"%s"},"Action":"sts:AssumeRole"}]}`, a, b)
}

func trustAllowCondition(principal, condition string) string {
	return fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"%s"},"Action":"sts:AssumeRole","Condition":{%s}}}`, principal, condition)
}

func trustFederated(provider string) string {
	return fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Federated":"%s"},"Action":"sts:AssumeRoleWithWebIdentity"}}`, provider)
}

func allowAssumeTwo(a, b string) string {
	return fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"sts:AssumeRole","Resource":["%s","%s"]}}`, a, b)
}

func attackPair(scanID, callerAccount, targetAccount, callerName, targetName, bucket, key, trust, targetPolicy string, callerExtra map[string]any) ([]models.AssetNode, []models.Relationship) {
	target := secRole(scanID, targetAccount, targetName, mergeProps(map[string]any{"trust_policy_document": trust}, nil))
	return attackPairWithTarget(scanID, secRole(scanID, callerAccount, callerName, callerExtra), target, bucket, key, targetPolicy)
}

func attackPairWithTarget(scanID string, caller, target models.AssetNode, bucket, key, targetPolicy string) ([]models.AssetNode, []models.Relationship) {
	b, object := completeObject(scanID, target.AccountID, bucket, key, nil)
	var assets []models.AssetNode
	var rels []models.Relationship
	caller.ScanID = scanID
	target.ScanID = scanID
	assets = append(assets, caller, target, b, object)
	nodes, edges := collectors.BuildIdentityPolicyEvidence(caller, []collectors.IdentityPolicyInput{inline(caller.Name, allowAssume(target.ARN))})
	assets, rels = appendPolicy(scanID, assets, rels, nodes, edges)
	if targetPolicy != "" {
		tNodes, tEdges := collectors.BuildIdentityPolicyEvidence(target, []collectors.IdentityPolicyInput{inline(target.Name, targetPolicy)})
		assets, rels = appendPolicy(scanID, assets, rels, tNodes, tEdges)
	}
	rels = append(rels, ownedBy(scanID, caller), ownedBy(scanID, target))
	return assets, rels
}

func mergeProps(base, extra map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func appendPolicy(scanID string, assets []models.AssetNode, rels []models.Relationship, nodes []models.AssetNode, edges []models.Relationship) ([]models.AssetNode, []models.Relationship) {
	for i := range nodes {
		nodes[i].ScanID = scanID
	}
	for i := range edges {
		edges[i].ScanID = scanID
	}
	return append(assets, nodes...), append(rels, edges...)
}

func attachIdentity(scanID string, role models.AssetNode, policy collectors.IdentityPolicyInput, assets *[]models.AssetNode, rels *[]models.Relationship) {
	nodes, edges := collectors.BuildIdentityPolicyEvidence(role, []collectors.IdentityPolicyInput{policy})
	nextAssets, nextRels := appendPolicy(scanID, *assets, *rels, nodes, edges)
	*assets = nextAssets
	*rels = nextRels
}

func trustDeny(principal string) string {
	return fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"%s"},"Action":"sts:AssumeRole"},{"Effect":"Deny","Principal":{"AWS":"%s"},"Action":"sts:AssumeRole"}]}`, principal, principal)
}

func bucketAllow(principal, resource string) string {
	return fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"%s"},"Action":"s3:GetObject","Resource":"%s"}}`, principal, resource)
}

func bucketDeny(principal, resource string) string {
	return fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Deny","Principal":{"AWS":"%s"},"Action":"s3:GetObject","Resource":"%s"}}`, principal, resource)
}

func multiAction(resource string) string {
	return fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"%s"},{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"%s"}]}`, resource, resource)
}
