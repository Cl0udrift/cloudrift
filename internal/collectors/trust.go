package collectors

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/models"
)

var accountIDInIAMArn = regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):`)

// roleTrustConcurrency bounds parallel per-role policy fetches (ListAttachedRolePolicies /
// ListRolePolicies / GetRolePolicy). Each external-trusting role needs several sequential
// IAM calls; processing roles one at a time made trust the slowest stage on large accounts.
const roleTrustConcurrency = 32

type IAMAPI interface {
	ListRoles(ctx context.Context, params *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error)
	ListAttachedRolePolicies(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	ListRolePolicies(ctx context.Context, params *iam.ListRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error)
	GetRolePolicy(ctx context.Context, params *iam.GetRolePolicyInput, optFns ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error)
	GetPolicy(ctx context.Context, params *iam.GetPolicyInput, optFns ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(ctx context.Context, params *iam.GetPolicyVersionInput, optFns ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
}

func retrieveBoundaryDocument(ctx context.Context, client IAMAPI, roleNode *models.AssetNode, cache *managedPolicyCache) {
	if roleNode == nil || roleNode.Properties == nil {
		return
	}
	if stringValue(roleNode.Properties["permissions_boundary_status"]) != "present" {
		return
	}
	arn := strings.TrimSpace(stringValue(roleNode.Properties["permissions_boundary_arn"]))
	if arn == "" {
		roleNode.Properties["permissions_boundary_status"] = "missing"
		roleNode.Properties["permissions_boundary_retrieval"] = "missing"
		roleNode.Properties["permissions_boundary_evidence"] = "a permissions boundary was indicated without an ARN; this is not confirmed absence"
		return
	}
	roleNode.Properties["permissions_boundary_retrieved_at"] = time.Now().UTC().Format(time.RFC3339)
	fetched := cache.get(ctx, client, arn, arn, roleNode.AccountID)
	roleNode.Properties["permissions_boundary_version"] = fetched.VersionID
	switch fetched.RetrievalStatus {
	case models.PolicyRetrievalOK:
		roleNode.Properties["permissions_boundary_document"] = fetched.Document
		roleNode.Properties["permissions_boundary_retrieval"] = "collected"
		roleNode.Properties["permissions_boundary_status"] = "present"
		roleNode.Properties["permissions_boundary_evidence"] = "iam:GetPolicy and iam:GetPolicyVersion retrieved the default boundary policy version"
	case models.PolicyRetrievalMalformed:
		roleNode.Properties["permissions_boundary_document"] = fetched.Document
		roleNode.Properties["permissions_boundary_retrieval"] = "malformed"
		roleNode.Properties["permissions_boundary_status"] = "malformed"
		roleNode.Properties["permissions_boundary_evidence"] = "the boundary document was retrieved but could not be normalized. It is not treated as absent."
	default:
		delete(roleNode.Properties, "permissions_boundary_document")
		roleNode.Properties["permissions_boundary_retrieval"] = "missing"
		roleNode.Properties["permissions_boundary_status"] = "missing"
		roleNode.Properties["permissions_boundary_evidence"] = "a boundary ARN is attached but the policy document was not retrieved. This is not confirmed absence."
	}
}

func boundaryPolicyGraph(role models.AssetNode) ([]models.AssetNode, []models.Relationship) {
	arn := strings.TrimSpace(stringValue(role.Properties["permissions_boundary_arn"]))
	if arn == "" {
		return nil, nil
	}
	status := stringValue(role.Properties["permissions_boundary_retrieval"])
	retrieval := models.PolicyRetrievalMissing
	switch status {
	case "collected":
		retrieval = models.PolicyRetrievalOK
	case "malformed":
		retrieval = models.PolicyRetrievalMalformed
	}
	return policyEvidenceGraph(role, []collectedPolicy{{
		ARN:             arn,
		Name:            arn,
		PolicyType:      "permissions_boundary",
		VersionID:       stringValue(role.Properties["permissions_boundary_version"]),
		Document:        stringValue(role.Properties["permissions_boundary_document"]),
		RetrievalStatus: retrieval,
		RoleARN:         role.ARN,
		AccountID:       role.AccountID,
	}})
}

func observePermissionsBoundary(roleNode *models.AssetNode, role iamtypes.Role) {
	if roleNode.Properties == nil {
		roleNode.Properties = map[string]any{}
	}
	if role.PermissionsBoundary != nil {
		arn := strings.TrimSpace(awsv2.ToString(role.PermissionsBoundary.PermissionsBoundaryArn))
		if arn != "" {
			roleNode.Properties["permissions_boundary_arn"] = arn
			roleNode.Properties["permissions_boundary_status"] = "present"
			roleNode.Properties["permissions_boundary_evidence"] = "iam:ListRoles returned a permissions boundary ARN; the boundary policy document was not retrieved"
			return
		}
	}
	roleNode.Properties["permissions_boundary_status"] = "confirmed_absent"
	roleNode.Properties["permissions_boundary_evidence"] = "iam:ListRoles returned this role with no permissions boundary"
}

var newIAMClient = func(cfg awsv2.Config) IAMAPI {
	return iam.NewFromConfig(cfg)
}

func CollectTrust(ctx context.Context, accounts []Account) ([]models.AssetNode, []models.Relationship, error) {
	return CollectTrustWithConfig(ctx, config.Default(), accounts)
}

func CollectTrustWithConfig(ctx context.Context, cfg *config.Config, accounts []Account) ([]models.AssetNode, []models.Relationship, error) {
	sem := make(chan struct{}, max(1, cfg.Scan.RoleAssumptionConcurrency))
	// Shared across accounts so total parallel per-role policy fetches stay bounded.
	roleSem := make(chan struct{}, roleTrustConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error

	nodeByARN := make(map[string]models.AssetNode)
	relByKey := make(map[string]models.Relationship)

	for _, account := range accounts {
		account := account
		if account.Session == nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			inventory := cfg != nil && cfg.Scan.IAMPolicyInventory
			localNodes, localRels, err := collectTrustFromClient(ctx, account.ID, newIAMClient(*account.Session), inventory, roleSem)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				failed := CollectionStatus(account.ID, "", "iam", "global", "failed", err.Error())
				nodeByARN[failed.ARN] = failed
				mu.Unlock()
				return
			}

			mu.Lock()
			succeeded := CollectionStatus(account.ID, "", "iam", "global", "succeeded", "")
			nodeByARN[succeeded.ARN] = succeeded
			for _, n := range localNodes {
				nodeByARN[n.ARN] = n
			}
			for _, r := range localRels {
				key := r.SourceARN + "|" + string(r.RelType) + "|" + r.TargetARN
				relByKey[key] = r
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	warnPartial(ctx, "trust", firstErr)

	nodes := make([]models.AssetNode, 0, len(nodeByARN))
	for _, node := range nodeByARN {
		nodes = append(nodes, node)
	}
	rels := make([]models.Relationship, 0, len(relByKey))
	for _, rel := range relByKey {
		rels = append(rels, rel)
	}

	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].ARN == nodes[j].ARN {
			return nodes[i].AssetType < nodes[j].AssetType
		}
		return nodes[i].ARN < nodes[j].ARN
	})
	sort.Slice(rels, func(i, j int) bool {
		if rels[i].SourceARN == rels[j].SourceARN {
			return rels[i].TargetARN < rels[j].TargetARN
		}
		return rels[i].SourceARN < rels[j].SourceARN
	})

	return nodes, rels, nil
}

func collectTrustFromClient(ctx context.Context, accountID string, client IAMAPI, inventory bool, roleSem chan struct{}) ([]models.AssetNode, []models.Relationship, error) {
	// Paginate the (cheap) role listing first; listing failure is fatal for the account.
	var roles []iamtypes.Role
	var marker *string
	for {
		out, err := client.ListRoles(ctx, &iam.ListRolesInput{Marker: marker})
		if err != nil {
			return nil, nil, err
		}
		roles = append(roles, out.Roles...)
		if !out.IsTruncated || out.Marker == nil {
			break
		}
		marker = out.Marker
	}

	// Fan out per-role: extracting principals and fetching each role's attached/inline
	// policies is several IAM calls per role, so run them concurrently. Output ordering is
	// irrelevant here — the caller dedups by ARN and sorts.
	var roleNodes []models.AssetNode
	var principalNodes []models.AssetNode
	var rels []models.Relationship
	var mu sync.Mutex
	var wg sync.WaitGroup
	managedCache := newManagedPolicyCache()
	for _, role := range roles {
		role := role
		principals := extractExternalPrincipals(accountID, awsv2.ToString(role.AssumeRolePolicyDocument))
		if len(principals) == 0 && !inventory {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			roleSem <- struct{}{}
			defer func() { <-roleSem }()

			roleNode := models.AssetNode{
				ARN:       awsv2.ToString(role.Arn),
				AssetType: models.AssetIAMRole,
				Name:      awsv2.ToString(role.RoleName),
				AccountID: accountID,
				Region:    "global",
				Properties: map[string]any{
					"path":                  awsv2.ToString(role.Path),
					"role_id":               awsv2.ToString(role.RoleId),
					"trust_policy_document": decodeIAMDocument(awsv2.ToString(role.AssumeRolePolicyDocument)),
				},
			}
			if role.CreateDate != nil {
				roleNode.Properties["create_date"] = role.CreateDate.UTC().Format(time.RFC3339)
			}
			if role.RoleLastUsed != nil && role.RoleLastUsed.LastUsedDate != nil {
				roleNode.Properties["role_last_used"] = role.RoleLastUsed.LastUsedDate.UTC().Format(time.RFC3339)
			}
			observePermissionsBoundary(&roleNode, role)
			var policyNodes []models.AssetNode
			var policyRels []models.Relationship
			if inventory {
				retrieveBoundaryDocument(ctx, client, &roleNode, managedCache)
				bundle := collectRolePolicyEvidence(ctx, client, roleNode, managedCache)
				roleNode.Properties["attached_policy_names"] = bundle.AttachedNames
				roleNode.Properties["attached_policy_arns"] = bundle.AttachedARNs
				roleNode.Properties["inline_policy_documents"] = bundle.InlineDocs
				roleNode.Properties["policy_parse_ok"] = bundle.ParseOK
				roleNode.Properties["policy_retrieval_status"] = bundle.RetrievalStatus
				policyNodes, policyRels = policyEvidenceGraph(roleNode, bundle.Policies)
				if boundaryNodes, boundaryRels := boundaryPolicyGraph(roleNode); len(boundaryNodes) > 0 {
					policyNodes = append(policyNodes, boundaryNodes...)
					policyRels = append(policyRels, boundaryRels...)
				}
			} else {
				attachedPolicyNames, inlinePolicyDocuments, parseOK := collectRolePermissionInputs(ctx, client, roleNode.Name)
				roleNode.Properties["attached_policy_names"] = attachedPolicyNames
				roleNode.Properties["inline_policy_documents"] = inlinePolicyDocuments
				roleNode.Properties["policy_parse_ok"] = parseOK
			}

			localPrincipals := make([]models.AssetNode, 0, len(principals))
			localRels := make([]models.Relationship, 0, len(principals))
			for _, p := range principals {
				extNode := models.AssetNode{
					ARN:       externalPrincipalARN(p.PrincipalType, p.Value),
					AssetType: models.AssetExternalPrincipal,
					Name:      p.Value,
					AccountID: accountID,
					Region:    "global",
					Properties: map[string]any{
						"principal_type":  p.PrincipalType,
						"principal_value": p.Value,
					},
				}
				extNode, _ = models.ResolvePrincipalOwnership(extNode)
				localPrincipals = append(localPrincipals, extNode)
				localRels = append(localRels, models.Relationship{
					SourceARN: roleNode.ARN,
					TargetARN: extNode.ARN,
					RelType:   models.RelTrusts,
					Properties: map[string]any{
						"principal_type":  p.PrincipalType,
						"principal_value": p.Value,
					},
				})
			}

			mu.Lock()
			roleNodes = append(roleNodes, roleNode)
			roleNodes = append(roleNodes, policyNodes...)
			principalNodes = append(principalNodes, localPrincipals...)
			rels = append(rels, localRels...)
			rels = append(rels, policyRels...)
			mu.Unlock()
		}()
	}
	wg.Wait()

	nodes := append(roleNodes, principalNodes...)
	if inventory {
		if details, ok := client.(IAMAuthDetailsAPI); ok {
			status := CollectionStatus(accountID, "", "iam_users_groups", "global", "succeeded", "")
			userNodes, userRels, err := collectUsersGroups(ctx, accountID, details, client, managedCache)
			if err != nil {
				// Usually AccessDenied on iam:GetAccountAuthorizationDetails. Roles still scan.
				status = CollectionStatus(accountID, "", "iam_users_groups", "global", "failed", err.Error())
			}
			nodes = append(nodes, status)
			if err == nil {
				if cr, ok := client.(IAMCredentialReportAPI); ok {
					credStatus := CollectionStatus(accountID, "", "iam_credential_report", "global", "succeeded", "")
					content, cerr := fetchCredentialReport(ctx, cr)
					if cerr == nil {
						cerr = annotateCredentials(userNodes, content)
					}
					if cerr != nil {
						credStatus = CollectionStatus(accountID, "", "iam_credential_report", "global", "failed", cerr.Error())
					}
					nodes = append(nodes, credStatus)
				}
			}
			nodes = append(nodes, userNodes...)
			rels = append(rels, userRels...)
		}
	}
	return nodes, rels, nil
}

type externalPrincipal struct {
	PrincipalType string
	Value         string
}

func extractExternalPrincipals(accountID, rawPolicy string) []externalPrincipal {
	doc, ok := parsePolicyDocument(rawPolicy)
	if !ok {
		return nil
	}

	var principals []externalPrincipal
	for _, statement := range doc.Statement {
		if !statementAllowsAssumeRole(statement) {
			continue
		}

		awsValues := principalValues(statement.Principal["AWS"])
		for _, v := range awsValues {
			if normalized, keep := normalizeExternalAWSPrincipal(accountID, v); keep {
				principals = append(principals, externalPrincipal{
					PrincipalType: "aws_account",
					Value:         normalized,
				})
			}
		}

		federatedValues := principalValues(statement.Principal["Federated"])
		for _, v := range federatedValues {
			pt := classifyFederatedPrincipal(v)
			if pt == "" {
				continue
			}
			principals = append(principals, externalPrincipal{
				PrincipalType: pt,
				Value:         strings.TrimSpace(v),
			})
		}
	}

	if len(principals) == 0 {
		return nil
	}

	dedup := make(map[string]externalPrincipal)
	for _, p := range principals {
		key := p.PrincipalType + "|" + p.Value
		dedup[key] = p
	}
	out := make([]externalPrincipal, 0, len(dedup))
	for _, p := range dedup {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PrincipalType == out[j].PrincipalType {
			return out[i].Value < out[j].Value
		}
		return out[i].PrincipalType < out[j].PrincipalType
	})
	return out
}

type policyDocument struct {
	Statement []policyStatement
}

type policyStatement struct {
	Effect    string
	Action    any
	Principal map[string]any
}

func parsePolicyDocument(raw string) (policyDocument, bool) {
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		decoded = raw
	}

	var anyDoc map[string]any
	if err := json.Unmarshal([]byte(decoded), &anyDoc); err != nil {
		return policyDocument{}, false
	}

	statementsAny, ok := anyDoc["Statement"]
	if !ok {
		return policyDocument{}, false
	}

	var statementMaps []map[string]any
	switch typed := statementsAny.(type) {
	case map[string]any:
		statementMaps = append(statementMaps, typed)
	case []any:
		for _, item := range typed {
			if m, ok := item.(map[string]any); ok {
				statementMaps = append(statementMaps, m)
			}
		}
	default:
		return policyDocument{}, false
	}

	out := policyDocument{Statement: make([]policyStatement, 0, len(statementMaps))}
	for _, m := range statementMaps {
		stmt := policyStatement{
			Effect: strings.TrimSpace(stringValue(m["Effect"])),
			Action: m["Action"],
		}
		if principalMap, ok := m["Principal"].(map[string]any); ok {
			stmt.Principal = principalMap
		} else {
			stmt.Principal = map[string]any{}
		}
		out.Statement = append(out.Statement, stmt)
	}
	return out, true
}

func statementAllowsAssumeRole(statement policyStatement) bool {
	if !strings.EqualFold(statement.Effect, "Allow") {
		return false
	}
	actions := principalValues(statement.Action)
	for _, action := range actions {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(action)), "sts:assumerole") {
			return true
		}
	}
	return false
}

func principalValues(raw any) []string {
	switch typed := raw.(type) {
	case string:
		v := strings.TrimSpace(typed)
		if v == "" {
			return nil
		}
		return []string{v}
	case []string:
		var out []string
		for _, item := range typed {
			item = strings.TrimSpace(item)
			if item != "" {
				out = append(out, item)
			}
		}
		return out
	case []any:
		var out []string
		for _, item := range typed {
			s, ok := item.(string)
			if !ok {
				continue
			}
			s = strings.TrimSpace(s)
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func normalizeExternalAWSPrincipal(accountID, value string) (string, bool) {
	value = strings.TrimSpace(value)
	if value == "" || value == "*" {
		return "", false
	}

	if len(value) == 12 && isDigits(value) {
		if value == accountID {
			return "", false
		}
		return "arn:aws:iam::" + value + ":root", true
	}

	m := accountIDInIAMArn.FindStringSubmatch(value)
	if len(m) == 2 {
		if m[1] == accountID {
			return "", false
		}
		return value, true
	}
	return "", false
}

func classifyFederatedPrincipal(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	lower := strings.ToLower(value)
	if strings.HasSuffix(lower, ".amazonaws.com") || strings.Contains(lower, ".amazonaws.com") {
		return ""
	}
	if strings.Contains(lower, "saml-provider/") {
		return "saml"
	}
	return "oidc"
}

func externalPrincipalARN(principalType, principalValue string) string {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(strings.TrimSpace(principalValue)))
	return "arn:cloudrift:external-principal:::" + principalType + "/" + encoded
}

func decodeIAMDocument(raw string) string {
	decoded, err := url.QueryUnescape(strings.TrimSpace(raw))
	if err != nil || strings.TrimSpace(decoded) == "" {
		return strings.TrimSpace(raw)
	}
	return decoded
}

type managedPolicyCache struct {
	mu       sync.Mutex
	byARN    map[string]collectedPolicy
	inflight map[string]*policyFetch
}

type policyFetch struct {
	done   chan struct{}
	result collectedPolicy
}

func newManagedPolicyCache() *managedPolicyCache {
	return &managedPolicyCache{byARN: map[string]collectedPolicy{}, inflight: map[string]*policyFetch{}}
}

func (c *managedPolicyCache) get(ctx context.Context, client IAMAPI, arn, name, accountID string) collectedPolicy {
	c.mu.Lock()
	if existing, ok := c.byARN[arn]; ok {
		c.mu.Unlock()
		return existing
	}
	if call, ok := c.inflight[arn]; ok {
		c.mu.Unlock()
		select {
		case <-call.done:
			return call.result
		case <-ctx.Done():
			return collectedPolicy{ARN: arn, Name: name, PolicyType: models.PolicyTypeManaged, AccountID: accountID, RetrievalStatus: models.PolicyRetrievalMissing}
		}
	}
	call := &policyFetch{done: make(chan struct{})}
	c.inflight[arn] = call
	c.mu.Unlock()

	fetched := fetchManagedPolicy(ctx, client, arn, name, accountID)
	c.mu.Lock()
	c.byARN[arn] = fetched
	delete(c.inflight, arn)
	call.result = fetched
	close(call.done)
	c.mu.Unlock()
	return fetched
}

func fetchManagedPolicy(ctx context.Context, client IAMAPI, arn, name, accountID string) collectedPolicy {
	out := collectedPolicy{
		ARN: arn, Name: name, PolicyType: models.PolicyTypeManaged, AccountID: accountID,
		RetrievalStatus: models.PolicyRetrievalMissing, VersionVerification: models.PolicyVersionMissing,
	}
	const attempts = 3
	for attempt := 0; attempt < attempts; attempt++ {
		policy, err := client.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: awsv2.String(arn)})
		if err != nil || policy == nil || policy.Policy == nil {
			return out
		}
		versionID := strings.TrimSpace(awsv2.ToString(policy.Policy.DefaultVersionId))
		out.VersionID = versionID
		if versionID == "" {
			out.VersionVerification = models.PolicyVersionMissing
			return out
		}
		ver, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
			PolicyArn: awsv2.String(arn),
			VersionId: awsv2.String(versionID),
		})
		if err != nil || ver == nil || ver.PolicyVersion == nil {
			out.VersionVerification = models.PolicyVersionMissing
			return out
		}
		returned := strings.TrimSpace(awsv2.ToString(ver.PolicyVersion.VersionId))
		out.Document = decodeIAMDocument(awsv2.ToString(ver.PolicyVersion.Document))
		if returned != "" && returned != versionID {
			out.VersionVerification = models.PolicyVersionMismatch
			out.RetrievalStatus = models.PolicyRetrievalPartial
			return out
		}
		if strings.TrimSpace(out.Document) == "" {
			out.VersionVerification = models.PolicyVersionMissing
			return out
		}
		if _, nerr := models.NormalizeIdentityPolicy(arn, models.PolicyTypeManaged, accountID, out.Document); nerr != nil {
			out.RetrievalStatus = models.PolicyRetrievalMalformed
			out.VersionVerification = models.PolicyVersionMissing
			return out
		}
		confirm, cerr := client.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: awsv2.String(arn)})
		if cerr != nil || confirm == nil || confirm.Policy == nil {
			out.VersionVerification = models.PolicyVersionIndeterminate
			out.RetrievalStatus = models.PolicyRetrievalPartial
			return out
		}
		confirmed := strings.TrimSpace(awsv2.ToString(confirm.Policy.DefaultVersionId))
		if confirmed == versionID {
			out.RetrievalStatus = models.PolicyRetrievalOK
			out.VersionVerification = models.PolicyVersionVerified
			return out
		}
		out.VersionVerification = models.PolicyVersionIndeterminate
		out.RetrievalStatus = models.PolicyRetrievalPartial
	}
	return out
}

type rolePolicyBundle struct {
	AttachedNames   []string
	AttachedARNs    []string
	InlineDocs      []string
	Policies        []collectedPolicy
	ParseOK         bool
	RetrievalStatus string
}

func (b *rolePolicyBundle) mark(status string) {
	b.ParseOK = false
	switch {
	case b.RetrievalStatus == "" || b.RetrievalStatus == models.PolicyRetrievalOK:
		b.RetrievalStatus = status
	case b.RetrievalStatus != status:
		b.RetrievalStatus = models.PolicyRetrievalPartial
	}
}

func collectRolePolicyEvidence(ctx context.Context, client IAMAPI, role models.AssetNode, cache *managedPolicyCache) rolePolicyBundle {
	bundle := rolePolicyBundle{ParseOK: true, RetrievalStatus: models.PolicyRetrievalOK}
	var attachedMarker *string
	for {
		out, err := client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
			RoleName: awsv2.String(role.Name),
			Marker:   attachedMarker,
		})
		if err != nil {
			bundle.mark(models.PolicyRetrievalMissing)
			break
		}
		for _, ap := range out.AttachedPolicies {
			name := strings.TrimSpace(awsv2.ToString(ap.PolicyName))
			arn := strings.TrimSpace(awsv2.ToString(ap.PolicyArn))
			if name != "" {
				bundle.AttachedNames = append(bundle.AttachedNames, name)
			}
			if arn == "" {
				bundle.mark(models.PolicyRetrievalMissing)
				bundle.Policies = append(bundle.Policies, collectedPolicy{
					Name:            name,
					PolicyType:      models.PolicyTypeManaged,
					RetrievalStatus: models.PolicyRetrievalMissing,
					RoleARN:         role.ARN,
					AccountID:       role.AccountID,
				})
				continue
			}
			bundle.AttachedARNs = append(bundle.AttachedARNs, arn)
			fetched := cache.get(ctx, client, arn, name, role.AccountID)
			fetched.RoleARN = role.ARN
			if fetched.RetrievalStatus != models.PolicyRetrievalOK {
				bundle.mark(fetched.RetrievalStatus)
			}
			bundle.Policies = append(bundle.Policies, fetched)
		}
		if !out.IsTruncated || out.Marker == nil {
			break
		}
		attachedMarker = out.Marker
	}

	inlineNames := make([]string, 0, 4)
	var inlineMarker *string
	for {
		out, err := client.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
			RoleName: awsv2.String(role.Name),
			Marker:   inlineMarker,
		})
		if err != nil {
			bundle.mark(models.PolicyRetrievalMissing)
			break
		}
		for _, pn := range out.PolicyNames {
			if s := strings.TrimSpace(pn); s != "" {
				inlineNames = append(inlineNames, s)
			}
		}
		if !out.IsTruncated || out.Marker == nil {
			break
		}
		inlineMarker = out.Marker
	}
	for _, pn := range inlineNames {
		policy := collectedPolicy{
			Name:            pn,
			PolicyType:      models.PolicyTypeInline,
			RoleARN:         role.ARN,
			AccountID:       role.AccountID,
			RetrievalStatus: models.PolicyRetrievalMissing,
		}
		out, err := client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
			RoleName:   awsv2.String(role.Name),
			PolicyName: awsv2.String(pn),
		})
		if err != nil {
			bundle.mark(models.PolicyRetrievalMissing)
			bundle.Policies = append(bundle.Policies, policy)
			continue
		}
		policy.Document = decodeIAMDocument(awsv2.ToString(out.PolicyDocument))
		if _, nerr := models.NormalizeIdentityPolicy(inlinePolicyARN(role.AccountID, role.Name, pn), models.PolicyTypeInline, role.AccountID, policy.Document); nerr != nil {
			policy.RetrievalStatus = models.PolicyRetrievalMalformed
			bundle.mark(models.PolicyRetrievalMalformed)
		} else {
			policy.RetrievalStatus = models.PolicyRetrievalOK
			bundle.InlineDocs = append(bundle.InlineDocs, policy.Document)
		}
		bundle.Policies = append(bundle.Policies, policy)
	}
	if bundle.RetrievalStatus == "" {
		bundle.RetrievalStatus = models.PolicyRetrievalOK
	}
	sort.Strings(bundle.AttachedNames)
	sort.Strings(bundle.AttachedARNs)
	sort.Strings(bundle.InlineDocs)
	return bundle
}

func collectRolePermissionInputs(ctx context.Context, client IAMAPI, roleName string) ([]string, []string, bool) {
	attachedPolicyNames := make([]string, 0, 4)
	inlinePolicyDocuments := make([]string, 0, 4)
	parseOK := true

	var attachedMarker *string
	for {
		out, err := client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
			RoleName: awsv2.String(roleName),
			Marker:   attachedMarker,
		})
		if err != nil {
			parseOK = false
			break
		}
		for _, ap := range out.AttachedPolicies {
			name := strings.TrimSpace(awsv2.ToString(ap.PolicyName))
			if name != "" {
				attachedPolicyNames = append(attachedPolicyNames, name)
			}
		}
		if !out.IsTruncated || out.Marker == nil {
			break
		}
		attachedMarker = out.Marker
	}

	inlinePolicyNames := make([]string, 0, 4)
	var inlineMarker *string
	for {
		out, err := client.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
			RoleName: awsv2.String(roleName),
			Marker:   inlineMarker,
		})
		if err != nil {
			parseOK = false
			break
		}
		for _, pn := range out.PolicyNames {
			if s := strings.TrimSpace(pn); s != "" {
				inlinePolicyNames = append(inlinePolicyNames, s)
			}
		}
		if !out.IsTruncated || out.Marker == nil {
			break
		}
		inlineMarker = out.Marker
	}

	for _, pn := range inlinePolicyNames {
		out, err := client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
			RoleName:   awsv2.String(roleName),
			PolicyName: awsv2.String(pn),
		})
		if err != nil {
			parseOK = false
			continue
		}
		decoded, err := url.QueryUnescape(awsv2.ToString(out.PolicyDocument))
		if err != nil {
			parseOK = false
			continue
		}
		inlinePolicyDocuments = append(inlinePolicyDocuments, decoded)
	}

	sort.Strings(attachedPolicyNames)
	sort.Strings(inlinePolicyDocuments)
	return attachedPolicyNames, inlinePolicyDocuments, parseOK
}

func stringValue(v any) string {
	s, _ := v.(string)
	return s
}

func isDigits(v string) bool {
	for _, ch := range v {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}
