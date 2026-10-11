package collectors

import (
	"context"
	"errors"
	"strings"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/smithy-go"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// OrgAuthorizationAPI is the read-only Organizations surface used to collect
// SCP and RCP documents. It is satisfied by the AWS SDK client.
type OrgAuthorizationAPI interface {
	DescribeOrganization(ctx context.Context, params *organizations.DescribeOrganizationInput, optFns ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error)
	ListRoots(ctx context.Context, params *organizations.ListRootsInput, optFns ...func(*organizations.Options)) (*organizations.ListRootsOutput, error)
	ListParents(ctx context.Context, params *organizations.ListParentsInput, optFns ...func(*organizations.Options)) (*organizations.ListParentsOutput, error)
	ListPoliciesForTarget(ctx context.Context, params *organizations.ListPoliciesForTargetInput, optFns ...func(*organizations.Options)) (*organizations.ListPoliciesForTargetOutput, error)
	DescribePolicy(ctx context.Context, params *organizations.DescribePolicyInput, optFns ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error)
}

// OrgPolicyDocument is one organization policy attachment and its content.
// The same policy ID may appear more than once when it is attached to more
// than one hierarchy node.
type OrgPolicyDocument struct {
	PolicyID    string
	Name        string
	Type        string
	TargetID    string
	Level       string
	Document    string
	RetrievedAt string
}

// AccountOrgEvidence is the organization control set for one account.
// Incomplete means the documents must not be evaluated as the full applicable set.
type AccountOrgEvidence struct {
	HierarchyComplete bool
	IsManagement      bool
	SCPKnown          bool
	SCPEnabled        bool
	RCPKnown          bool
	RCPEnabled        bool
	SCPDocuments      []OrgPolicyDocument
	RCPDocuments      []OrgPolicyDocument
	ParentChain       []string
	Detail            string
}

// OrgAuthorizationEvidence is collected once per scan from the management or
// delegated administrator credential, then applied to every scanned account.
type OrgAuthorizationEvidence struct {
	Discovery           string
	OrganizationID      string
	ManagementAccountID string
	Detail              string
	Accounts            map[string]AccountOrgEvidence
}

// CollectOrgAuthorization reads organization hierarchy and SCP/RCP documents.
// AccessDenied and a failed parent walk stay incomplete. They are not evidence
// that no policy applies. A standalone account is not_in_organization.
func CollectOrgAuthorization(ctx context.Context, api OrgAuthorizationAPI, accountIDs []string) OrgAuthorizationEvidence {
	ev := OrgAuthorizationEvidence{Discovery: "failed", Accounts: map[string]AccountOrgEvidence{}}
	if api == nil {
		ev.Detail = "organization client was not configured"
		return ev
	}
	described, err := api.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	if err != nil {
		switch {
		case orgNotInUse(err):
			ev.Discovery = "not_in_organization"
			ev.Detail = "DescribeOrganization reported that this account is not a member of an organization"
		case orgDenied(err):
			ev.Discovery = "access_denied"
			ev.Detail = "Organizations API access was denied. This is not evidence that no SCP or RCP applies."
		default:
			ev.Discovery = "failed"
			ev.Detail = err.Error()
		}
		return ev
	}
	if described == nil || described.Organization == nil {
		ev.Detail = "DescribeOrganization returned no organization"
		return ev
	}
	ev.Discovery = "collected"
	ev.OrganizationID = strings.TrimSpace(awsv2.ToString(described.Organization.Id))
	ev.ManagementAccountID = strings.TrimSpace(awsv2.ToString(described.Organization.MasterAccountId))
	if described.Organization.FeatureSet == orgtypes.OrganizationFeatureSetConsolidatedBilling {
		ev.Detail = "organization feature set CONSOLIDATED_BILLING does not support service control policies or resource control policies"
		for _, id := range accountIDs {
			id = strings.TrimSpace(id)
			if id == "" {
				continue
			}
			ev.Accounts[id] = AccountOrgEvidence{
				HierarchyComplete: true, SCPKnown: true, RCPKnown: true, Detail: ev.Detail,
				IsManagement: id == ev.ManagementAccountID,
			}
		}
		return ev
	}
	roots, rootErr := listRoots(ctx, api)
	if rootErr != nil {
		ev.Detail = rootErr.Error()
		for _, id := range accountIDs {
			ev.Accounts[id] = AccountOrgEvidence{Detail: ev.Detail}
		}
		return ev
	}
	rootByID := map[string]orgtypes.Root{}
	for _, root := range roots {
		rootByID[awsv2.ToString(root.Id)] = root
	}
	cache := map[string]OrgPolicyDocument{}
	seen := map[string]struct{}{}
	for _, id := range accountIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ev.Accounts[id] = accountOrgEvidence(ctx, api, id, ev.ManagementAccountID, rootByID, cache)
	}
	return ev
}

// ApplyOrgEvidence stamps collected organization controls onto IAM roles.
// Roles outside the collected account set are left unchanged.
func ApplyOrgEvidence(nodes []models.AssetNode, ev OrgAuthorizationEvidence) {
	for i := range nodes {
		if nodes[i].AssetType != models.AssetIAMRole {
			continue
		}
		if _, ok := ev.Accounts[nodes[i].AccountID]; !ok && ev.Discovery == "collected" {
			continue
		}
		if nodes[i].Properties == nil {
			nodes[i].Properties = map[string]any{}
		}
		props := nodes[i].Properties
		props["org_policy_discovery"] = ev.Discovery
		switch ev.Discovery {
		case "access_denied", "failed":
			setControlMissing(props, "scp", ev.Detail)
			setControlMissing(props, "rcp", ev.Detail)
			continue
		case "not_in_organization":
			setControlAbsent(props, "scp", ev.Detail)
			setControlAbsent(props, "rcp", ev.Detail)
			continue
		}
		account := ev.Accounts[nodes[i].AccountID]
		if ev.ManagementAccountID != "" {
			props["org_management_account_id"] = ev.ManagementAccountID
		}
		if len(account.ParentChain) > 0 {
			props["org_hierarchy_targets"] = append([]string{}, account.ParentChain...)
		}
		if ev.ManagementAccountID != "" && nodes[i].AccountID == ev.ManagementAccountID {
			note := "the management account is not affected by service control policies or resource control policies"
			setControlAbsent(props, "scp", note)
			setControlAbsent(props, "rcp", note)
			continue
		}
		path, _ := props["path"].(string)
		if strings.Contains(path, "/aws-service-role/") {
			setControlAbsent(props, "scp", "service-linked roles are not limited by service control policies")
		} else {
			applyControl(props, "scp", account.SCPKnown, account.SCPEnabled, account.HierarchyComplete, account.SCPDocuments, account.Detail)
		}
		applyControl(props, "rcp", account.RCPKnown, account.RCPEnabled, account.HierarchyComplete, account.RCPDocuments, account.Detail)
	}
}

func accountOrgEvidence(ctx context.Context, api OrgAuthorizationAPI, accountID, managementID string, roots map[string]orgtypes.Root, cache map[string]OrgPolicyDocument) AccountOrgEvidence {
	out := AccountOrgEvidence{IsManagement: accountID == managementID && managementID != ""}
	chain, rootID, err := parentChain(ctx, api, accountID)
	if err != nil {
		out.Detail = err.Error()
		return out
	}
	out.ParentChain = append([]string{}, chain...)
	root, ok := roots[rootID]
	if !ok {
		out.Detail = "organization root " + rootID + " was not returned by ListRoots"
		return out
	}
	out.SCPEnabled, out.SCPKnown = policyTypeEnabled(root, orgtypes.PolicyTypeServiceControlPolicy)
	out.RCPEnabled, out.RCPKnown = policyTypeEnabled(root, orgtypes.PolicyTypeResourceControlPolicy)
	if !out.SCPKnown || !out.RCPKnown {
		out.Detail = "policy type status was not present on the organization root"
		return out
	}
	if out.SCPEnabled {
		docs, err := policiesForChain(ctx, api, chain, orgtypes.PolicyTypeServiceControlPolicy, cache)
		if err != nil {
			out.Detail = err.Error()
			return out
		}
		out.SCPDocuments = docs
	}
	if out.RCPEnabled {
		docs, err := policiesForChain(ctx, api, chain, orgtypes.PolicyTypeResourceControlPolicy, cache)
		if err != nil {
			out.Detail = err.Error()
			return out
		}
		out.RCPDocuments = docs
	}
	out.HierarchyComplete = true
	return out
}

func parentChain(ctx context.Context, api OrgAuthorizationAPI, accountID string) ([]string, string, error) {
	var chain []string
	current := accountID
	for range 16 {
		var parents []orgtypes.Parent
		var token *string
		for {
			resp, err := api.ListParents(ctx, &organizations.ListParentsInput{ChildId: awsv2.String(current), NextToken: token})
			if err != nil {
				return nil, "", err
			}
			parents = append(parents, resp.Parents...)
			if resp.NextToken == nil || awsv2.ToString(resp.NextToken) == "" {
				break
			}
			token = resp.NextToken
		}
		if len(parents) == 0 {
			return nil, "", errors.New("ListParents returned no parent for " + current)
		}
		parent := parents[0]
		pid := strings.TrimSpace(awsv2.ToString(parent.Id))
		if pid == "" {
			return nil, "", errors.New("ListParents returned an empty parent id")
		}
		chain = append(chain, pid)
		if parent.Type == orgtypes.ParentTypeRoot {
			return append([]string{accountID}, chain...), pid, nil
		}
		current = pid
	}
	return nil, "", errors.New("organization parent chain exceeded 16 levels")
}

func policiesForChain(ctx context.Context, api OrgAuthorizationAPI, chain []string, kind orgtypes.PolicyType, cache map[string]OrgPolicyDocument) ([]OrgPolicyDocument, error) {
	seen := map[string]struct{}{}
	var docs []OrgPolicyDocument
	for _, target := range chain {
		var token *string
		for {
			resp, err := api.ListPoliciesForTarget(ctx, &organizations.ListPoliciesForTargetInput{
				TargetId:  awsv2.String(target),
				Filter:    kind,
				NextToken: token,
			})
			if err != nil {
				return nil, err
			}
			for _, summary := range resp.Policies {
				id := strings.TrimSpace(awsv2.ToString(summary.Id))
				if id == "" {
					continue
				}
				key := id + "@" + target
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				doc, err := describePolicy(ctx, api, id, string(kind), target, cache)
				if err != nil {
					return nil, err
				}
				docs = append(docs, doc)
			}
			if resp.NextToken == nil || awsv2.ToString(resp.NextToken) == "" {
				break
			}
			token = resp.NextToken
		}
	}
	return docs, nil
}

func describePolicy(ctx context.Context, api OrgAuthorizationAPI, id, kind, target string, cache map[string]OrgPolicyDocument) (OrgPolicyDocument, error) {
	if existing, ok := cache[id]; ok {
		existing.TargetID = target
		existing.Level = attachmentLevel(target)
		return existing, nil
	}
	resp, err := api.DescribePolicy(ctx, &organizations.DescribePolicyInput{PolicyId: awsv2.String(id)})
	if err != nil {
		return OrgPolicyDocument{}, err
	}
	if resp == nil || resp.Policy == nil || resp.Policy.Content == nil {
		return OrgPolicyDocument{}, errors.New("DescribePolicy returned no content for " + id)
	}
	doc := OrgPolicyDocument{
		PolicyID:    id,
		Name:        strings.TrimSpace(awsv2.ToString(resp.Policy.PolicySummary.Name)),
		Type:        kind,
		TargetID:    target,
		Level:       attachmentLevel(target),
		Document:    strings.TrimSpace(awsv2.ToString(resp.Policy.Content)),
		RetrievedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if doc.Document == "" {
		return OrgPolicyDocument{}, errors.New("DescribePolicy returned an empty document for " + id)
	}
	cache[id] = doc
	return doc, nil
}

func listRoots(ctx context.Context, api OrgAuthorizationAPI) ([]orgtypes.Root, error) {
	var roots []orgtypes.Root
	var token *string
	for {
		resp, err := api.ListRoots(ctx, &organizations.ListRootsInput{NextToken: token})
		if err != nil {
			return nil, err
		}
		roots = append(roots, resp.Roots...)
		if resp.NextToken == nil || awsv2.ToString(resp.NextToken) == "" {
			break
		}
		token = resp.NextToken
	}
	return roots, nil
}

func policyTypeEnabled(root orgtypes.Root, kind orgtypes.PolicyType) (enabled bool, known bool) {
	if root.PolicyTypes == nil {
		return false, false
	}
	for _, item := range root.PolicyTypes {
		if item.Type != kind {
			continue
		}
		return item.Status == orgtypes.PolicyTypeStatusEnabled, true
	}
	return false, true
}

func applyControl(props map[string]any, kind string, known, enabled, complete bool, docs []OrgPolicyDocument, detail string) {
	if !complete || !known {
		note := "organization hierarchy or policy retrieval was incomplete. Partial policies were not evaluated as the full set."
		if detail != "" {
			note += " " + detail
		}
		setControlMissing(props, kind, note)
		props[kind+"_coverage"] = "PARTIAL"
		return
	}
	if !enabled {
		setControlAbsent(props, kind, strings.ToUpper(kind)+" policy type is not enabled for this organization root")
		props[kind+"_enabled"] = false
		return
	}
	if len(docs) == 0 {
		setControlMissing(props, kind, kind+" is enabled but no policy document was returned. An empty result is not treated as full access.")
		props[kind+"_coverage"] = "FAILED"
		return
	}
	raws := make([]string, 0, len(docs))
	refs := make([]string, 0, len(docs))
	attachments := make([]map[string]any, 0, len(docs))
	for _, doc := range docs {
		if strings.TrimSpace(doc.Document) == "" {
			setControlMissing(props, kind, kind+" policy "+doc.PolicyID+" had no document")
			props[kind+"_coverage"] = "FAILED"
			return
		}
		level := doc.Level
		if level == "" {
			level = attachmentLevel(doc.TargetID)
		}
		if level == "" || strings.TrimSpace(doc.TargetID) == "" {
			setControlMissing(props, kind, kind+" policy "+doc.PolicyID+" is not attached to a recorded root, organizational unit, or account")
			props[kind+"_coverage"] = "FAILED"
			return
		}
		raws = append(raws, doc.Document)
		refs = append(refs, doc.PolicyID+"@"+doc.TargetID)
		attachments = append(attachments, map[string]any{
			"policy_id":          doc.PolicyID,
			"policy_name":        doc.Name,
			"policy_type":        doc.Type,
			"attachment_level":   level,
			"attachment_target":  doc.TargetID,
			"document":           doc.Document,
			"retrieved_at":       doc.RetrievedAt,
			"evaluation_support": "supported_statement_language",
			"enabled":            true,
		})
	}
	props[kind+"_status"] = "present"
	props[kind+"_documents"] = raws
	props[kind+"_attachments"] = attachments
	props[kind+"_hierarchy_complete"] = true
	props[kind+"_enabled"] = true
	props[kind+"_evidence"] = "collected " + kind + " attachments " + strings.Join(refs, ", ")
	props[kind+"_coverage"] = "COMPLETE_FOR_SUPPORTED_SCOPE"
}

func attachmentLevel(target string) string {
	switch {
	case strings.HasPrefix(target, "r-"):
		return "root"
	case strings.HasPrefix(target, "ou-"):
		return "organizational_unit"
	case len(target) == 12 && digitsOnly(target):
		return "account"
	default:
		return ""
	}
}

func digitsOnly(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func setControlMissing(props map[string]any, kind, evidence string) {
	props[kind+"_status"] = "missing"
	props[kind+"_evidence"] = evidence
	props[kind+"_coverage"] = "NOT_COLLECTED"
	delete(props, kind+"_documents")
	delete(props, kind+"_attachments")
	delete(props, kind+"_hierarchy_complete")
}

func setControlAbsent(props map[string]any, kind, evidence string) {
	props[kind+"_status"] = "confirmed_absent"
	props[kind+"_evidence"] = evidence
	props[kind+"_coverage"] = "NOT_APPLICABLE"
	delete(props, kind+"_documents")
	delete(props, kind+"_attachments")
	delete(props, kind+"_hierarchy_complete")
}

func orgDenied(err error) bool {
	var api smithy.APIError
	if errors.As(err, &api) {
		code := api.ErrorCode()
		return code == "AccessDeniedException" || code == "AccessDenied"
	}
	return false
}

func orgNotInUse(err error) bool {
	var api smithy.APIError
	if errors.As(err, &api) {
		return api.ErrorCode() == "AWSOrganizationsNotInUseException"
	}
	var typed *orgtypes.AWSOrganizationsNotInUseException
	return errors.As(err, &typed)
}
