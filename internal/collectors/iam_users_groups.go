package collectors

import (
	"context"
	"sort"
	"strings"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// IAMAuthDetailsAPI is the one call that returns every user and group with its inline
// policies, attached managed policy ARNs, group membership and permissions boundary.
// It is a separate interface so clients that only list roles keep working.
type IAMAuthDetailsAPI interface {
	GetAccountAuthorizationDetails(ctx context.Context, params *iam.GetAccountAuthorizationDetailsInput, optFns ...func(*iam.Options)) (*iam.GetAccountAuthorizationDetailsOutput, error)
}

// collectUsersGroups returns user and group assets, their policy evidence, and the
// MEMBER_OF edges. A failure is returned to the caller, which records it as a collection
// status instead of failing the account scan.
func collectUsersGroups(ctx context.Context, accountID string, details IAMAuthDetailsAPI, client IAMAPI, cache *managedPolicyCache) ([]models.AssetNode, []models.Relationship, error) {
	var users []iamtypes.UserDetail
	var groups []iamtypes.GroupDetail
	var marker *string
	for {
		out, err := details.GetAccountAuthorizationDetails(ctx, &iam.GetAccountAuthorizationDetailsInput{
			Filter: []iamtypes.EntityType{iamtypes.EntityTypeUser, iamtypes.EntityTypeGroup},
			Marker: marker,
		})
		if err != nil {
			return nil, nil, err
		}
		users = append(users, out.UserDetailList...)
		groups = append(groups, out.GroupDetailList...)
		if !out.IsTruncated || out.Marker == nil {
			break
		}
		marker = out.Marker
	}

	groupARNByName := map[string]string{}
	for _, g := range groups {
		groupARNByName[awsv2.ToString(g.GroupName)] = awsv2.ToString(g.Arn)
	}

	var nodes []models.AssetNode
	var rels []models.Relationship
	add := func(node models.AssetNode, inline []iamtypes.PolicyDetail, attached []iamtypes.AttachedPolicy) {
		bundle := principalPolicyBundle(ctx, client, node, inline, attached, cache)
		node.Properties["attached_policy_names"] = bundle.AttachedNames
		node.Properties["attached_policy_arns"] = bundle.AttachedARNs
		node.Properties["inline_policy_documents"] = bundle.InlineDocs
		node.Properties["policy_parse_ok"] = bundle.ParseOK
		node.Properties["policy_retrieval_status"] = bundle.RetrievalStatus
		policyNodes, policyRels := policyEvidenceGraph(node, bundle.Policies)
		nodes = append(nodes, node)
		nodes = append(nodes, policyNodes...)
		rels = append(rels, policyRels...)
	}

	for _, g := range groups {
		node := models.AssetNode{
			ARN: awsv2.ToString(g.Arn), AssetType: models.AssetIAMGroup, Name: awsv2.ToString(g.GroupName),
			AccountID: accountID, Region: "global",
			Properties: map[string]any{"path": awsv2.ToString(g.Path), "group_id": awsv2.ToString(g.GroupId)},
		}
		add(node, g.GroupPolicyList, g.AttachedManagedPolicies)
	}
	for _, u := range users {
		node := models.AssetNode{
			ARN: awsv2.ToString(u.Arn), AssetType: models.AssetIAMUser, Name: awsv2.ToString(u.UserName),
			AccountID: accountID, Region: "global",
			Properties: map[string]any{"path": awsv2.ToString(u.Path), "user_id": awsv2.ToString(u.UserId)},
		}
		if u.CreateDate != nil {
			node.Properties["create_date"] = u.CreateDate.UTC().Format(time.RFC3339)
		}
		observeUserBoundary(&node, u)
		retrieveBoundaryDocument(ctx, client, &node, cache)

		sort.Strings(u.GroupList)
		var groupARNs []string
		for _, name := range u.GroupList {
			arn, ok := groupARNByName[name]
			if !ok {
				// A group named on the user but absent from the listing means that group's
				// policies are unknown, so the user's effective access cannot be complete.
				node.Properties["group_membership_complete"] = false
				continue
			}
			groupARNs = append(groupARNs, arn)
			rels = append(rels, models.Relationship{
				SourceARN: node.ARN, TargetARN: arn, RelType: models.RelMemberOf,
				Properties: map[string]any{"scan_scope": "identity_policy"},
			})
		}
		node.Properties["group_names"] = u.GroupList
		node.Properties["group_arns"] = groupARNs
		add(node, u.UserPolicyList, u.AttachedManagedPolicies)
	}
	return nodes, rels, nil
}

func observeUserBoundary(node *models.AssetNode, u iamtypes.UserDetail) {
	if u.PermissionsBoundary != nil {
		if arn := strings.TrimSpace(awsv2.ToString(u.PermissionsBoundary.PermissionsBoundaryArn)); arn != "" {
			node.Properties["permissions_boundary_arn"] = arn
			node.Properties["permissions_boundary_status"] = "present"
			node.Properties["permissions_boundary_evidence"] = "iam:GetAccountAuthorizationDetails returned a permissions boundary ARN; the boundary policy document was not retrieved"
			return
		}
	}
	node.Properties["permissions_boundary_status"] = "confirmed_absent"
	node.Properties["permissions_boundary_evidence"] = "iam:GetAccountAuthorizationDetails returned this user with no permissions boundary"
}

// principalPolicyBundle builds the same bundle as collectRolePolicyEvidence from inline
// documents already returned by GetAccountAuthorizationDetails. Managed documents still
// come through the shared, version-verified cache.
func principalPolicyBundle(ctx context.Context, client IAMAPI, node models.AssetNode, inline []iamtypes.PolicyDetail, attached []iamtypes.AttachedPolicy, cache *managedPolicyCache) rolePolicyBundle {
	bundle := rolePolicyBundle{ParseOK: true, RetrievalStatus: models.PolicyRetrievalOK}
	for _, ap := range attached {
		name := strings.TrimSpace(awsv2.ToString(ap.PolicyName))
		arn := strings.TrimSpace(awsv2.ToString(ap.PolicyArn))
		if name != "" {
			bundle.AttachedNames = append(bundle.AttachedNames, name)
		}
		if arn == "" {
			bundle.mark(models.PolicyRetrievalMissing)
			bundle.Policies = append(bundle.Policies, collectedPolicy{
				Name: name, PolicyType: models.PolicyTypeManaged, RetrievalStatus: models.PolicyRetrievalMissing,
				RoleARN: node.ARN, AccountID: node.AccountID,
			})
			continue
		}
		bundle.AttachedARNs = append(bundle.AttachedARNs, arn)
		fetched := cache.get(ctx, client, arn, name, node.AccountID)
		fetched.RoleARN = node.ARN
		if fetched.RetrievalStatus != models.PolicyRetrievalOK {
			bundle.mark(fetched.RetrievalStatus)
		}
		bundle.Policies = append(bundle.Policies, fetched)
	}
	for _, p := range inline {
		policy := collectedPolicy{
			Name: awsv2.ToString(p.PolicyName), PolicyType: models.PolicyTypeInline,
			RoleARN: node.ARN, AccountID: node.AccountID,
			Document: decodeIAMDocument(awsv2.ToString(p.PolicyDocument)),
		}
		if _, err := models.NormalizeIdentityPolicy(inlinePolicyARNFor(node, policy.Name), models.PolicyTypeInline, node.AccountID, policy.Document); err != nil {
			policy.RetrievalStatus = models.PolicyRetrievalMalformed
			bundle.mark(models.PolicyRetrievalMalformed)
		} else {
			policy.RetrievalStatus = models.PolicyRetrievalOK
			bundle.InlineDocs = append(bundle.InlineDocs, policy.Document)
		}
		bundle.Policies = append(bundle.Policies, policy)
	}
	sort.Strings(bundle.AttachedNames)
	sort.Strings(bundle.AttachedARNs)
	sort.Strings(bundle.InlineDocs)
	return bundle
}
