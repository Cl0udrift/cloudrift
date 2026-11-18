package collectors

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/identitystore"
	idstypes "github.com/aws/aws-sdk-go-v2/service/identitystore/types"
	"github.com/aws/aws-sdk-go-v2/service/ssoadmin"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/ssoadmin/types"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// IAM Identity Center is read from the organization management account or the delegated administrator. Every call is a read.
// The instance lives in one home Region, so each Region is asked; a Region without an instance answers with an empty list.

type SSOAdminAPI interface {
	ListInstances(context.Context, *ssoadmin.ListInstancesInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListInstancesOutput, error)
	ListPermissionSets(context.Context, *ssoadmin.ListPermissionSetsInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListPermissionSetsOutput, error)
	DescribePermissionSet(context.Context, *ssoadmin.DescribePermissionSetInput, ...func(*ssoadmin.Options)) (*ssoadmin.DescribePermissionSetOutput, error)
	ListManagedPoliciesInPermissionSet(context.Context, *ssoadmin.ListManagedPoliciesInPermissionSetInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListManagedPoliciesInPermissionSetOutput, error)
	ListCustomerManagedPolicyReferencesInPermissionSet(context.Context, *ssoadmin.ListCustomerManagedPolicyReferencesInPermissionSetInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListCustomerManagedPolicyReferencesInPermissionSetOutput, error)
	GetInlinePolicyForPermissionSet(context.Context, *ssoadmin.GetInlinePolicyForPermissionSetInput, ...func(*ssoadmin.Options)) (*ssoadmin.GetInlinePolicyForPermissionSetOutput, error)
	ListAccountsForProvisionedPermissionSet(context.Context, *ssoadmin.ListAccountsForProvisionedPermissionSetInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountsForProvisionedPermissionSetOutput, error)
	ListAccountAssignments(context.Context, *ssoadmin.ListAccountAssignmentsInput, ...func(*ssoadmin.Options)) (*ssoadmin.ListAccountAssignmentsOutput, error)
}

type IdentityStoreAPI interface {
	DescribeUser(context.Context, *identitystore.DescribeUserInput, ...func(*identitystore.Options)) (*identitystore.DescribeUserOutput, error)
	DescribeGroup(context.Context, *identitystore.DescribeGroupInput, ...func(*identitystore.Options)) (*identitystore.DescribeGroupOutput, error)
	ListGroupMemberships(context.Context, *identitystore.ListGroupMembershipsInput, ...func(*identitystore.Options)) (*identitystore.ListGroupMembershipsOutput, error)
}

// IdentityCenterClients are the clients for one Region. Tests supply fakes.
type IdentityCenterClients struct {
	SSO   SSOAdminAPI
	Store IdentityStoreAPI
}

// Caps keep a large directory from running away: assignments are read per permission set and account, and group members per group.
const (
	maxPermissionSets  = 500
	maxGroupMembers    = 5000
	maxPrincipalLookup = 5000
)

// IdentityCenterPrincipalARN names a user or group of an Identity Store.
func IdentityCenterPrincipalARN(storeID, kind, id string) string {
	return "arn:aws:identitystore:::" + storeID + "/" + kind + "/" + id
}

// CollectIdentityCenterRegion reads every instance in one Region. found is false when the Region has no instance, so the
// caller can tell "no instance here" from a failure. A partial read keeps what it has and returns the reason.
func CollectIdentityCenterRegion(ctx context.Context, region string, c IdentityCenterClients, at time.Time) (assets []models.AssetNode, rels []models.Relationship, found bool, err error) {
	instances, err := c.SSO.ListInstances(ctx, &ssoadmin.ListInstancesInput{})
	if err != nil {
		return nil, nil, false, err
	}
	for _, inst := range instances.Instances {
		found = true
		a, r, ierr := collectInstance(ctx, region, c, inst, at)
		assets, rels = append(assets, a...), append(rels, r...)
		if ierr != nil {
			err = ierr
		}
	}
	return assets, rels, found, err
}

func collectInstance(ctx context.Context, region string, c IdentityCenterClients, inst ssotypes.InstanceMetadata, at time.Time) ([]models.AssetNode, []models.Relationship, error) {
	instanceARN, storeID, owner := awsv2.ToString(inst.InstanceArn), awsv2.ToString(inst.IdentityStoreId), awsv2.ToString(inst.OwnerAccountId)
	collected := at.UTC().Format(time.RFC3339)
	assets := []models.AssetNode{{
		ARN: instanceARN, AssetType: models.AssetIdentityCenterInstance, Name: firstNonEmptyStr(awsv2.ToString(inst.Name), storeID), AccountID: owner, Region: region,
		Properties: map[string]any{"identity_store_id": storeID, "owner_account_id": owner, "status": string(inst.Status), "collected_at": collected, "source_api": "sso:ListInstances"},
	}}
	var rels []models.Relationship
	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	var psARNs []string
	var token *string
	for {
		out, err := c.SSO.ListPermissionSets(ctx, &ssoadmin.ListPermissionSetsInput{InstanceArn: inst.InstanceArn, NextToken: token})
		if err != nil {
			return assets, rels, err
		}
		psARNs = append(psARNs, out.PermissionSets...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	if len(psARNs) > maxPermissionSets {
		psARNs = psARNs[:maxPermissionSets]
		note(errTruncated)
	}

	principals := map[string]string{} // principal key -> "USER" or "GROUP"
	for _, psARN := range psARNs {
		ps, accounts, assigns, err := readPermissionSet(ctx, c.SSO, inst.InstanceArn, psARN)
		note(err)
		if ps == nil {
			continue
		}
		node := models.AssetNode{
			ARN: psARN, AssetType: models.AssetIdentityCenterPermissionSet, Name: awsv2.ToString(ps.set.Name), AccountID: owner, Region: region,
			Properties: map[string]any{
				"instance_arn": instanceARN, "description": awsv2.ToString(ps.set.Description), "session_duration": awsv2.ToString(ps.set.SessionDuration),
				"managed_policies": ps.managed, "customer_managed_policies": ps.customer, "inline_policy_document": ps.inline,
				"accounts": accounts, "collected_at": collected, "source_api": "sso:DescribePermissionSet",
			},
		}
		if ps.err != "" {
			node.Properties["read_status"] = "partial"
			node.Properties["read_error"] = ps.err
		} else {
			node.Properties["read_status"] = "ok"
		}
		assets = append(assets, node)
		for _, a := range assigns {
			key := string(a.PrincipalType) + "|" + awsv2.ToString(a.PrincipalId)
			principals[key] = string(a.PrincipalType)
			kind := strings.ToLower(string(a.PrincipalType))
			rels = append(rels, models.Relationship{
				SourceARN: IdentityCenterPrincipalARN(storeID, kind, awsv2.ToString(a.PrincipalId)), TargetARN: psARN, RelType: models.RelIdentityCenterAssigned,
				Properties: map[string]any{"account_id": awsv2.ToString(a.AccountId), "principal_type": string(a.PrincipalType), "source_api": "sso:ListAccountAssignments", "collected_at": collected},
			})
		}
	}

	// Look up each assigned user and group once, and the members of each assigned group.
	keys := make([]string, 0, len(principals))
	for k := range principals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > maxPrincipalLookup {
		keys = keys[:maxPrincipalLookup]
		note(errTruncated)
	}
	var mu sync.Mutex
	groupIDs := []string{}
	userSeen := map[string]bool{}
	addUser := func(id, name, display string) {
		mu.Lock()
		defer mu.Unlock()
		if userSeen[id] {
			return
		}
		userSeen[id] = true
		assets = append(assets, models.AssetNode{
			ARN: IdentityCenterPrincipalARN(storeID, "user", id), AssetType: models.AssetIdentityCenterUser, Name: firstNonEmptyStr(name, id), AccountID: owner, Region: region,
			Properties: map[string]any{"identity_store_id": storeID, "user_id": id, "user_name": name, "display_name": display, "collected_at": collected, "source_api": "identitystore:DescribeUser"},
		})
	}
	for _, k := range keys {
		typ, id, _ := strings.Cut(k, "|")
		switch typ {
		case "USER":
			u, err := c.Store.DescribeUser(ctx, &identitystore.DescribeUserInput{IdentityStoreId: awsv2.String(storeID), UserId: awsv2.String(id)})
			if err != nil {
				note(err)
				addUser(id, "", "") // keep the user: it is assigned, even if its name could not be read
				continue
			}
			addUser(id, awsv2.ToString(u.UserName), awsv2.ToString(u.DisplayName))
		case "GROUP":
			g, err := c.Store.DescribeGroup(ctx, &identitystore.DescribeGroupInput{IdentityStoreId: awsv2.String(storeID), GroupId: awsv2.String(id)})
			name := id
			if err != nil {
				note(err)
			} else {
				name = firstNonEmptyStr(awsv2.ToString(g.DisplayName), id)
			}
			assets = append(assets, models.AssetNode{
				ARN: IdentityCenterPrincipalARN(storeID, "group", id), AssetType: models.AssetIdentityCenterGroup, Name: name, AccountID: owner, Region: region,
				Properties: map[string]any{"identity_store_id": storeID, "group_id": id, "collected_at": collected, "source_api": "identitystore:DescribeGroup"},
			})
			groupIDs = append(groupIDs, id)
		}
	}
	for _, gid := range groupIDs {
		members := 0
		var mtoken *string
		for {
			out, err := c.Store.ListGroupMemberships(ctx, &identitystore.ListGroupMembershipsInput{IdentityStoreId: awsv2.String(storeID), GroupId: awsv2.String(gid), NextToken: mtoken})
			if err != nil {
				note(err)
				break
			}
			for _, m := range out.GroupMemberships {
				uid, ok := m.MemberId.(*idstypes.MemberIdMemberUserId)
				if !ok {
					continue
				}
				if members++; members > maxGroupMembers {
					note(errTruncated)
					break
				}
				if !userSeen[uid.Value] {
					addUser(uid.Value, "", "") // a member who holds access only through the group; the name is not read
				}
				rels = append(rels, models.Relationship{
					SourceARN: IdentityCenterPrincipalARN(storeID, "user", uid.Value), TargetARN: IdentityCenterPrincipalARN(storeID, "group", gid), RelType: models.RelIdentityCenterMember,
					Properties: map[string]any{"source_api": "identitystore:ListGroupMemberships", "collected_at": collected},
				})
			}
			if members > maxGroupMembers || out.NextToken == nil || *out.NextToken == "" {
				break
			}
			mtoken = out.NextToken
		}
	}
	return assets, rels, firstErr
}

type permissionSetRead struct {
	set      *ssotypes.PermissionSet
	managed  []map[string]string
	customer []map[string]string
	inline   string
	err      string
}

func readPermissionSet(ctx context.Context, api SSOAdminAPI, instance *string, psARN string) (*permissionSetRead, []string, []ssotypes.AccountAssignment, error) {
	d, err := api.DescribePermissionSet(ctx, &ssoadmin.DescribePermissionSetInput{InstanceArn: instance, PermissionSetArn: awsv2.String(psARN)})
	if err != nil || d.PermissionSet == nil {
		return nil, nil, nil, err
	}
	ps := &permissionSetRead{set: d.PermissionSet, managed: []map[string]string{}, customer: []map[string]string{}}
	var firstErr error
	fail := func(err error) {
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			if ps.err == "" {
				ps.err = err.Error()
			}
		}
	}
	var token *string
	for {
		out, err := api.ListManagedPoliciesInPermissionSet(ctx, &ssoadmin.ListManagedPoliciesInPermissionSetInput{InstanceArn: instance, PermissionSetArn: awsv2.String(psARN), NextToken: token})
		if err != nil {
			fail(err)
			break
		}
		for _, m := range out.AttachedManagedPolicies {
			ps.managed = append(ps.managed, map[string]string{"arn": awsv2.ToString(m.Arn), "name": awsv2.ToString(m.Name)})
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	cm, err := api.ListCustomerManagedPolicyReferencesInPermissionSet(ctx, &ssoadmin.ListCustomerManagedPolicyReferencesInPermissionSetInput{InstanceArn: instance, PermissionSetArn: awsv2.String(psARN)})
	fail(err)
	if err == nil {
		for _, m := range cm.CustomerManagedPolicyReferences {
			ps.customer = append(ps.customer, map[string]string{"name": awsv2.ToString(m.Name), "path": awsv2.ToString(m.Path)})
		}
	}
	in, err := api.GetInlinePolicyForPermissionSet(ctx, &ssoadmin.GetInlinePolicyForPermissionSetInput{InstanceArn: instance, PermissionSetArn: awsv2.String(psARN)})
	fail(err)
	if err == nil {
		ps.inline = awsv2.ToString(in.InlinePolicy)
	}

	var accounts []string
	token = nil
	for {
		out, err := api.ListAccountsForProvisionedPermissionSet(ctx, &ssoadmin.ListAccountsForProvisionedPermissionSetInput{InstanceArn: instance, PermissionSetArn: awsv2.String(psARN), NextToken: token})
		if err != nil {
			fail(err)
			break
		}
		accounts = append(accounts, out.AccountIds...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	var assigns []ssotypes.AccountAssignment
	for _, acct := range accounts {
		token = nil
		for {
			out, err := api.ListAccountAssignments(ctx, &ssoadmin.ListAccountAssignmentsInput{InstanceArn: instance, PermissionSetArn: awsv2.String(psARN), AccountId: awsv2.String(acct), NextToken: token})
			if err != nil {
				fail(err)
				break
			}
			assigns = append(assigns, out.AccountAssignments...)
			if out.NextToken == nil || *out.NextToken == "" {
				break
			}
			token = out.NextToken
		}
	}
	return ps, accounts, assigns, firstErr
}

func firstNonEmptyStr(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

// identityCenterRegions are the commercial Regions an Identity Center instance can live in, including the opt-in ones. A Region the
// account has not opted in to answers with an error that is classified as unsupported, so asking is safe. The China and GovCloud
// partitions are not covered: a scan there records "no instance", and the page says that does not prove nobody can sign in.
var identityCenterRegions = []string{
	"us-east-1", "us-east-2", "us-west-1", "us-west-2", "ca-central-1", "ca-west-1", "sa-east-1", "mx-central-1",
	"eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-central-2", "eu-north-1", "eu-south-1", "eu-south-2",
	"ap-south-1", "ap-south-2", "ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-southeast-4", "ap-southeast-5", "ap-southeast-7",
	"ap-northeast-1", "ap-northeast-2", "ap-northeast-3", "ap-east-1",
	"me-south-1", "me-central-1", "il-central-1", "af-south-1",
}

// identityCenterClients is replaced in tests.
var identityCenterClients = func(cfg awsv2.Config) IdentityCenterClients {
	return IdentityCenterClients{SSO: ssoadmin.NewFromConfig(cfg), Store: identitystore.NewFromConfig(cfg)}
}

// CollectIdentityCenter asks each Region for an Identity Center instance and reads it. It returns one collection record that
// says what happened: collected, no instance found (which also happens when the credential is not the management account or the
// delegated administrator), or failed with the reason. "No instance" is never reported as "no access".
func CollectIdentityCenter(ctx context.Context, baseCfg awsv2.Config, now time.Time) ([]models.AssetNode, []models.Relationship) {
	type result struct {
		region string
		assets []models.AssetNode
		rels   []models.Relationship
		found  bool
		err    error
	}
	results := make([]result, len(identityCenterRegions))
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for i, region := range identityCenterRegions {
		wg.Add(1)
		go func(i int, region string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			cfg := baseCfg.Copy()
			cfg.Region = region
			a, r, found, err := CollectIdentityCenterRegion(ctx, region, identityCenterClients(cfg), now)
			results[i] = result{region, a, r, found, err}
		}(i, region)
	}
	wg.Wait()
	var assets []models.AssetNode
	var rels []models.Relationship
	instances, denied, unsupported := 0, 0, 0
	var problem, firstDetail string
	for _, res := range results {
		assets, rels = append(assets, res.assets...), append(rels, res.rels...)
		if res.found {
			instances++
		}
		if res.err == nil {
			continue
		}
		status, detail := serviceStatus(res.err)
		switch {
		case res.found:
			problem = detail // an instance was found here and not all of it could be read
		case status == "failed" && strings.HasPrefix(detail, "access_denied"):
			denied++
			firstDetail = detail
		case status == "unsupported":
			unsupported++ // a Region the account has not opted in to
		}
	}
	status, detail := "succeeded", ""
	switch {
	case instances > 0 && problem != "":
		status, detail = "partial", "an instance was found and part of it could not be read: "+problem
	case instances > 0:
		detail = "instances found: " + strconv.Itoa(instances)
	case denied+unsupported == len(identityCenterRegions) && denied > 0:
		status, detail = "failed", firstDetail+". The credential needs the sso and identitystore read actions and must be the organization management account or the delegated administrator."
	default:
		detail = "no IAM Identity Center instance was found. Identity Center is visible only from the organization management account or the delegated administrator."
	}
	return append(assets, CollectionStatus("", "", "identity_center", "account", status, detail)), rels
}
