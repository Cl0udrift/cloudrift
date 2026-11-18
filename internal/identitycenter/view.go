// Package identitycenter builds the IAM Identity Center view from the assets and relationships a scan stored.
package identitycenter

import (
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/blastradius"
	"github.com/Zero0x00/cloudrift/internal/models"
)

const settingKey = "scan.identity_center"

// Build reads the stored scan. The state comes from the collection record: a scan that never ran the collector is not_collected,
// never "no instance".
func Build(scanID string, assets []models.AssetNode, rels []models.Relationship) schema.IdentityCenterResponse {
	out := schema.IdentityCenterResponse{
		ScanID: scanID, Instances: []schema.IdentityCenterInstance{}, PermissionSets: []schema.IdentityCenterPermissionSet{},
		Principals: []schema.IdentityCenterPrincipal{}, Accounts: []schema.IdentityCenterAccount{}, Notes: []string{},
	}
	status, detail, recorded := collectionRecord(assets)
	switch {
	case !recorded:
		out.State, out.ConfigKey = "not_collected", settingKey
		out.Detail = "IAM Identity Center was not collected in this scan. It is opt-in: turn it on in Settings and scan again."
		return out
	case status == "failed":
		out.State, out.Detail = "failed", detail
		return out
	}
	out.State, out.Detail = status, detail
	byARN := map[string]models.AssetNode{}
	for _, a := range assets {
		byARN[a.ARN] = a
	}

	sets := map[string]*schema.IdentityCenterPermissionSet{}
	for _, a := range assets {
		switch a.AssetType {
		case models.AssetIdentityCenterInstance:
			out.Instances = append(out.Instances, schema.IdentityCenterInstance{ARN: a.ARN, Name: a.Name, IdentityStoreID: str(a, "identity_store_id"), OwnerAccountID: str(a, "owner_account_id"), Status: str(a, "status")})
		case models.AssetIdentityCenterPermissionSet:
			ps := permissionSet(a, assets)
			sets[a.ARN] = &ps
		}
	}
	if len(out.Instances) == 0 && status == "succeeded" {
		out.State = "no_instance"
	}

	// principal -> its own assignments; group -> member users
	type pair struct{ account, ps string }
	direct := map[string][]pair{}
	groupsOf := map[string][]string{}
	members := map[string]int{}
	for _, r := range rels {
		switch r.RelType {
		case models.RelIdentityCenterAssigned:
			acct, _ := r.Properties["account_id"].(string)
			direct[r.SourceARN] = append(direct[r.SourceARN], pair{acct, r.TargetARN})
			if ps := sets[r.TargetARN]; ps != nil {
				ps.Assignments++
			}
		case models.RelIdentityCenterMember:
			groupsOf[r.SourceARN] = append(groupsOf[r.SourceARN], r.TargetARN)
			members[r.TargetARN]++
		}
	}
	nameOf := func(arn string) string {
		if a, ok := byARN[arn]; ok {
			return a.Name
		}
		return arn
	}
	assignment := func(p pair, via string) schema.IdentityCenterAssignment {
		ps := sets[p.ps]
		a := schema.IdentityCenterAssignment{AccountID: p.account, PermissionSetARN: p.ps, PermissionSet: nameOf(p.ps), Via: via}
		if ps != nil {
			a.Administrative = ps.Administrative
		}
		return a
	}
	perAccount := map[string]*schema.IdentityCenterAccount{}
	accountPrincipals := map[string]map[string]bool{}
	accountAdmins := map[string]map[string]bool{}
	touch := func(acct string) *schema.IdentityCenterAccount {
		if perAccount[acct] == nil {
			perAccount[acct] = &schema.IdentityCenterAccount{AccountID: acct}
			accountPrincipals[acct], accountAdmins[acct] = map[string]bool{}, map[string]bool{}
		}
		return perAccount[acct]
	}
	for _, a := range assets {
		if a.AssetType != models.AssetIdentityCenterUser && a.AssetType != models.AssetIdentityCenterGroup {
			continue
		}
		kind := "user"
		if a.AssetType == models.AssetIdentityCenterGroup {
			kind = "group"
		}
		p := schema.IdentityCenterPrincipal{ARN: a.ARN, Kind: kind, Name: a.Name, DisplayName: str(a, "display_name"), Groups: []string{}, Assignments: []schema.IdentityCenterAssignment{}, AdministrativeIn: []string{}}
		p.NameRead = kind == "group" && a.Name != "" && a.Name != str(a, "group_id") || kind == "user" && str(a, "user_name") != ""
		p.Members = members[a.ARN]
		for _, d := range direct[a.ARN] {
			p.Assignments = append(p.Assignments, assignment(d, "direct"))
		}
		if kind == "user" {
			for _, g := range groupsOf[a.ARN] {
				p.Groups = append(p.Groups, nameOf(g))
				for _, d := range direct[g] {
					p.Assignments = append(p.Assignments, assignment(d, "group: "+nameOf(g)))
				}
			}
			sort.Strings(p.Groups)
		}
		adm := map[string]bool{}
		for _, as := range p.Assignments {
			touch(as.AccountID)
			accountPrincipals[as.AccountID][a.ARN] = true
			if as.Administrative {
				adm[as.AccountID] = true
				accountAdmins[as.AccountID][a.ARN] = true
			}
		}
		for acct := range adm {
			p.AdministrativeIn = append(p.AdministrativeIn, acct)
		}
		sort.Strings(p.AdministrativeIn)
		sort.Slice(p.Assignments, func(i, j int) bool {
			if p.Assignments[i].AccountID != p.Assignments[j].AccountID {
				return p.Assignments[i].AccountID < p.Assignments[j].AccountID
			}
			return p.Assignments[i].PermissionSet < p.Assignments[j].PermissionSet
		})
		out.Principals = append(out.Principals, p)
	}
	for _, ps := range sets {
		for _, acct := range ps.Accounts {
			touch(acct).PermissionSets++
		}
		out.PermissionSets = append(out.PermissionSets, *ps)
	}
	for acct, a := range perAccount {
		a.Principals, a.AdministrativePrincipals = len(accountPrincipals[acct]), len(accountAdmins[acct])
		out.Accounts = append(out.Accounts, *a)
	}
	sort.Slice(out.PermissionSets, func(i, j int) bool {
		if out.PermissionSets[i].Administrative != out.PermissionSets[j].Administrative {
			return out.PermissionSets[i].Administrative
		}
		return out.PermissionSets[i].Name < out.PermissionSets[j].Name
	})
	sort.Slice(out.Principals, func(i, j int) bool {
		if len(out.Principals[i].AdministrativeIn) != len(out.Principals[j].AdministrativeIn) {
			return len(out.Principals[i].AdministrativeIn) > len(out.Principals[j].AdministrativeIn)
		}
		return out.Principals[i].Name < out.Principals[j].Name
	})
	sort.Slice(out.Accounts, func(i, j int) bool {
		if out.Accounts[i].AdministrativePrincipals != out.Accounts[j].AdministrativePrincipals {
			return out.Accounts[i].AdministrativePrincipals > out.Accounts[j].AdministrativePrincipals
		}
		return out.Accounts[i].AccountID < out.Accounts[j].AccountID
	})
	out.Notes = []string{
		"Administrative means the permission set grants every action on every resource: the AdministratorAccess managed policy, or an inline policy that allows * on *. Other broad policies (PowerUserAccess, customer managed policies whose documents were not read) are not marked administrative, so the count is a floor.",
		"A user's access includes what its groups are assigned. Nested group membership is not modeled because Identity Center does not nest groups.",
		"Permission boundaries on a permission set and the roles' own IAM policies are not combined here; this page shows who is assigned what, not what the resulting session can do.",
	}
	return out
}

func permissionSet(a models.AssetNode, assets []models.AssetNode) schema.IdentityCenterPermissionSet {
	ps := schema.IdentityCenterPermissionSet{
		ARN: a.ARN, Name: a.Name, Description: str(a, "description"), SessionDuration: str(a, "session_duration"),
		Managed: []schema.IdentityCenterPolicyRef{}, CustomerManaged: []schema.IdentityCenterPolicyRef{}, Accounts: []string{}, Roles: []string{},
		ReadStatus: str(a, "read_status"), ReadError: str(a, "read_error"),
	}
	for _, m := range refs(a.Properties["managed_policies"]) {
		ps.Managed = append(ps.Managed, schema.IdentityCenterPolicyRef{Name: m["name"], ARN: m["arn"]})
		if strings.HasSuffix(m["arn"], ":policy/AdministratorAccess") {
			ps.Administrative, ps.AdminReason = true, "the AWS managed AdministratorAccess policy is attached"
		}
	}
	for _, m := range refs(a.Properties["customer_managed_policies"]) {
		ps.CustomerManaged = append(ps.CustomerManaged, schema.IdentityCenterPolicyRef{Name: m["name"]})
	}
	if inline := str(a, "inline_policy_document"); strings.TrimSpace(inline) != "" {
		ps.HasInline = true
		if !ps.Administrative && blastradius.LooksAdministrative(inline) {
			ps.Administrative, ps.AdminReason = true, "an inline policy allows every action on every resource"
		}
	}
	for _, acct := range stringList(a.Properties["accounts"]) {
		ps.Accounts = append(ps.Accounts, acct)
	}
	sort.Strings(ps.Accounts)
	// The role Identity Center creates in each account is AWSReservedSSO_<permission set name>_<hash>, under the SSO role path.
	prefix := "AWSReservedSSO_" + a.Name + "_"
	for _, r := range assets {
		if r.AssetType == models.AssetIAMRole && strings.HasPrefix(r.Name, prefix) && strings.Contains(r.ARN, ":role/aws-reserved/sso.amazonaws.com/") && contains(ps.Accounts, r.AccountID) {
			ps.Roles = append(ps.Roles, r.ARN)
		}
	}
	sort.Strings(ps.Roles)
	return ps
}

// collectionRecord returns the identity_center collection status. recorded is false when the scan has none.
func collectionRecord(assets []models.AssetNode) (status, detail string, recorded bool) {
	for _, a := range assets {
		if a.AssetType == "collection_status" && a.Properties["collector"] == "identity_center" {
			s, _ := a.Properties["status"].(string)
			d, _ := a.Properties["detail"].(string)
			return s, d, true
		}
	}
	return "", "", false
}

func str(a models.AssetNode, key string) string {
	s, _ := a.Properties[key].(string)
	return s
}

func refs(v any) []map[string]string {
	var out []map[string]string
	switch t := v.(type) {
	case []map[string]string:
		return t
	case []any:
		for _, e := range t {
			m, _ := e.(map[string]any)
			row := map[string]string{}
			for k, val := range m {
				row[k], _ = val.(string)
			}
			out = append(out, row)
		}
	}
	return out
}

func stringList(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		var out []string
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
