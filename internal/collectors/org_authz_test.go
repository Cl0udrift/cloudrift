package collectors

import (
	"context"
	"errors"
	"testing"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/smithy-go"

	"github.com/Zero0x00/cloudrift/internal/models"
)

type orgAPIError struct{ code, message string }

func (e orgAPIError) Error() string                 { return e.message }
func (e orgAPIError) ErrorCode() string             { return e.code }
func (e orgAPIError) ErrorMessage() string          { return e.message }
func (e orgAPIError) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

type fakeOrgAuth struct {
	describeErr error
	master      string
	roots       []orgtypes.Root
	parents     map[string]orgtypes.Parent
	policies    map[string][]orgtypes.PolicySummary
	pages       map[string][]orgtypes.PolicySummary
	docs        map[string]string
	describes   int
	parentErr   map[string]error
	feature     orgtypes.OrganizationFeatureSet
}

func (f *fakeOrgAuth) DescribeOrganization(context.Context, *organizations.DescribeOrganizationInput, ...func(*organizations.Options)) (*organizations.DescribeOrganizationOutput, error) {
	if f.describeErr != nil {
		return nil, f.describeErr
	}
	return &organizations.DescribeOrganizationOutput{Organization: &orgtypes.Organization{
		Id: awsv2.String("o-1"), MasterAccountId: awsv2.String(f.master), FeatureSet: f.feature,
	}}, nil
}

func (f *fakeOrgAuth) ListRoots(context.Context, *organizations.ListRootsInput, ...func(*organizations.Options)) (*organizations.ListRootsOutput, error) {
	return &organizations.ListRootsOutput{Roots: f.roots}, nil
}

func (f *fakeOrgAuth) ListParents(_ context.Context, in *organizations.ListParentsInput, _ ...func(*organizations.Options)) (*organizations.ListParentsOutput, error) {
	id := awsv2.ToString(in.ChildId)
	if err := f.parentErr[id]; err != nil {
		return nil, err
	}
	parent, ok := f.parents[id]
	if !ok {
		return &organizations.ListParentsOutput{}, nil
	}
	return &organizations.ListParentsOutput{Parents: []orgtypes.Parent{parent}}, nil
}

func (f *fakeOrgAuth) ListPoliciesForTarget(_ context.Context, in *organizations.ListPoliciesForTargetInput, _ ...func(*organizations.Options)) (*organizations.ListPoliciesForTargetOutput, error) {
	key := awsv2.ToString(in.TargetId) + "|" + string(in.Filter)
	if awsv2.ToString(in.NextToken) == "" {
		if page, ok := f.pages[key]; ok && len(page) > 1 {
			return &organizations.ListPoliciesForTargetOutput{
				Policies: page[:1], NextToken: awsv2.String("more"),
			}, nil
		}
	}
	if page, ok := f.pages[key]; ok {
		return &organizations.ListPoliciesForTargetOutput{Policies: page[1:]}, nil
	}
	return &organizations.ListPoliciesForTargetOutput{Policies: f.policies[key]}, nil
}

func (f *fakeOrgAuth) DescribePolicy(_ context.Context, in *organizations.DescribePolicyInput, _ ...func(*organizations.Options)) (*organizations.DescribePolicyOutput, error) {
	f.describes++
	id := awsv2.ToString(in.PolicyId)
	doc, ok := f.docs[id]
	if !ok {
		return nil, errors.New("missing policy")
	}
	return &organizations.DescribePolicyOutput{Policy: &orgtypes.Policy{
		Content:       awsv2.String(doc),
		PolicySummary: &orgtypes.PolicySummary{Id: awsv2.String(id), Name: awsv2.String(id)},
	}}, nil
}

func scpDoc(effect, action string) string {
	return `{"Version":"2012-10-17","Statement":{"Effect":"` + effect + `","Action":"` + action + `","Resource":"*"}}`
}

func enabledRoot(scp, rcp bool) orgtypes.Root {
	types := []orgtypes.PolicyTypeSummary{}
	if scp {
		types = append(types, orgtypes.PolicyTypeSummary{Type: orgtypes.PolicyTypeServiceControlPolicy, Status: orgtypes.PolicyTypeStatusEnabled})
	}
	if rcp {
		types = append(types, orgtypes.PolicyTypeSummary{Type: orgtypes.PolicyTypeResourceControlPolicy, Status: orgtypes.PolicyTypeStatusEnabled})
	}
	return orgtypes.Root{Id: awsv2.String("r-root"), PolicyTypes: types}
}

func chainParents(account, ou string) map[string]orgtypes.Parent {
	return map[string]orgtypes.Parent{
		account: {Id: awsv2.String(ou), Type: orgtypes.ParentTypeOrganizationalUnit},
		ou:      {Id: awsv2.String("r-root"), Type: orgtypes.ParentTypeRoot},
	}
}

func TestOrgAuthorization_AccessDeniedIsNotAbsence(t *testing.T) {
	ev := CollectOrgAuthorization(context.Background(), &fakeOrgAuth{describeErr: orgAPIError{code: "AccessDeniedException", message: "denied"}}, []string{"111111111111"})
	if ev.Discovery != "access_denied" {
		t.Fatal(ev.Discovery)
	}
	role := models.AssetNode{ARN: "arn:aws:iam::111111111111:role/A", AssetType: models.AssetIAMRole, AccountID: "111111111111", Properties: map[string]any{"path": "/"}}
	ApplyOrgEvidence([]models.AssetNode{role}, ev)
	if role.Properties["scp_status"] != "missing" || role.Properties["rcp_status"] != "missing" {
		t.Fatalf("%v", role.Properties)
	}
}

func TestOrgAuthorization_StandaloneAccount(t *testing.T) {
	ev := CollectOrgAuthorization(context.Background(), &fakeOrgAuth{describeErr: orgAPIError{code: "AWSOrganizationsNotInUseException", message: "none"}}, []string{"111111111111"})
	nodes := []models.AssetNode{{ARN: "arn:aws:iam::111111111111:role/A", AssetType: models.AssetIAMRole, AccountID: "111111111111"}}
	ApplyOrgEvidence(nodes, ev)
	role := nodes[0]
	if role.Properties["scp_status"] != "confirmed_absent" || role.Properties["scp_coverage"] != "NOT_APPLICABLE" {
		t.Fatalf("%v", role.Properties)
	}
}

func TestOrgAuthorization_HierarchyAndSharedPolicy(t *testing.T) {
	deny := scpDoc("Deny", "s3:GetObject")
	allow := scpDoc("Allow", "*")
	api := &fakeOrgAuth{
		master:  "999999999999",
		roots:   []orgtypes.Root{enabledRoot(true, true)},
		parents: chainParents("111111111111", "ou-1"),
		policies: map[string][]orgtypes.PolicySummary{
			"111111111111|SERVICE_CONTROL_POLICY":  {{Id: awsv2.String("p-acct")}},
			"ou-1|SERVICE_CONTROL_POLICY":          {{Id: awsv2.String("p-ou")}},
			"r-root|SERVICE_CONTROL_POLICY":        {{Id: awsv2.String("p-root")}},
			"111111111111|RESOURCE_CONTROL_POLICY": {{Id: awsv2.String("p-rcp")}},
		},
		docs: map[string]string{"p-acct": deny, "p-ou": deny, "p-root": allow, "p-rcp": allow},
	}
	second := chainParents("222222222222", "ou-1")
	for k, v := range second {
		api.parents[k] = v
	}
	api.policies["222222222222|SERVICE_CONTROL_POLICY"] = []orgtypes.PolicySummary{{Id: awsv2.String("p-root")}}
	ev := CollectOrgAuthorization(context.Background(), api, []string{"111111111111", "222222222222"})
	acct := ev.Accounts["111111111111"]
	if !acct.HierarchyComplete || len(acct.SCPDocuments) != 3 || len(acct.RCPDocuments) != 1 {
		t.Fatalf("%+v", acct)
	}
	if api.describes != 4 {
		t.Fatalf("shared root policy was described %d times", api.describes)
	}
	role := models.AssetNode{ARN: "arn:aws:iam::111111111111:role/A", AssetType: models.AssetIAMRole, AccountID: "111111111111", Properties: map[string]any{"path": "/"}}
	ApplyOrgEvidence([]models.AssetNode{role}, ev)
	if role.Properties["scp_status"] != "present" || role.Properties["scp_coverage"] != "COMPLETE_FOR_SUPPORTED_SCOPE" {
		t.Fatalf("%v", role.Properties["scp_status"])
	}
	before := map[string]string{}
	for _, doc := range acct.SCPDocuments {
		before[doc.PolicyID] = doc.Document
	}
	api.docs["p-acct"] = scpDoc("Deny", "s3:*")
	again := CollectOrgAuthorization(context.Background(), api, []string{"111111111111"})
	var saw bool
	for _, doc := range again.Accounts["111111111111"].SCPDocuments {
		if doc.PolicyID == "p-acct" {
			saw = doc.Document != before["p-acct"]
		}
	}
	if !saw {
		t.Fatal("changed policy document was reused")
	}
}

func TestOrgAuthorization_IncompleteParentStaysMissing(t *testing.T) {
	api := &fakeOrgAuth{
		master: "999999999999", roots: []orgtypes.Root{enabledRoot(true, false)},
		parents:   chainParents("111111111111", "ou-1"),
		parentErr: map[string]error{"ou-1": orgAPIError{code: "AccessDeniedException", message: "no parent"}},
		policies: map[string][]orgtypes.PolicySummary{
			"111111111111|SERVICE_CONTROL_POLICY": {{Id: awsv2.String("p-acct")}},
		},
		docs: map[string]string{"p-acct": scpDoc("Allow", "*")},
	}
	ev := CollectOrgAuthorization(context.Background(), api, []string{"111111111111"})
	role := models.AssetNode{ARN: "arn:aws:iam::111111111111:role/A", AssetType: models.AssetIAMRole, AccountID: "111111111111", Properties: map[string]any{"path": "/"}}
	ApplyOrgEvidence([]models.AssetNode{role}, ev)
	if role.Properties["scp_status"] != "missing" {
		t.Fatalf("partial hierarchy evaluated: %v", role.Properties["scp_status"])
	}
	if _, ok := role.Properties["scp_documents"]; ok {
		t.Fatal("partial SCP documents were stored for evaluation")
	}
	if _, ok := role.Properties["scp_attachments"]; ok {
		t.Fatal("partial SCP attachments were stored for evaluation")
	}
}

func TestOrgAuthorization_DisabledTypeAndManagementAndSLR(t *testing.T) {
	api := &fakeOrgAuth{
		master: "111111111111", roots: []orgtypes.Root{enabledRoot(false, false)},
		parents: chainParents("222222222222", "ou-1"),
	}
	ev := CollectOrgAuthorization(context.Background(), api, []string{"111111111111", "222222222222"})
	member := models.AssetNode{ARN: "arn:aws:iam::222222222222:role/A", AssetType: models.AssetIAMRole, AccountID: "222222222222", Properties: map[string]any{"path": "/"}}
	mgmt := models.AssetNode{ARN: "arn:aws:iam::111111111111:role/M", AssetType: models.AssetIAMRole, AccountID: "111111111111", Properties: map[string]any{"path": "/"}}
	slr := models.AssetNode{ARN: "arn:aws:iam::222222222222:role/aws-service-role/s3.amazonaws.com/X", AssetType: models.AssetIAMRole, AccountID: "222222222222", Properties: map[string]any{"path": "/aws-service-role/s3.amazonaws.com/"}}
	ApplyOrgEvidence([]models.AssetNode{member, mgmt, slr}, ev)
	if member.Properties["scp_status"] != "confirmed_absent" || member.Properties["rcp_status"] != "confirmed_absent" {
		t.Fatalf("disabled types: %v %v", member.Properties["scp_status"], member.Properties["rcp_status"])
	}
	if mgmt.Properties["scp_status"] != "confirmed_absent" {
		t.Fatal(mgmt.Properties["scp_evidence"])
	}
	if slr.Properties["scp_status"] != "confirmed_absent" {
		t.Fatal(slr.Properties["scp_evidence"])
	}
}

func TestOrgAuthorization_Pagination(t *testing.T) {
	api := &fakeOrgAuth{
		master: "999999999999", roots: []orgtypes.Root{enabledRoot(true, false)},
		parents: chainParents("111111111111", "ou-1"),
		pages: map[string][]orgtypes.PolicySummary{
			"r-root|SERVICE_CONTROL_POLICY": {{Id: awsv2.String("p-a")}, {Id: awsv2.String("p-b")}},
		},
		docs: map[string]string{"p-a": scpDoc("Allow", "*"), "p-b": scpDoc("Allow", "s3:GetObject")},
	}
	ev := CollectOrgAuthorization(context.Background(), api, []string{"111111111111"})
	if len(ev.Accounts["111111111111"].SCPDocuments) != 2 {
		t.Fatalf("%d", len(ev.Accounts["111111111111"].SCPDocuments))
	}
}

func TestOrgAuthorization_AttachmentLevelsAndRepeatedPolicy(t *testing.T) {
	api := &fakeOrgAuth{
		master: "999999999999", roots: []orgtypes.Root{enabledRoot(true, false)},
		parents: chainParents("111111111111", "ou-1"),
		policies: map[string][]orgtypes.PolicySummary{
			"111111111111|SERVICE_CONTROL_POLICY": {{Id: awsv2.String("p-full")}},
			"ou-1|SERVICE_CONTROL_POLICY":         {{Id: awsv2.String("p-full")}, {Id: awsv2.String("p-s3")}},
			"r-root|SERVICE_CONTROL_POLICY":       {{Id: awsv2.String("p-full")}},
		},
		docs: map[string]string{"p-full": scpDoc("Allow", "*"), "p-s3": scpDoc("Allow", "s3:*")},
	}
	ev := CollectOrgAuthorization(context.Background(), api, []string{"111111111111"})
	docs := ev.Accounts["111111111111"].SCPDocuments
	if len(docs) != 4 || api.describes != 2 {
		t.Fatalf("attachments=%d describes=%d", len(docs), api.describes)
	}
	role := models.AssetNode{ARN: "arn:aws:iam::111111111111:role/A", AssetType: models.AssetIAMRole, AccountID: "111111111111", Properties: map[string]any{"path": "/"}}
	nodes := []models.AssetNode{role}
	ApplyOrgEvidence(nodes, ev)
	atts, _ := nodes[0].Properties["scp_attachments"].([]map[string]any)
	if len(atts) != 4 || nodes[0].Properties["scp_hierarchy_complete"] != true {
		t.Fatalf("%d complete=%v", len(atts), nodes[0].Properties["scp_hierarchy_complete"])
	}
	targets := map[string]int{}
	for _, att := range atts {
		if att["attachment_level"] == "" || att["retrieved_at"] == "" || att["policy_id"] == "" {
			t.Fatalf("attachment provenance %+v", att)
		}
		targets[att["attachment_target"].(string)]++
	}
	if targets["r-root"] != 1 || targets["ou-1"] != 2 || targets["111111111111"] != 1 {
		t.Fatalf("targets %+v", targets)
	}
}

func TestOrgAuthorization_ConsolidatedBillingHasNoPolicies(t *testing.T) {
	api := &fakeOrgAuth{
		master: "999999999999", feature: orgtypes.OrganizationFeatureSetConsolidatedBilling,
		roots: []orgtypes.Root{enabledRoot(true, true)},
	}
	ev := CollectOrgAuthorization(context.Background(), api, []string{"111111111111"})
	nodes := []models.AssetNode{{ARN: "arn:aws:iam::111111111111:role/A", AssetType: models.AssetIAMRole, AccountID: "111111111111", Properties: map[string]any{}}}
	ApplyOrgEvidence(nodes, ev)
	if nodes[0].Properties["scp_status"] != "confirmed_absent" || nodes[0].Properties["rcp_status"] != "confirmed_absent" {
		t.Fatalf("%v", nodes[0].Properties)
	}
}
