package collectors

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/Zero0x00/cloudrift/internal/iamauth"
)

type fakeSimulator struct {
	byAction map[string]iamtypes.PolicyEvaluationDecisionType
	calls    []*iam.SimulatePrincipalPolicyInput
}

func (f *fakeSimulator) SimulatePrincipalPolicy(_ context.Context, in *iam.SimulatePrincipalPolicyInput, _ ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error) {
	f.calls = append(f.calls, in)
	d, ok := f.byAction[in.ActionNames[0]]
	if !ok {
		return nil, apiErr{"Throttling"}
	}
	return &iam.SimulatePrincipalPolicyOutput{EvaluationResults: []iamtypes.EvaluationResult{{EvalDecision: d}}}, nil
}

func TestCompareWithSimulator(t *testing.T) {
	sim := &fakeSimulator{byAction: map[string]iamtypes.PolicyEvaluationDecisionType{
		"a:Agree":    iamtypes.PolicyEvaluationDecisionTypeAllowed,
		"a:False":    iamtypes.PolicyEvaluationDecisionTypeImplicitDeny,
		"a:Deny":     iamtypes.PolicyEvaluationDecisionTypeExplicitDeny,
		"a:BadDeny":  iamtypes.PolicyEvaluationDecisionTypeImplicitDeny,
		"a:Cautious": iamtypes.PolicyEvaluationDecisionTypeAllowed,
		"a:Unknown":  iamtypes.PolicyEvaluationDecisionTypeImplicitDeny,
	}}
	probe := func(action, status string) AgreementProbe {
		return AgreementProbe{PrincipalARN: "arn:aws:iam::1:role/r", Action: action, ResourceARN: "arn:aws:s3:::b/k",
			Context: map[string]string{"aws:SourceIp": "10.0.0.1"}, Decision: iamauth.AuthorizationDecision{Status: status}}
	}
	report := CompareWithSimulator(context.Background(), sim, []AgreementProbe{
		probe("a:Agree", iamauth.StatusAllowed),
		probe("a:False", iamauth.StatusAllowed),
		probe("a:Deny", iamauth.StatusDenied),
		probe("a:BadDeny", iamauth.StatusDenied),
		probe("a:Cautious", iamauth.StatusUnknown),
		probe("a:Unknown", iamauth.StatusConditional),
		probe("a:Throttled", iamauth.StatusAllowed),
	})
	if report.Compared != 6 || report.Agree != 3 || len(report.FalseAllows) != 1 || len(report.BadDenies) != 1 || len(report.Conservative) != 1 || len(report.Errors) != 1 {
		t.Fatalf("%+v", report)
	}
	if got := sim.calls[0].ContextEntries; len(got) != 1 || *got[0].ContextKeyName != "aws:SourceIp" {
		t.Fatalf("context was not passed: %+v", got)
	}
}
