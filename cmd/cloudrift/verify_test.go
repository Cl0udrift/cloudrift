package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/Zero0x00/cloudrift/internal/models"
)

type fakeSim struct{ decide func(action, resource string) iamtypes.PolicyEvaluationDecisionType }

func (f fakeSim) SimulatePrincipalPolicy(_ context.Context, in *iam.SimulatePrincipalPolicyInput, _ ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error) {
	d := f.decide(in.ActionNames[0], in.ResourceArns[0])
	return &iam.SimulatePrincipalPolicyOutput{EvaluationResults: []iamtypes.EvaluationResult{{EvalDecision: d}}}, nil
}

func verifyWorld(withSCP bool) []models.AssetNode {
	props := map[string]any{
		"permissions_boundary_status": "confirmed_absent", "permissions_boundary_evidence": "fixture: none",
		"inline_policy_documents": []any{`{"Statement":[{"Effect":"Allow","Action":"iam:AttachUserPolicy","Resource":"*"}]}`},
	}
	if withSCP {
		props["scp_status"] = "present"
		props["scp_documents"] = []any{`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`}
	}
	return []models.AssetNode{{ScanID: "s", ARN: "arn:aws:iam::1:user/alice", Name: "alice", AccountID: "1", AssetType: models.AssetIAMUser, Properties: props}}
}

func TestVerifyAuthzAgreementAndDisagreement(t *testing.T) {
	allowOnlyAttach := func(action, _ string) iamtypes.PolicyEvaluationDecisionType {
		if action == "iam:AttachUserPolicy" {
			return iamtypes.PolicyEvaluationDecisionTypeAllowed
		}
		return iamtypes.PolicyEvaluationDecisionTypeImplicitDeny
	}
	var out bytes.Buffer
	failed, err := runVerifyAuthz(context.Background(), fakeSim{allowOnlyAttach}, "s", verifyWorld(false), nil, 50, false, &out)
	if err != nil || failed || !strings.Contains(out.String(), "Result: AGREEMENT") {
		t.Fatalf("a simulator that agrees must pass: failed=%v err=%v\n%s", failed, err, out.String())
	}

	out.Reset()
	denyAll := func(string, string) iamtypes.PolicyEvaluationDecisionType { return iamtypes.PolicyEvaluationDecisionTypeImplicitDeny }
	failed, err = runVerifyAuthz(context.Background(), fakeSim{denyAll}, "s", verifyWorld(false), nil, 50, false, &out)
	if err != nil || !failed || !strings.Contains(out.String(), "FALSE ALLOW") || !strings.Contains(out.String(), "CONFIRMED_DISAGREEMENT") {
		t.Fatalf("a local allow the simulator does not give must fail: failed=%v\n%s", failed, out.String())
	}
}

func TestVerifyAuthzSkipsCallersWithOrganizationControls(t *testing.T) {
	var out bytes.Buffer
	called := 0
	api := fakeSim{func(string, string) iamtypes.PolicyEvaluationDecisionType {
		called++
		return iamtypes.PolicyEvaluationDecisionTypeAllowed
	}}
	failed, err := runVerifyAuthz(context.Background(), api, "s", verifyWorld(true), nil, 50, true, &out)
	if err != nil || failed {
		t.Fatalf("%v %v", failed, err)
	}
	if called != 0 || !strings.Contains(out.String(), "INCOMPARABLE") || !strings.Contains(out.String(), "SCP/RCP") {
		t.Fatalf("with SCPs in the scan nothing is comparable and the simulator must not be asked: calls=%d\n%s", called, out.String())
	}
}
