package iamauth

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// TestAWSExampleSCPsAgainstSimulator asks iam:SimulateCustomPolicy the same question as each AWS SCP example case,
// with the SCP documents passed as the permissions boundary (an SCP filters like a boundary: an explicit Deny blocks,
// and an Allow is needed). It needs AWS credentials and is skipped otherwise:
//
//	CLOUDRIFT_LIVE_AWS_PROFILE=<profile> go test ./internal/iamauth -run SCPsAgainstSimulator -v
//
// RCPs are not covered because the simulator does not evaluate them.
func TestAWSExampleSCPsAgainstSimulator(t *testing.T) {
	profile := os.Getenv("CLOUDRIFT_LIVE_AWS_PROFILE")
	if profile == "" {
		t.Skip("set CLOUDRIFT_LIVE_AWS_PROFILE to compare with iam:SimulateCustomPolicy")
	}
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsconfig.WithSharedConfigProfile(profile), awsconfig.WithDefaultRegion("us-east-1"))
	if err != nil {
		t.Fatal(err)
	}
	client := iam.NewFromConfig(cfg)
	var agree, falseAllow, badDeny, conservative int
	for _, c := range awsExampleCases() {
		req := c.build()
		if len(req.SCPs.Documents) == 0 {
			continue // an RCP case
		}
		local := Evaluate(req).Status
		// The simulator takes one boundary document, so the default FullAWSAccess allow and the example are merged.
		merged := []any{map[string]any{"Effect": "Allow", "Action": "*", "Resource": "*"}}
		for _, d := range req.SCPs.Documents {
			if !strings.HasPrefix(d.ID, "example-") {
				continue
			}
			var doc struct{ Statement []any }
			if err := json.Unmarshal([]byte(d.Raw), &doc); err != nil {
				t.Fatalf("%s: %v", d.ID, err)
			}
			merged = append(merged, doc.Statement...)
		}
		raw, _ := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": merged})
		boundary := []string{string(raw)}
		in := &iam.SimulateCustomPolicyInput{
			PolicyInputList:                    []string{`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`},
			PermissionsBoundaryPolicyInputList: boundary,
			ActionNames:                        []string{req.Action},
			ResourceArns:                       []string{req.ResourceARN},
		}
		for k, v := range req.RequestContext {
			in.ContextEntries = append(in.ContextEntries, iamtypes.ContextEntry{ContextKeyName: awsv2.String(k), ContextKeyValues: []string{v}, ContextKeyType: iamtypes.ContextKeyTypeEnumString})
		}
		out, err := client.SimulateCustomPolicy(context.Background(), in)
		if err != nil || len(out.EvaluationResults) == 0 {
			t.Errorf("%s: simulator call failed: %v", c.name, err)
			continue
		}
		sim := out.EvaluationResults[0].EvalDecision
		t.Logf("%-95s local=%-18s simulator=%s", c.name, local, sim)
		switch {
		case local == StatusAllowed && sim == iamtypes.PolicyEvaluationDecisionTypeAllowed,
			local == StatusDenied && sim == iamtypes.PolicyEvaluationDecisionTypeExplicitDeny:
			agree++
		case local == StatusAllowed:
			falseAllow++
			t.Errorf("FALSE ALLOW: %s (simulator: %s)", c.name, sim)
		case local == StatusDenied:
			badDeny++
			t.Errorf("BAD DENY: %s (simulator: %s)", c.name, sim)
		case sim == iamtypes.PolicyEvaluationDecisionTypeAllowed:
			conservative++
		default:
			agree++
		}
	}
	t.Logf("agree %d, false allows %d, bad denies %d, conservative %d", agree, falseAllow, badDeny, conservative)
}
