package collectors

import (
	"context"
	"sort"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/Zero0x00/cloudrift/internal/iamauth"
)

// SimulatorAPI is the one read-only call used to cross-check local decisions.
type SimulatorAPI interface {
	SimulatePrincipalPolicy(ctx context.Context, params *iam.SimulatePrincipalPolicyInput, optFns ...func(*iam.Options)) (*iam.SimulatePrincipalPolicyOutput, error)
}

// AgreementProbe is one local decision to cross-check.
type AgreementProbe struct {
	PrincipalARN string
	Action       string
	ResourceARN  string
	Context      map[string]string
	Decision     iamauth.AuthorizationDecision
}

// AgreementReport compares local decisions with iam:SimulatePrincipalPolicy.
//
// The simulator evaluates the principal's identity policies and boundary only. It does not
// evaluate resource policies, SCPs or RCPs, so use it on probes where those controls are
// absent or irrelevant. A disagreement is a finding about the evaluator or the evidence, not
// proof of either side. FalseAllows is the number that must be zero.
type AgreementReport struct {
	Compared     int
	Agree        int
	FalseAllows  []string // local VALIDATED_ALLOWED but the simulator did not allow
	BadDenies    []string // local VALIDATED_DENIED but the simulator did not report an explicit deny
	Conservative []string // local UNKNOWN or CONDITIONAL where the simulator allowed (safe, but lowers coverage)
	Errors       []string // probes the simulator call failed for
}

// CompareWithSimulator runs one read-only simulator call per probe.
func CompareWithSimulator(ctx context.Context, api SimulatorAPI, probes []AgreementProbe) AgreementReport {
	var report AgreementReport
	for _, p := range probes {
		in := &iam.SimulatePrincipalPolicyInput{
			PolicySourceArn: awsv2.String(p.PrincipalARN),
			ActionNames:     []string{p.Action},
			ResourceArns:    []string{p.ResourceARN},
		}
		keys := make([]string, 0, len(p.Context))
		for k := range p.Context {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			in.ContextEntries = append(in.ContextEntries, iamtypes.ContextEntry{
				ContextKeyName: awsv2.String(k), ContextKeyValues: []string{p.Context[k]}, ContextKeyType: iamtypes.ContextKeyTypeEnumString,
			})
		}
		out, err := api.SimulatePrincipalPolicy(ctx, in)
		label := p.Action + " " + p.ResourceARN
		if err != nil || out == nil || len(out.EvaluationResults) == 0 {
			report.Errors = append(report.Errors, label+": "+apiErrorCode(err))
			continue
		}
		report.Compared++
		sim := out.EvaluationResults[0].EvalDecision
		allowed := sim == iamtypes.PolicyEvaluationDecisionTypeAllowed
		explicitDeny := sim == iamtypes.PolicyEvaluationDecisionTypeExplicitDeny
		switch p.Decision.Status {
		case iamauth.StatusAllowed:
			if allowed {
				report.Agree++
			} else {
				report.FalseAllows = append(report.FalseAllows, label)
			}
		case iamauth.StatusDenied:
			if explicitDeny {
				report.Agree++
			} else {
				report.BadDenies = append(report.BadDenies, label)
			}
		default:
			if allowed {
				report.Conservative = append(report.Conservative, label)
			} else {
				report.Agree++
			}
		}
	}
	return report
}
