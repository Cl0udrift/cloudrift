package blastradius

import (
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/iamauth"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// Privilege-escalation techniques after the public Pacu iam__privesc_scan method list
// (Rhino Security Labs, BSD-3). Only the method definitions are used: which actions a
// method needs and what it yields. Each step is evaluated by the local evaluator.

// passRolePlan is iam:PassRole to a service role plus the calls that run code as that role.
// The caller chooses the resource name and Region, so a policy scoped to other names or Regions
// yields UNKNOWN, never an allow.
type passRolePlan struct {
	kind, service string
	actions       []string
	probeARN      func(account string) string
}

var passRolePlans = []passRolePlan{
	{"PASS_ROLE_LAMBDA", "lambda.amazonaws.com", []string{"lambda:CreateFunction", "lambda:InvokeFunction"}, lambdaProbe},
	{"PASS_ROLE_LAMBDA_ADDPERMISSION", "lambda.amazonaws.com", []string{"lambda:CreateFunction", "lambda:AddPermission"}, lambdaProbe},
	{"PASS_ROLE_CLOUDFORMATION", "cloudformation.amazonaws.com", []string{"cloudformation:CreateStack"}, func(a string) string {
		return "arn:aws:cloudformation:us-east-1:" + a + ":stack/cloudrift-probe/00000000-0000-0000-0000-000000000000"
	}},
	{"PASS_ROLE_GLUE_ENDPOINT", "glue.amazonaws.com", []string{"glue:CreateDevEndpoint", "glue:GetDevEndpoint"}, func(a string) string {
		return "arn:aws:glue:us-east-1:" + a + ":devEndpoint/cloudrift-probe"
	}},
	{"PASS_ROLE_DATA_PIPELINE", "datapipeline.amazonaws.com", []string{"datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition"}, func(a string) string {
		return "arn:aws:datapipeline:us-east-1:" + a + ":pipeline/cloudrift-probe"
	}},
}

func lambdaProbe(account string) string {
	return "arn:aws:lambda:us-east-1:" + account + ":function:cloudrift-probe"
}

type evalFunc func(iamauth.Capability, models.AssetNode, map[string]string) schema.PermissionDecision

func capOf(action string) iamauth.Capability {
	c, _ := iamauth.CapabilityFor(action)
	return c
}

func probeAsset(arn, account string) models.AssetNode {
	return models.AssetNode{
		ARN: arn, AccountID: account,
		Properties: map[string]any{
			"function_policy_status": "confirmed_absent", "function_policy_evidence": "a resource that does not exist yet has no resource policy",
		},
	}
}

// privescChains evaluates the multi-call escalations for one caller session.
func privescChains(req PermissionBlastRequest, caller models.AssetNode, roles, functions []models.AssetNode, eval evalFunc) []schema.PrivescChain {
	account := caller.AccountID
	var chains []schema.PrivescChain
	candidates := append(append([]models.AssetNode{}, roles...), caller)

	for _, plan := range passRolePlans {
		probe := probeAsset(plan.probeARN(account), account)
		var steps []schema.PermissionDecision
		for _, a := range plan.actions {
			steps = append(steps, eval(capOf(a), probe, req.RequestContext))
		}
		ctx := map[string]string{}
		for k, v := range req.RequestContext {
			ctx[k] = v
		}
		ctx["iam:PassedToService"] = plan.service
		for _, target := range candidates {
			if target.AccountID != account || !trustsService(target, plan.service) {
				continue
			}
			all := append([]schema.PermissionDecision{eval(capOf("iam:PassRole"), target, ctx)}, steps...)
			chains = append(chains, schema.PrivescChain{Kind: plan.kind, Service: plan.service, RoleARN: target.ARN, Status: combineSteps(all), Steps: all})
		}
	}

	// Edit the code of an existing function, then invoke it: the code runs as the function's role.
	for _, fn := range functions {
		role := executionRole(fn, req.Relationships)
		if role == "" || role == caller.ARN || !containsARN(roles, role) {
			continue
		}
		all := []schema.PermissionDecision{eval(capOf("lambda:UpdateFunctionCode"), fn, req.RequestContext), eval(capOf("lambda:InvokeFunction"), fn, req.RequestContext)}
		chains = append(chains, schema.PrivescChain{Kind: "EDIT_LAMBDA_CODE", Service: "lambda.amazonaws.com", RoleARN: role, Status: combineSteps(all), Steps: all})
	}

	// Publish a new default version of a customer managed policy attached to a role. One decision per policy.
	byPolicy := map[string]schema.PermissionDecision{}
	for _, rel := range req.Relationships {
		if rel.RelType != models.RelPolicyAttachedTo || strings.Contains(rel.TargetARN, ":aws:policy/") {
			continue
		}
		holder := rel.SourceARN
		if holder != caller.ARN && !containsARN(roles, holder) {
			continue
		}
		d, ok := byPolicy[rel.TargetARN]
		if !ok {
			d = eval(capOf("iam:CreatePolicyVersion"), models.AssetNode{ARN: rel.TargetARN, AccountID: account}, req.RequestContext)
			byPolicy[rel.TargetARN] = d
		}
		chains = append(chains, schema.PrivescChain{Kind: "CREATE_POLICY_VERSION", Service: "iam.amazonaws.com", RoleARN: holder, Status: d.Status, Steps: []schema.PermissionDecision{d}})
	}
	sort.SliceStable(chains, func(i, j int) bool {
		if chains[i].Kind == chains[j].Kind {
			return chains[i].RoleARN < chains[j].RoleARN
		}
		return chains[i].Kind < chains[j].Kind
	})
	return chains
}

func executionRole(fn models.AssetNode, rels []models.Relationship) string {
	for _, rel := range rels {
		if rel.RelType == models.RelLambdaUsesExecutionRole && rel.SourceARN == fn.ARN {
			return rel.TargetARN
		}
	}
	return ""
}

func containsARN(assets []models.AssetNode, arn string) bool {
	for _, a := range assets {
		if a.ARN == arn {
			return true
		}
	}
	return false
}
