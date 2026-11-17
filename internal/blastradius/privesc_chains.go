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
	// optional calls are evaluated and shown but never decide the chain.
	optional []string
	probeARN func(account string) string
	// trustAction is the action the role's trust policy must allow the service; empty means sts:AssumeRole.
	trustAction string
	// probes gives an action its own resource ARN; identityOnly actions are decided from the identity policy alone.
	probes       map[string]string
	identityOnly []string
}

// allPassRolePlans is the five hand-written plans plus every record in iamauth.PassRoleServices.
func allPassRolePlans() []passRolePlan {
	plans := append([]passRolePlan{}, passRolePlans...)
	for _, s := range iamauth.PassRoleServices {
		s := s
		plans = append(plans, passRolePlan{
			kind: s.Kind, service: s.Principal, actions: s.Required, optional: s.Optional, trustAction: s.TrustAction,
			probes: s.Probes, identityOnly: s.IdentityOnly,
			probeARN: func(account string) string { return strings.ReplaceAll(s.Probe, "{account}", account) },
		})
	}
	return plans
}

var passRolePlans = []passRolePlan{
	{kind: "PASS_ROLE_LAMBDA", service: "lambda.amazonaws.com", actions: []string{"lambda:CreateFunction", "lambda:InvokeFunction"}, probeARN: lambdaProbe},
	{kind: "PASS_ROLE_LAMBDA_ADDPERMISSION", service: "lambda.amazonaws.com", actions: []string{"lambda:CreateFunction", "lambda:AddPermission"}, probeARN: lambdaProbe},
	{kind: "PASS_ROLE_CLOUDFORMATION", service: "cloudformation.amazonaws.com", actions: []string{"cloudformation:CreateStack"}, probeARN: func(a string) string {
		return "arn:aws:cloudformation:us-east-1:" + a + ":stack/cloudrift-probe/00000000-0000-0000-0000-000000000000"
	}},
	{kind: "PASS_ROLE_GLUE_ENDPOINT", service: "glue.amazonaws.com", actions: []string{"glue:CreateDevEndpoint"}, optional: []string{"glue:GetDevEndpoint"}, probeARN: func(a string) string {
		return "arn:aws:glue:us-east-1:" + a + ":devEndpoint/cloudrift-probe"
	}},
	{kind: "PASS_ROLE_DATA_PIPELINE", service: "datapipeline.amazonaws.com", actions: []string{"datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition", "datapipeline:ActivatePipeline"}, probeARN: func(a string) string {
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

	for _, plan := range allPassRolePlans() {
		// What a service presents when it assumes the role for a resource the caller creates in this account.
		presented := map[string]string{"aws:SourceAccount": account, "aws:SourceArn": plan.probeARN(account)}
		var targets []models.AssetNode
		for _, target := range candidates {
			if target.AccountID == account && trustsServiceAction(target, plan.service, plan.trustAction, presented) {
				targets = append(targets, target)
			}
		}
		if len(targets) == 0 {
			continue // no role the service can assume, so nothing to pass; skip evaluating the calls
		}
		probe := probeAsset(plan.probeARN(account), account)
		// stepProbe is the resource the action acts on: its own type when the plan names one, else the plan's.
		stepProbe := func(a string) models.AssetNode {
			if arn, ok := plan.probes[a]; ok {
				return probeAsset(strings.ReplaceAll(arn, "{account}", account), account)
			}
			return probe
		}
		stepCap := func(a string) iamauth.Capability {
			c := capOf(a)
			for _, id := range plan.identityOnly {
				if strings.EqualFold(id, a) {
					c.IdentityOnlyProbe = true
				}
			}
			return c
		}
		var steps, optional []schema.PermissionDecision
		for _, a := range plan.actions {
			steps = append(steps, eval(stepCap(a), stepProbe(a), req.RequestContext))
		}
		for _, a := range plan.optional {
			optional = append(optional, eval(stepCap(a), stepProbe(a), req.RequestContext))
		}
		ctx := map[string]string{}
		for k, v := range req.RequestContext {
			ctx[k] = v
		}
		ctx["iam:PassedToService"] = plan.service
		for _, target := range targets {
			all := append([]schema.PermissionDecision{eval(capOf("iam:PassRole"), target, ctx)}, steps...)
			chains = append(chains, schema.PrivescChain{Kind: plan.kind, Service: plan.service, RoleARN: target.ARN, Status: combineSteps(all), Steps: all, OptionalSteps: optional})
		}
	}

	// Edit the code of an existing function, then invoke it: the code runs as the function's role.
	for _, fn := range functions {
		role := executionRole(fn, req.Relationships)
		if role == "" || role == caller.ARN || !containsARN(roles, role) {
			continue
		}
		// Updating the code is the escalation. Invoking it, or letting another principal invoke it, only
		// makes it run sooner; an existing trigger can run it, so those calls are optional.
		all := []schema.PermissionDecision{eval(capOf("lambda:UpdateFunctionCode"), fn, req.RequestContext)}
		optional := []schema.PermissionDecision{eval(capOf("lambda:InvokeFunction"), fn, req.RequestContext), eval(capOf("lambda:AddPermission"), fn, req.RequestContext)}
		chains = append(chains, schema.PrivescChain{Kind: "EDIT_LAMBDA_CODE", Service: "lambda.amazonaws.com", RoleARN: role, Status: combineSteps(all), Steps: all, OptionalSteps: optional})
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

// Technique names one hop type the attack search can model.
type Technique struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"` // movement, escalation, impact
	Summary string `json:"summary"`
}

// AttackTechniques lists every technique the attack search models. The coverage page reads it,
// so the page cannot drift from the code.
func AttackTechniques() []Technique {
	out := []Technique{
		{techniqueAssumeRole, "movement", "sts:AssumeRole into another role (same or cross account)"},
		{techniqueRewriteTrust, "escalation", "iam:UpdateAssumeRolePolicy so the session can trust itself, then assume the role"},
		{techniqueGrantPolicy, "escalation", "iam:AttachRolePolicy or iam:PutRolePolicy on the session's own role or a reachable role"},
		{techniquePolicyVer, "escalation", "iam:CreatePolicyVersion on a customer managed policy attached to the session's role or a reachable role"},
		{"EDIT_LAMBDA_CODE", "escalation", "lambda:UpdateFunctionCode plus invoke on a function whose execution role is another role"},
		{techniqueGrantUser, "escalation", "iam:AttachUserPolicy or iam:PutUserPolicy on the session's own user or a reachable user"},
		{techniqueGrantGroup, "escalation", "iam:AttachGroupPolicy or iam:PutGroupPolicy on a group the user belongs to"},
		{techniqueJoinGroup, "escalation", "iam:AddUserToGroup into a group that holds administrative policies"},
		{techniqueTakeover, "escalation", "iam:CreateAccessKey, iam:CreateLoginProfile or iam:UpdateLoginProfile on another user"},
		{techniqueReadObject, "impact", "s3:GetObject on a collected object"},
		{techniqueReadSecret, "impact", "secretsmanager:GetSecretValue including the KMS decrypt leg"},
	}
	for _, p := range allPassRolePlans() {
		out = append(out, Technique{p.kind, "escalation", "iam:PassRole to " + p.service + " plus " + strings.Join(p.actions, " and ")})
	}
	return out
}
