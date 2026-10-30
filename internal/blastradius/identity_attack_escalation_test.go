package blastradius

import (
	"context"
	"testing"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func hasEscalation(r schema.IdentityAttackReport, kind, target string) bool {
	for _, e := range r.Escalations {
		if e.Kind == kind && e.TargetARN == target {
			return true
		}
	}
	return false
}

func TestIdentityAttack_Escalation(t *testing.T) {
	caller := "arn:aws:iam::111111111111:role/A"
	target := "arn:aws:iam::111111111111:role/B"

	self := analyzeAttack(caller, []models.AssetNode{
		controlledRole(caller, allowDoc("iam:PutRolePolicy", caller), ""),
	}, nil)
	if self.PrivilegeEscalation != "VALIDATED_POSSIBLE" || !hasEscalation(self, "SELF_POLICY_GRANT", caller) {
		t.Fatalf("self grant not found: %s %#v", self.PrivilegeEscalation, self.Escalations)
	}

	rewrite := analyzeAttack(caller, []models.AssetNode{
		controlledRole(caller, allowDoc("iam:UpdateAssumeRolePolicy", target), ""),
		controlledRole(target, "", ""),
	}, nil)
	if !hasEscalation(rewrite, "TRUST_REWRITE", target) || rewrite.ReachableIdentityCount != 1 {
		t.Fatalf("trust rewrite: %#v reachable=%d", rewrite.Escalations, rewrite.ReachableIdentityCount)
	}

	reach := analyzeAttack(caller, []models.AssetNode{
		controlledRole(caller, allowDoc("sts:AssumeRole", target), ""),
		controlledRole(target, allowDoc("iam:AttachRolePolicy", target), trustAllow(caller)),
	}, nil)
	if !hasEscalation(reach, "SELF_POLICY_GRANT", target) {
		t.Fatalf("assumed role self grant missing: %#v", reach.Escalations)
	}

	grantOther := `{"Statement":[{"Effect":"Allow","Action":"iam:PutRolePolicy","Resource":"` + target + `"},{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"` + target + `"}]}`
	onReachable := analyzeAttack(caller, []models.AssetNode{
		controlledRole(caller, grantOther, ""),
		controlledRole(target, "", trustAllow(caller)),
	}, nil)
	if !hasEscalation(onReachable, "GRANT_ON_REACHABLE_ROLE", target) {
		t.Fatalf("grant on reachable role missing: %#v", onReachable.Escalations)
	}

	// Grant on a role the session cannot reach is a hop, not an escalation.
	unreachable := analyzeAttack(caller, []models.AssetNode{
		controlledRole(caller, allowDoc("iam:PutRolePolicy", target), ""),
		controlledRole(target, "", ""),
	}, nil)
	if len(unreachable.Escalations) != 0 || unreachable.PrivilegeEscalation != "NONE_FOUND_IN_MODELED_TECHNIQUES" {
		t.Fatalf("unreachable grant escalated: %#v %s", unreachable.Escalations, unreachable.PrivilegeEscalation)
	}

	denied := analyzeAttack(caller, []models.AssetNode{
		controlledRole(caller, `{"Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"},{"Effect":"Deny","Action":"iam:PutRolePolicy","Resource":"*"},{"Effect":"Deny","Action":"iam:AttachRolePolicy","Resource":"*"}]}`, ""),
	}, nil)
	if hasEscalation(denied, "SELF_POLICY_GRANT", caller) {
		t.Fatal("explicit deny still produced a self grant")
	}

	unknown := analyzeAttack(caller, []models.AssetNode{controlledRole(caller, "", "")}, nil)
	if len(unknown.Escalations) != 0 {
		t.Fatal("no policy produced an escalation")
	}
}

func lambdaTrust(extra string) string {
	return `{"Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"` + extra + `}]}`
}

func TestIdentityAttack_PassRoleLambda(t *testing.T) {
	caller := "arn:aws:iam::111111111111:role/A"
	target := "arn:aws:iam::111111111111:role/Exec"
	full := `{"Statement":[
	  {"Effect":"Allow","Action":"iam:PassRole","Resource":"` + target + `"},
	  {"Effect":"Allow","Action":["lambda:CreateFunction","lambda:InvokeFunction"],"Resource":"*"}]}`

	ok := analyzeAttack(caller, []models.AssetNode{controlledRole(caller, full, ""), controlledRole(target, "", lambdaTrust(""))}, nil)
	if !hasEscalation(ok, "PASS_ROLE_LAMBDA", target) || ok.ReachableIdentityCount != 1 {
		t.Fatalf("chain not found: %#v", ok.Escalations)
	}

	noInvoke := `{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"` + target + `"},{"Effect":"Allow","Action":"lambda:CreateFunction","Resource":"*"}]}`
	if r := analyzeAttack(caller, []models.AssetNode{controlledRole(caller, noInvoke, ""), controlledRole(target, "", lambdaTrust(""))}, nil); hasEscalation(r, "PASS_ROLE_LAMBDA", target) {
		t.Fatal("chain without invoke escalated")
	}

	if r := analyzeAttack(caller, []models.AssetNode{controlledRole(caller, full, ""), controlledRole(target, "", trustAllow(caller))}, nil); hasEscalation(r, "PASS_ROLE_LAMBDA", target) {
		t.Fatal("role Lambda cannot assume escalated")
	}
	cond := lambdaTrust(`,"Condition":{"StringEquals":{"aws:SourceAccount":"111111111111"}}`)
	if r := analyzeAttack(caller, []models.AssetNode{controlledRole(caller, full, ""), controlledRole(target, "", cond)}, nil); hasEscalation(r, "PASS_ROLE_LAMBDA", target) {
		t.Fatal("conditional trust escalated")
	}

	ec2Only := `{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"` + target + `","Condition":{"StringEquals":{"iam:PassedToService":"ec2.amazonaws.com"}}},{"Effect":"Allow","Action":["lambda:CreateFunction","lambda:InvokeFunction"],"Resource":"*"}]}`
	if r := analyzeAttack(caller, []models.AssetNode{controlledRole(caller, ec2Only, ""), controlledRole(target, "", lambdaTrust(""))}, nil); hasEscalation(r, "PASS_ROLE_LAMBDA", target) {
		t.Fatal("PassRole limited to ec2 escalated through lambda")
	}

	denied := `{"Statement":[{"Effect":"Allow","Action":["iam:PassRole","lambda:*"],"Resource":"*"},{"Effect":"Deny","Action":"lambda:CreateFunction","Resource":"*"}]}`
	if r := analyzeAttack(caller, []models.AssetNode{controlledRole(caller, denied, ""), controlledRole(target, "", lambdaTrust(""))}, nil); hasEscalation(r, "PASS_ROLE_LAMBDA", target) {
		t.Fatal("explicit deny escalated")
	}

	scoped := `{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"` + target + `"},{"Effect":"Allow","Action":["lambda:CreateFunction","lambda:InvokeFunction"],"Resource":"arn:aws:lambda:*:111111111111:function:prod-*"}]}`
	if r := analyzeAttack(caller, []models.AssetNode{controlledRole(caller, scoped, ""), controlledRole(target, "", lambdaTrust(""))}, nil); hasEscalation(r, "PASS_ROLE_LAMBDA", target) {
		t.Fatal("name-scoped policy escalated; the probe must not guess a matching name")
	}
}

func serviceTrust(service string) string {
	return `{"Statement":[{"Effect":"Allow","Principal":{"Service":"` + service + `"},"Action":"sts:AssumeRole"}]}`
}

func attackWithRels(principal string, assets []models.AssetNode, rels []models.Relationship) schema.IdentityAttackReport {
	return AnalyzeIdentityAttack(context.Background(), IdentityAttackRequest{
		ScanID: permScan, InitialPrincipal: principal, SessionSource: "assumed", Assets: assets, Relationships: rels,
	})
}

func TestIdentityAttack_PassRoleServices(t *testing.T) {
	caller := "arn:aws:iam::111111111111:role/A"
	target := "arn:aws:iam::111111111111:role/Svc"
	cases := []struct {
		kind, service string
		actions       []string
	}{
		{"PASS_ROLE_CLOUDFORMATION", "cloudformation.amazonaws.com", []string{"cloudformation:CreateStack"}},
		{"PASS_ROLE_GLUE_ENDPOINT", "glue.amazonaws.com", []string{"glue:CreateDevEndpoint", "glue:GetDevEndpoint"}},
		{"PASS_ROLE_DATA_PIPELINE", "datapipeline.amazonaws.com", []string{"datapipeline:CreatePipeline", "datapipeline:PutPipelineDefinition"}},
		{"PASS_ROLE_LAMBDA_ADDPERMISSION", "lambda.amazonaws.com", []string{"lambda:CreateFunction", "lambda:AddPermission"}},
	}
	for _, c := range cases {
		doc := func(actions []string) string {
			q := ""
			for i, a := range actions {
				if i > 0 {
					q += ","
				}
				q += `"` + a + `"`
			}
			return `{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"` + target + `"},{"Effect":"Allow","Action":[` + q + `],"Resource":"*"}]}`
		}
		trusted := controlledRole(target, "", serviceTrust(c.service))
		if r := analyzeAttack(caller, []models.AssetNode{controlledRole(caller, doc(c.actions), ""), trusted}, nil); !hasEscalation(r, c.kind, target) {
			t.Errorf("%s: chain not found: %#v", c.kind, r.Escalations)
		}
		if r := analyzeAttack(caller, []models.AssetNode{controlledRole(caller, doc(c.actions[:len(c.actions)-1]), ""), trusted}, nil); hasEscalation(r, c.kind, target) {
			t.Errorf("%s: escalated with a missing step", c.kind)
		}
		wrongTrust := controlledRole(target, "", serviceTrust("ec2.amazonaws.com"))
		if r := analyzeAttack(caller, []models.AssetNode{controlledRole(caller, doc(c.actions), ""), wrongTrust}, nil); hasEscalation(r, c.kind, target) {
			t.Errorf("%s: escalated for a role the service cannot assume", c.kind)
		}
	}
}

func TestIdentityAttack_EditLambdaCode(t *testing.T) {
	caller := "arn:aws:iam::111111111111:role/A"
	exec := "arn:aws:iam::111111111111:role/Exec"
	fn := "arn:aws:lambda:us-east-1:111111111111:function:app"
	fnAsset := models.AssetNode{ARN: fn, AssetType: models.AssetLambdaFunction, AccountID: "111111111111", Properties: map[string]any{
		"function_policy_status": "confirmed_absent", "function_policy_evidence": "test fixture: no function policy",
	}}
	rels := []models.Relationship{{SourceARN: fn, TargetARN: exec, RelType: models.RelLambdaUsesExecutionRole}}
	both := `{"Statement":[{"Effect":"Allow","Action":["lambda:UpdateFunctionCode","lambda:InvokeFunction"],"Resource":"` + fn + `"}]}`
	assets := func(doc string) []models.AssetNode {
		return []models.AssetNode{controlledRole(caller, doc, ""), controlledRole(exec, "", ""), fnAsset}
	}
	if r := attackWithRels(caller, assets(both), rels); !hasEscalation(r, "EDIT_LAMBDA_CODE", exec) {
		t.Fatalf("edit chain not found: %#v", r.Escalations)
	}
	if r := attackWithRels(caller, assets(allowDoc("lambda:UpdateFunctionCode", fn)), rels); hasEscalation(r, "EDIT_LAMBDA_CODE", exec) {
		t.Fatal("update without invoke escalated")
	}
	if r := attackWithRels(caller, assets(both), nil); hasEscalation(r, "EDIT_LAMBDA_CODE", exec) {
		t.Fatal("function with no known execution role escalated")
	}
}

func TestIdentityAttack_CreatePolicyVersion(t *testing.T) {
	caller := "arn:aws:iam::111111111111:role/A"
	managed := "arn:aws:iam::111111111111:policy/Shared"
	awsManaged := "arn:aws:iam::aws:policy/ReadOnlyAccess"
	grant := allowDoc("iam:CreatePolicyVersion", "*")
	rels := func(policy string) []models.Relationship {
		return []models.Relationship{{SourceARN: caller, TargetARN: policy, RelType: models.RelPolicyAttachedTo}}
	}
	assets := func(policy string) []models.AssetNode {
		return []models.AssetNode{controlledRole(caller, grant, ""), policyAsset(policy, allowDoc("s3:ListBucket", "*"))}
	}
	if r := attackWithRels(caller, assets(managed), rels(managed)); !hasEscalation(r, "SELF_POLICY_GRANT", caller) {
		t.Fatalf("policy version edit not found: %#v", r.Escalations)
	}
	if r := attackWithRels(caller, assets(awsManaged), rels(awsManaged)); len(r.Escalations) != 0 {
		t.Fatalf("AWS managed policy escalated: %#v", r.Escalations)
	}
	if r := attackWithRels(caller, assets(managed), nil); len(r.Escalations) != 0 {
		t.Fatalf("unattached policy escalated: %#v", r.Escalations)
	}
}
