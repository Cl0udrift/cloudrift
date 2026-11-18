package blastradius

// Benchmark against the pathfinding.cloud catalog (testdata/pathfinding). Ground truth comes only from the
// reference record: its required permissions and what each permission means in AWS. No Cloudrift technique
// list is consulted to decide what a path "should" do.

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/referencecov"
)

type pfPath struct {
	Additional []string `json:"additional"`
	ID         string   `json:"id"`
	Cat        string   `json:"cat"`
	Required   []string `json:"required"`
}

type pfCase struct {
	ID      string   `json:"id"`
	Variant string   `json:"variant"`
	Expect  string   `json:"expect"` // exploitable | not_exploitable | ambiguous | not_representable
	Fired   []string `json:"fired_labels"`
	Want    []string `json:"want_labels"`
	Techs   []string `json:"techniques"`
	Outcome string   `json:"outcome"` // detected | partial | not_detected | n/a
	Note    string   `json:"note,omitempty"`
}

const pfAcct = "111111111111"

func pfRole(n string) string { return "arn:aws:iam::" + pfAcct + ":role/" + n }
func pfUser(n string) string { return "arn:aws:iam::" + pfAcct + ":user/" + n }

var pfServices = map[string][]string{
	"apprunner": {"tasks.apprunner.amazonaws.com", "build.apprunner.amazonaws.com"}, "batch": {"ecs-tasks.amazonaws.com", "batch.amazonaws.com"},
	"bedrock-agentcore": {"bedrock-agentcore.amazonaws.com"}, "braket": {"braket.amazonaws.com"}, "cloudformation": {"cloudformation.amazonaws.com"},
	"codebuild": {"codebuild.amazonaws.com"}, "cognito-identity": {"cognito-identity.amazonaws.com"}, "datapipeline": {"datapipeline.amazonaws.com", "elasticmapreduce.amazonaws.com"},
	"ec2": {"ec2.amazonaws.com"}, "ecs": {"ecs-tasks.amazonaws.com", "ecs.amazonaws.com"}, "elasticmapreduce": {"elasticmapreduce.amazonaws.com", "ec2.amazonaws.com"},
	"emr-serverless": {"emr-serverless.amazonaws.com"}, "gamelift": {"gamelift.amazonaws.com", "ec2.amazonaws.com"}, "glue": {"glue.amazonaws.com"}, "imagebuilder": {"ec2.amazonaws.com", "imagebuilder.amazonaws.com"},
	"kinesisanalytics": {"kinesisanalytics.amazonaws.com"}, "lambda": {"lambda.amazonaws.com"}, "omics": {"omics.amazonaws.com"}, "sagemaker": {"sagemaker.amazonaws.com"},
	"scheduler": {"scheduler.amazonaws.com"}, "ssm": {"ssm.amazonaws.com"}, "states": {"states.amazonaws.com"},
}

// label says what a permission lets an attacker do in AWS, independent of any scanner.
func pfLabel(perm string, passrole bool) string {
	switch perm {
	case "sts:AssumeRole":
		return "assume_role"
	case "iam:UpdateAssumeRolePolicy":
		return "rewrite_trust"
	case "iam:AttachRolePolicy", "iam:PutRolePolicy":
		return "grant_role_policy"
	case "iam:AttachUserPolicy", "iam:PutUserPolicy":
		return "grant_user_policy"
	case "iam:AttachGroupPolicy", "iam:PutGroupPolicy":
		return "grant_group_policy"
	case "iam:CreatePolicyVersion":
		return "edit_managed_policy"
	case "iam:AddUserToGroup":
		return "join_group"
	case "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile":
		return "user_takeover"
	case "lambda:UpdateFunctionCode":
		return "edit_function_code"
	case "ssm:StartSession", "ssm:SendCommand", "ec2-instance-connect:SendSSHPublicKey", "ecs:ExecuteCommand", "ec2:ModifyInstanceAttribute",
		"cloudformation:UpdateStack", "cloudformation:CreateChangeSet", "codebuild:StartBuild", "codebuild:StartBuildBatch", "states:UpdateStateMachine",
		"glue:UpdateDevEndpoint", "batch:SubmitJob", "apprunner:UpdateService", "sagemaker:CreatePresignedNotebookInstanceUrl", "sagemaker:UpdateNotebookInstance",
		"bedrock-agentcore:InvokeCodeInterpreter", "bedrock-agentcore:InvokeAgentRuntimeCommand", "bedrock-agentcore:ConnectBrowserAutomationStream",
		"ec2:CreateLaunchTemplateVersion", "codedeploy:CreateDeployment":
		return "workload_exec" // runs commands or code on a workload that runs as a role
	case "iam:DeleteAccessKey":
		return "" // enabler only
	}
	return ""
}

func pfNeedsUser(req []string) bool {
	for _, p := range req {
		switch p {
		case "iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:AddUserToGroup", "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile", "iam:AttachGroupPolicy", "iam:PutGroupPolicy":
			return true
		}
	}
	return false
}

func pfServiceOf(req []string) string {
	for _, p := range req {
		svc := strings.SplitN(p, ":", 2)[0]
		if _, ok := pfServices[svc]; ok {
			return svc
		}
	}
	return ""
}

func pfWanted(p pfPath, granted []string) []string {
	set := map[string]bool{}
	pass := false
	for _, g := range granted {
		if g == "iam:PassRole" {
			pass = true
		}
	}
	for _, g := range granted {
		if l := pfLabel(g, pass); l != "" {
			set[l] = true
		}
	}
	if pass {
		if svc := pfServiceOf(granted); svc != "" {
			set["passrole:"+svc] = true
		}
	}
	var out []string
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func pfDoc(perms []string, deny string) string {
	b, _ := json.Marshal(perms)
	d := `{"Statement":[{"Effect":"Allow","Action":` + string(b) + `,"Resource":"*"}`
	if deny != "" {
		d += `,{"Effect":"Deny","Action":"` + deny + `","Resource":"*"}`
	}
	return d + `]}`
}

func pfLabelsFromTech(t string) []string {
	switch {
	case t == "ASSUME_ROLE":
		return []string{"assume_role"}
	case t == "REWRITE_TRUST":
		return []string{"rewrite_trust"}
	case t == "GRANT_ROLE_POLICY":
		return []string{"grant_role_policy"}
	case t == "GRANT_USER_POLICY":
		return []string{"grant_user_policy"}
	case t == "GRANT_GROUP_POLICY":
		return []string{"grant_group_policy"}
	case t == "CREATE_POLICY_VERSION":
		return []string{"edit_managed_policy"}
	case t == "ADD_USER_TO_GROUP":
		return []string{"join_group"}
	case t == "TAKEOVER_USER":
		return []string{"user_takeover"}
	case t == "EDIT_LAMBDA_CODE":
		return []string{"edit_function_code"}
	case strings.HasPrefix(t, "WORKLOAD_"):
		return []string{"workload_exec"}
	case strings.HasPrefix(t, "PASS_ROLE_") && pfKeyService(t) != "":
		return []string{"passrole:" + pfKeyService(t)}
	case strings.HasPrefix(t, "PASS_ROLE_LAMBDA"):
		return []string{"passrole:lambda"}
	case t == "PASS_ROLE_CLOUDFORMATION":
		return []string{"passrole:cloudformation"}
	case t == "PASS_ROLE_GLUE_ENDPOINT":
		return []string{"passrole:glue"}
	case t == "PASS_ROLE_DATA_PIPELINE":
		return []string{"passrole:datapipeline"}
	}
	return nil
}

func pfRun(p pfPath, granted []string, deny string, mode ...string) (fired, techs []string) {
	m := ""
	if len(mode) > 0 {
		m = mode[0]
	}
	admin := `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	attackerARN := pfRole("Attacker")
	var attacker models.AssetNode
	var assets []models.AssetNode
	var rels []models.Relationship
	doc := pfDoc(granted, deny)
	if pfNeedsUser(p.Required) {
		attackerARN = pfUser("attacker")
		attacker = controlled(models.AssetNode{ARN: attackerARN, AssetType: models.AssetIAMUser, Name: "attacker"}, doc)
	} else {
		attacker = controlled(models.AssetNode{ARN: attackerARN, AssetType: models.AssetIAMRole, Name: "Attacker"}, doc)
		attacker.Properties["trust_policy_document"] = trustAllow("arn:aws:iam::" + pfAcct + ":root")
	}
	assets = append(assets, attacker)
	svc := pfServiceOf(p.Required)
	adminRole := controlled(models.AssetNode{ARN: pfRole("AdminRole"), AssetType: models.AssetIAMRole, Name: "AdminRole"}, admin)
	trust := trustAllow("arn:aws:iam::999999999999:root")
	if svc != "" && containsStr(p.Required, "iam:PassRole") {
		var ps []string
		for _, s := range pfServices[svc] {
			ps = append(ps, `"`+s+`"`)
		}
		action := "sts:AssumeRole"
		if svc == "cognito-identity" {
			action = "sts:AssumeRoleWithWebIdentity" // the reference's trust policy for this path
		}
		cond := ""
		switch m {
		case "condtrust":
			cond = `,"Condition":{"StringEquals":{"aws:SourceAccount":"` + pfAcct + `"}}`
		case "condtrust_wrong":
			cond = `,"Condition":{"StringEquals":{"aws:SourceAccount":"999999999999"}}`
		}
		trust = `{"Statement":[{"Effect":"Allow","Principal":{"Service":[` + strings.Join(ps, ",") + `]},"Action":"` + action + `"` + cond + `}]}`
	}
	if m == "wrongtrust" {
		trust = `{"Statement":[{"Effect":"Allow","Principal":{"Service":["not-a-matching-service.amazonaws.com"]},"Action":"sts:AssumeRole"}]}`
	}
	if m == "boundary" {
		attacker.Properties["permissions_boundary_status"] = "present"
		attacker.Properties["permissions_boundary_evidence"] = "fixture boundary"
		attacker.Properties["permissions_boundary_document"] = `{"Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}`
		assets[0] = attacker
	}
	adminRole.Properties["trust_policy_document"] = trust
	target := controlled(models.AssetNode{ARN: pfRole("Target"), AssetType: models.AssetIAMRole, Name: "Target"})
	target.Properties["trust_policy_document"] = trustAllow("arn:aws:iam::" + pfAcct + ":root")
	// The victim's credential state comes from the path's prerequisites: UpdateLoginProfile needs a console
	// password, DeleteAccessKey is only needed when the victim already holds two keys, and the others need room.
	console, keys := containsStr(p.Required, "iam:UpdateLoginProfile"), 1
	if containsStr(p.Required, "iam:DeleteAccessKey") {
		keys = 2
	}
	switch m {
	case "blocked":
		console, keys = !console, 2
	}
	victim := credUser(pfUser("victim"), console, keys)
	if m == "noreport" {
		victim = controlled(models.AssetNode{ARN: pfUser("victim"), AssetType: models.AssetIAMUser, Name: "victim"})
	}
	group := controlled(models.AssetNode{ARN: "arn:aws:iam::" + pfAcct + ":group/Admins", AssetType: models.AssetIAMGroup, Name: "Admins"}, admin)
	devs := controlled(models.AssetNode{ARN: "arn:aws:iam::" + pfAcct + ":group/Devs", AssetType: models.AssetIAMGroup, Name: "Devs"})
	assets = append(assets, adminRole, target, victim, group, devs)
	if attacker.AssetType == models.AssetIAMUser {
		rels = append(rels, models.Relationship{SourceARN: attackerARN, TargetARN: devs.ARN, RelType: models.RelMemberOf})
	}
	pol := managed("arn:aws:iam::"+pfAcct+":policy/Customer", `{"Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}`)
	assets = append(assets, pol)
	rels = append(rels, attached(attackerARN, pol), attached(target.ARN, pol))
	// Existing resources that run as AdminRole, for the existing-passrole family.
	fn := models.AssetNode{ARN: "arn:aws:lambda:us-east-1:" + pfAcct + ":function:existing", AssetType: models.AssetLambdaFunction, AccountID: pfAcct,
		Properties: map[string]any{"function_policy_status": "confirmed_absent", "function_policy_evidence": "fixture"}}
	inst := models.AssetNode{ARN: "arn:aws:ec2:us-east-1:" + pfAcct + ":instance/i-0123456789abcdef0", AssetType: models.AssetEC2Instance, AccountID: pfAcct, Properties: map[string]any{}}
	prof := models.AssetNode{ARN: "arn:aws:iam::" + pfAcct + ":instance-profile/P", AssetType: models.AssetInstanceProfile, AccountID: pfAcct, Properties: map[string]any{}}
	taskDef := models.AssetNode{ARN: "arn:aws:ecs:us-east-1:" + pfAcct + ":task-definition/app:1", AssetType: models.AssetECSTaskDefinition, AccountID: pfAcct, Properties: map[string]any{}}
	task := models.AssetNode{ARN: "arn:aws:ecs:us-east-1:" + pfAcct + ":task/cluster/0123456789abcdef", AssetType: models.AssetECSTask, AccountID: pfAcct, Properties: map[string]any{}}
	stack := models.AssetNode{ARN: "arn:aws:cloudformation:us-east-1:" + pfAcct + ":stack/existing/0123", AssetType: models.AssetCloudFormationStack, AccountID: pfAcct, Properties: map[string]any{}}
	project := models.AssetNode{ARN: "arn:aws:codebuild:us-east-1:" + pfAcct + ":project/existing", AssetType: models.AssetCodeBuildProject, AccountID: pfAcct, Properties: map[string]any{}}
	machine := models.AssetNode{ARN: "arn:aws:states:us-east-1:" + pfAcct + ":stateMachine:existing", AssetType: models.AssetStateMachine, AccountID: pfAcct, Properties: map[string]any{}}
	assets = append(assets, fn, inst, prof, taskDef, task, stack, project, machine)
	// One more existing resource of each remaining type, all running as AdminRole.
	var more []models.AssetNode
	for _, t := range models.WorkloadResourceTypes {
		if t == models.AssetCloudFormationStack || t == models.AssetCodeBuildProject || t == models.AssetStateMachine {
			continue
		}
		more = append(more, models.AssetNode{ARN: "arn:aws:fixture:us-east-1:" + pfAcct + ":" + string(t) + "/existing", AssetType: t, AccountID: pfAcct, Properties: map[string]any{}})
	}
	assets = append(assets, more...)
	if m == "norole" {
		rels = append(rels, models.Relationship{SourceARN: fn.ARN, TargetARN: adminRole.ARN, RelType: models.RelLambdaUsesExecutionRole})
	} else {
		rels = append(rels,
			models.Relationship{SourceARN: task.ARN, TargetARN: taskDef.ARN, RelType: models.RelECSTaskUsesTaskDef},
			models.Relationship{SourceARN: taskDef.ARN, TargetARN: adminRole.ARN, RelType: models.RelECSTaskDefUsesTaskRole})
	}
	rels = append(rels,
		models.Relationship{SourceARN: inst.ARN, TargetARN: prof.ARN, RelType: models.RelEC2UsesInstanceProfile})
	if m != "norole" {
		for _, w := range append([]models.AssetNode{stack, project, machine}, more...) {
			rels = append(rels, models.Relationship{SourceARN: w.ARN, TargetARN: adminRole.ARN, RelType: models.RelRunsAsRole})
		}
		rels = append(rels,
			models.Relationship{SourceARN: fn.ARN, TargetARN: adminRole.ARN, RelType: models.RelLambdaUsesExecutionRole},
			models.Relationship{SourceARN: prof.ARN, TargetARN: adminRole.ARN, RelType: models.RelInstanceProfileContains})
	}
	report := AnalyzeIdentityAttack(context.Background(), IdentityAttackRequest{
		ScanID: "audit", InitialPrincipal: attackerARN, SessionSource: "assumed", Assets: assets, Relationships: rels,
	})
	seen := map[string]bool{}
	for _, tr := range report.Transitions {
		if tr.Status != "VALIDATED_ALLOWED" || tr.Cycle {
			continue
		}
		if tr.Technique == "READ_S3_OBJECT" || tr.Technique == "READ_SECRET" {
			continue
		}
		techs = append(techs, tr.Technique)
		for _, l := range pfLabelsFromTech(tr.Technique) {
			seen[l] = true
		}
	}
	for _, e := range report.Escalations {
		techs = append(techs, "ESC:"+e.Technique)
		for _, l := range pfLabelsFromTech(e.Technique) {
			seen[l] = true
		}
	}
	for k := range seen {
		fired = append(fired, k)
	}
	sort.Strings(fired)
	sort.Strings(techs)
	return
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func subset(a, b []string) bool {
	for _, x := range a {
		if !containsStr(b, x) {
			return false
		}
	}
	return true
}

func TestPathfindingBenchmark(t *testing.T) {
	raw, err := os.ReadFile("testdata/pathfinding/paths.json")
	if err != nil {
		t.Fatal(err)
	}
	var paths []pfPath
	if err := json.Unmarshal(raw, &paths); err != nil {
		t.Fatal(err)
	}
	var out []pfCase
	for _, p := range paths {
		want := pfWanted(p, p.Required)
		// Existing-resource families need an asset type the product must model.
		fired, techs := pfRun(p, p.Required, "")
		c := pfCase{ID: p.ID, Variant: "positive", Expect: "exploitable", Fired: fired, Want: want, Techs: techs}
		switch {
		case len(want) > 0 && subset(want, fired):
			c.Outcome = "detected"
		case len(fired) > 0 && len(want) > 0 && anyIn(want, fired):
			c.Outcome = "partial"
		default:
			c.Outcome = "not_detected"
		}
		if len(want) == 0 {
			c.Outcome = "not_detected"
			c.Note = "no AWS-semantic label for these permissions in the harness; judged by whether any validated hop fired"
			if len(fired) > 0 {
				c.Outcome = "detected_by_unrelated_hop"
			}
		}
		out = append(out, c)
		// Negative controls: remove one required permission (by omission, then by explicit Deny).
		for _, drop := range p.Required {
			var rest []string
			for _, r := range p.Required {
				if r != drop {
					rest = append(rest, r)
				}
			}
			ambiguous := false
			for _, q := range paths {
				if q.ID != p.ID && len(q.Required) > 0 && subset(q.Required, rest) {
					ambiguous = true
				}
			}
			for _, kind := range []string{"drop", "deny"} {
				var f, ts []string
				if kind == "drop" {
					f, ts = pfRun(p, rest, "")
				} else {
					f, ts = pfRun(p, p.Required, drop)
				}
				n := pfCase{ID: p.ID, Variant: kind + ":" + drop, Expect: "not_exploitable", Fired: f, Techs: ts}
				if ambiguous {
					n.Expect = "ambiguous"
				}
				if len(f) > 0 {
					n.Outcome = "detected"
				} else {
					n.Outcome = "not_detected"
				}
				out = append(out, n)
			}
		}
		bf, _ := pfRun(p, p.Required, "", "boundary")
		bc := pfCase{ID: p.ID, Variant: "boundary", Expect: "not_exploitable", Fired: bf, Outcome: "not_detected"}
		if len(bf) > 0 {
			bc.Outcome = "detected"
		}
		out = append(out, bc)
		if tk := takeoverPerms(p.Required); len(tk) > 0 && !containsStr(p.Required, "iam:DeleteAccessKey") {
			// The call is allowed by policy but AWS would reject it for the victim's state, or the state is unknown.
			var rest []string
			for _, r := range p.Required {
				if !containsStr(tk, r) {
					rest = append(rest, r)
				}
			}
			ambiguous := false
			for _, q := range paths {
				if q.ID != p.ID && len(q.Required) > 0 && subset(q.Required, rest) {
					ambiguous = true
				}
			}
			for _, mode := range []string{"blocked", "noreport"} {
				f, _ := pfRun(p, p.Required, "", mode)
				c := pfCase{ID: p.ID, Variant: mode, Expect: "not_exploitable", Fired: f, Outcome: "not_detected"}
				if ambiguous {
					c.Expect = "ambiguous"
				}
				if len(f) > 0 {
					c.Outcome = "detected"
				}
				out = append(out, c)
			}
		}
		// A smaller path inside this one's permissions (StartBuild on an existing project, inside CreateProject plus
		// StartBuild) legitimately fires when this path's own mechanism is broken, so those controls cannot judge it.
		inner := false
		for _, q := range paths {
			if q.ID != p.ID && len(q.Required) > 0 && subset(q.Required, p.Required) {
				inner = true
			}
		}
		if workloadPerm(p.Required) {
			// The permissions are held but no collected workload runs as a role, so there is nothing to reach.
			nf, _ := pfRun(p, p.Required, "", "norole")
			nc := pfCase{ID: p.ID, Variant: "norole", Expect: "not_exploitable", Fired: nf, Outcome: "not_detected"}
			if inner {
				nc.Expect = "ambiguous"
			}
			if len(nf) > 0 {
				nc.Outcome = "detected"
			}
			out = append(out, nc)
		}
		if containsStr(p.Required, "iam:PassRole") {
			// A trust policy conditioned on the caller's own account holds for what the service presents; another account's does not.
			cf, _ := pfRun(p, p.Required, "", "condtrust")
			cc := pfCase{ID: p.ID, Variant: "condtrust", Expect: "exploitable", Fired: cf, Want: want, Outcome: "not_detected"}
			if len(want) > 0 && subset(want, cf) {
				cc.Outcome = "detected"
			}
			out = append(out, cc)
			xf, _ := pfRun(p, p.Required, "", "condtrust_wrong")
			xc := pfCase{ID: p.ID, Variant: "condtrust_wrong", Expect: "not_exploitable", Fired: xf, Outcome: "not_detected"}
			if inner {
				xc.Expect = "ambiguous"
			}
			if len(xf) > 0 {
				xc.Outcome = "detected"
			}
			out = append(out, xc)
			wf, _ := pfRun(p, p.Required, "", "wrongtrust")
			wc := pfCase{ID: p.ID, Variant: "wrongtrust", Expect: "not_exploitable", Fired: wf, Outcome: "not_detected"}
			if inner {
				wc.Expect = "ambiguous"
			}
			if len(wf) > 0 {
				wc.Outcome = "detected"
			}
			out = append(out, wc)
		}
		if len(p.Additional) > 0 {
			af, _ := pfRun(p, append(append([]string{}, p.Required...), p.Additional...), "")
			ac := pfCase{ID: p.ID, Variant: "with_additional", Expect: "exploitable", Fired: af, Want: want, Outcome: "not_detected"}
			if len(want) > 0 && subset(want, af) {
				ac.Outcome = "detected"
			}
			out = append(out, ac)
		}
	}
	pfAssert(t, out, paths)
}

// pfFloor is every path the benchmark saw detected with the minimal reference permissions when it was added.
// A path leaving this list is a regression. A path joining it should be added in the same change.
var pfFloor = []string{
	"apprunner-001", "apprunner-002", "batch-001", "batch-002", "batch-003", "bedrock-001", "bedrock-002",
	"bedrock-003", "bedrock-004", "bedrock-005", "bedrock-006", "bedrock-007", "braket-001",
	"cloudformation-001", "cloudformation-002", "cloudformation-003", "cloudformation-004",
	"cloudformation-005", "codebuild-001", "codebuild-002", "codebuild-003", "codebuild-004", "codedeploy-001",
	"cognitoidentity-001", "datapipeline-001", "ec2-001", "ec2-002", "ec2-003", "ec2-005",
	"ec2instanceconnect-003", "ecs-001", "ecs-002", "ecs-003", "ecs-004", "ecs-005", "ecs-006", "ecs-007",
	"ecs-008", "ecs-009", "emr-001", "emrserverless-001", "gamelift-001", "glue-001", "glue-002", "glue-003",
	"glue-004", "glue-005", "glue-006", "glue-007", "iam-001", "iam-002", "iam-003", "iam-004", "iam-005",
	"iam-006", "iam-007", "iam-008", "iam-009", "iam-010", "iam-011", "iam-012", "iam-013", "iam-014",
	"iam-015", "iam-016", "iam-017", "iam-018", "iam-019", "iam-020", "iam-021", "imagebuilder-001",
	"kinesisanalytics-001", "lambda-001", "lambda-002", "lambda-003", "lambda-004", "lambda-005", "lambda-006",
	"omics-001", "sagemaker-001", "sagemaker-002", "sagemaker-003", "sagemaker-004", "sagemaker-005",
	"scheduler-001", "ssm-001", "ssm-002", "ssm-003", "stepfunctions-001", "stepfunctions-002", "sts-001",
}

func pfAssert(t *testing.T, out []pfCase, paths []pfPath) {
	cat := map[string]string{}
	for _, p := range paths {
		cat[p.ID] = p.Cat
	}
	groups := map[string][2]int{} // key -> detected, total
	detected := map[string]bool{}
	var tp, fn, fp, tn int
	for _, c := range out {
		switch {
		case c.Variant == "positive":
			d := c.Outcome == "detected"
			detected[c.ID] = d
			for _, k := range []string{"category " + cat[c.ID], "service " + strings.SplitN(c.ID, "-", 2)[0]} {
				g := groups[k]
				g[1]++
				if d {
					g[0]++
				}
				groups[k] = g
			}
			if d {
				tp++
			} else {
				fn++
			}
		case c.Expect == "not_exploitable":
			if c.Outcome == "detected" {
				fp++
				t.Errorf("false positive: %s (%s) was reported although the path cannot work", c.ID, c.Variant)
			} else {
				tn++
			}
		}
	}
	for _, c := range out {
		if c.Variant == "condtrust" && containsStr(pfFloor, c.ID) && c.Outcome != "detected" {
			t.Errorf("%s: a trust policy conditioned on the caller's account was not matched", c.ID)
		}
	}
	for _, id := range pfFloor {
		if !detected[id] {
			t.Errorf("regression: %s was detected and no longer is", id)
		}
	}
	for id, d := range detected {
		if d && !containsStr(pfFloor, id) {
			t.Errorf("%s is newly detected: add it to pfFloor so it cannot regress", id)
		}
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("  %-32s %2d of %2d detected", k, groups[k][0], groups[k][1])
	}
	var p, r float64
	if tp+fp > 0 {
		p = float64(tp) / float64(tp+fp)
	}
	if tp+fn > 0 {
		r = float64(tp) / float64(tp+fn)
	}
	t.Logf("pathfinding benchmark: %d paths, detected %d, missed %d, false positives %d, true negatives %d; precision %.2f recall %.2f (simulated, minimal reference permissions)", tp+fn, tp, fn, fp, tn, p, r)
	pfCheckReferenceCoverage(t, out, paths, fp, tn, p, r)
}

// pfKeyService maps the service key in a data-driven plan's kind (PASS_ROLE_<KEY>_<n>) to the service name the
// reference uses in its permissions. It is naming only; it says nothing about which paths are exploitable.
func pfKeyService(kind string) string {
	key := strings.SplitN(strings.TrimPrefix(kind, "PASS_ROLE_"), "_", 2)[0]
	m := map[string]string{"APPRUNNER": "apprunner", "BATCH": "batch", "BEDROCK": "bedrock-agentcore", "BRAKET": "braket", "CLOUDFORMATION": "cloudformation",
		"CODEBUILD": "codebuild", "COGNITOIDENTITY": "cognito-identity", "EC2": "ec2", "ECS": "ecs", "EMR": "elasticmapreduce", "EMRSERVERLESS": "emr-serverless",
		"GAMELIFT": "gamelift", "GLUE": "glue", "IMAGEBUILDER": "imagebuilder", "KINESISANALYTICS": "kinesisanalytics", "LAMBDA": "lambda", "OMICS": "omics", "SAGEMAKER": "sagemaker",
		"SCHEDULER": "scheduler", "SSM": "ssm", "STEPFUNCTIONS": "states"}
	if strings.HasPrefix(kind, "PASS_ROLE_GLUE_ENDPOINT") {
		return "glue"
	}
	return m[key]
}

func workloadPerm(req []string) bool {
	for _, r := range req {
		if pfLabel(r, false) == "workload_exec" {
			return true
		}
	}
	return false
}

func takeoverPerms(req []string) []string {
	var out []string
	for _, r := range req {
		switch r {
		case "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile":
			out = append(out, r)
		}
	}
	return out
}

func anyIn(a, b []string) bool {
	for _, x := range a {
		if containsStr(b, x) {
			return true
		}
	}
	return false
}

var pfCategoryName = map[string]string{
	"new-passrole":      "Pass a role to a new resource",
	"existing-passrole": "Use a resource that already exists",
	"principal-access":  "Take over an identity",
	"self-escalation":   "Change your own permissions",
}

// pfCheckReferenceCoverage builds the report the Coverage page shows from this benchmark's own results and
// compares it with the checked-in file. Run with UPDATE_REFERENCE_COVERAGE=1 to rewrite the file.
func pfCheckReferenceCoverage(t *testing.T, out []pfCase, paths []pfPath, fp, tn int, precision, recall float64) {
	t.Helper()
	status := map[string]string{}
	for _, c := range out {
		if c.Variant != "positive" {
			continue
		}
		switch c.Outcome {
		case "detected":
			status[c.ID] = referencecov.Detected
		case "partial":
			status[c.ID] = referencecov.Partial
		default:
			status[c.ID] = referencecov.NotDetected
		}
	}
	rep := referencecov.Report{
		Source: referencecov.Source{
			Name: "pathfinding.cloud", URL: "https://pathfinding.cloud", License: "Apache-2.0 (Datadog Security Labs)",
			Commit: "b3f449e50cb7f06a881a4703237d4ce7be627683", Snapshot: "2026-11-16", AWSRecords: len(paths),
			Excluded: "6 GCP records are not counted: Cloudrift covers AWS only.",
			Method:   "Simulated: a fixture is built from each record's minimal required permissions and checked against the attack search. Not a test on a live account.",
		},
	}
	byCat, bySvc := map[string]*referencecov.Group{}, map[string]*referencecov.Group{}
	bump := func(m map[string]*referencecov.Group, key, name, st string) {
		g := m[key]
		if g == nil {
			g = &referencecov.Group{Key: key, Name: name}
			m[key] = g
		}
		g.Total++
		switch st {
		case referencecov.Detected:
			g.Detected++
		case referencecov.Partial:
			g.Partial++
		default:
			g.NotDetected++
		}
	}
	for _, p := range paths {
		st := status[p.ID]
		svc := strings.SplitN(p.ID, "-", 2)[0]
		reason := ""
		if st != referencecov.Detected {
			reason = "No technique models this path yet."
			if p.Cat == "existing-passrole" {
				reason = "Needs an existing resource the scan does not collect yet. Whether to collect it is a product decision."
			}
			if st == referencecov.Partial {
				reason = "Part of the path is modeled."
			}
		}
		rep.Paths = append(rep.Paths, referencecov.Path{ID: p.ID, Category: p.Cat, Service: svc, Status: st, Required: p.Required, Reason: reason, URL: "https://pathfinding.cloud/paths/" + p.ID})
		bump(byCat, p.Cat, pfCategoryName[p.Cat], st)
		bump(bySvc, svc, svc, st)
		rep.Totals.Paths++
		switch st {
		case referencecov.Detected:
			rep.Totals.Detected++
		case referencecov.Partial:
			rep.Totals.Partial++
		default:
			rep.Totals.NotDetected++
		}
	}
	rep.Totals.FalsePositives, rep.Totals.TrueNegatives = fp, tn
	rep.Totals.Precision, rep.Totals.Recall = float64(int(precision*100+0.5))/100, float64(int(recall*100+0.5))/100
	flatten := func(m map[string]*referencecov.Group) []referencecov.Group {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var res []referencecov.Group
		for _, k := range keys {
			res = append(res, *m[k])
		}
		return res
	}
	rep.Categories, rep.Services = flatten(byCat), flatten(bySvc)
	sort.Slice(rep.Paths, func(i, j int) bool { return rep.Paths[i].ID < rep.Paths[j].ID })
	want, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	want = append(want, '\n')
	file := "../referencecov/reference_coverage.json"
	if os.Getenv("UPDATE_REFERENCE_COVERAGE") == "1" {
		if err := os.WriteFile(file, want, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	have, err := os.ReadFile(file)
	if err != nil || string(have) != string(want) {
		t.Errorf("internal/referencecov/reference_coverage.json is out of date with the benchmark. Run: UPDATE_REFERENCE_COVERAGE=1 go test ./internal/blastradius -run TestPathfindingBenchmark")
	}
}
