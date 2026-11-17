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
	"emr-serverless": {"emr-serverless.amazonaws.com"}, "gamelift": {"gamelift.amazonaws.com"}, "glue": {"glue.amazonaws.com"}, "imagebuilder": {"ec2.amazonaws.com", "imagebuilder.amazonaws.com"},
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
		trust = `{"Statement":[{"Effect":"Allow","Principal":{"Service":[` + strings.Join(ps, ",") + `]},"Action":"sts:AssumeRole"}]}`
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
	victim := controlled(models.AssetNode{ARN: pfUser("victim"), AssetType: models.AssetIAMUser, Name: "victim"})
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
	assets = append(assets, fn, inst, prof)
	rels = append(rels,
		models.Relationship{SourceARN: fn.ARN, TargetARN: adminRole.ARN, RelType: models.RelLambdaUsesExecutionRole},
		models.Relationship{SourceARN: inst.ARN, TargetARN: prof.ARN, RelType: models.RelEC2UsesInstanceProfile},
		models.Relationship{SourceARN: prof.ARN, TargetARN: adminRole.ARN, RelType: models.RelInstanceProfileContains})
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
		if containsStr(p.Required, "iam:PassRole") {
			wf, _ := pfRun(p, p.Required, "", "wrongtrust")
			wc := pfCase{ID: p.ID, Variant: "wrongtrust", Expect: "not_exploitable", Fired: wf, Outcome: "not_detected"}
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
	"cloudformation-001", "datapipeline-001", "lambda-001", "lambda-004", "lambda-006", "sts-001",
	"iam-001", "iam-002", "iam-003", "iam-004", "iam-005", "iam-006", "iam-007", "iam-008", "iam-009", "iam-010", "iam-011",
	"iam-012", "iam-013", "iam-014", "iam-015", "iam-016", "iam-017", "iam-018", "iam-019", "iam-020", "iam-021",
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
}

func anyIn(a, b []string) bool {
	for _, x := range a {
		if containsStr(b, x) {
			return true
		}
	}
	return false
}
