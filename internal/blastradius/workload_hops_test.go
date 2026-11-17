package blastradius

import (
	"strings"
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
)

const (
	wlCaller = "arn:aws:iam::111111111111:role/A"
	wlRole   = "arn:aws:iam::111111111111:role/AppRole"
	wlProf   = "arn:aws:iam::111111111111:instance-profile/App"
)

func wlInstance(id string) (models.AssetNode, []models.Relationship) {
	arn := "arn:aws:ec2:us-east-1:111111111111:instance/" + id
	return models.AssetNode{ARN: arn, AssetType: models.AssetEC2Instance, AccountID: "111111111111", Properties: map[string]any{}},
		[]models.Relationship{{SourceARN: arn, TargetARN: wlProf, RelType: models.RelEC2UsesInstanceProfile}}
}

func wlProfile() (models.AssetNode, models.Relationship) {
	return models.AssetNode{ARN: wlProf, AssetType: models.AssetInstanceProfile, AccountID: "111111111111", Properties: map[string]any{}},
		models.Relationship{SourceARN: wlProf, TargetARN: wlRole, RelType: models.RelInstanceProfileContains}
}

func TestEC2WorkloadEscalation(t *testing.T) {
	i1, r1 := wlInstance("i-0000000000000001")
	i2, r2 := wlInstance("i-0000000000000002")
	prof, pr := wlProfile()
	rels := append(append(r1, r2...), pr)
	assets := func(policy string) []models.AssetNode {
		return []models.AssetNode{controlledRole(wlCaller, policy, ""), controlledRole(wlRole, "", ""), i1, i2, prof}
	}
	on := func(arn string) string { return allowOn("ssm:SendCommand", arn) }
	policy := func(stmts ...string) string { return `{"Statement":[` + strings.Join(stmts, ",") + `]}` }

	r := attackWithRels(wlCaller, assets(policy(on("*"))), rels)
	if !hasEscalation(r, "WORKLOAD_SSM_002", wlRole) {
		t.Fatalf("SendCommand on every instance must reach the role: %#v", r.Escalations)
	}
	said := false
	for _, tr := range r.Transitions {
		for _, e := range tr.Evidence {
			if strings.Contains(e, "not verified: the SSM agent") {
				said = true
			}
		}
	}
	if !said {
		t.Fatal("the unverified SSM agent precondition must be in the evidence")
	}

	// Two instances run as the role and only the second is allowed: the hop must be reported as allowed, not hidden
	// behind the first (not allowed) instance.
	second := policy(on(i2.ARN))
	r = attackWithRels(wlCaller, assets(second), rels)
	if !hasEscalation(r, "WORKLOAD_SSM_002", wlRole) {
		t.Fatal("an allowed second instance must be found")
	}
	for _, tr := range r.Transitions {
		if tr.Technique == "WORKLOAD_SSM_002" && tr.TargetARN == wlRole && tr.Status != "VALIDATED_ALLOWED" {
			t.Fatalf("transition shows %s although one instance is allowed", tr.Status)
		}
	}

	if r := attackWithRels(wlCaller, assets(policy(on("arn:aws:ec2:us-east-1:111111111111:instance/i-9999999999999999"))), rels); hasEscalation(r, "WORKLOAD_SSM_002", wlRole) {
		t.Fatal("a policy for another instance escalated")
	}
	if r := attackWithRels(wlCaller, assets(policy(on("*"), `{"Effect":"Deny","Action":"ssm:SendCommand","Resource":"*"}`)), rels); hasEscalation(r, "WORKLOAD_SSM_002", wlRole) {
		t.Fatal("an explicit Deny escalated")
	}
	// No instance profile relationship: the instance runs as no collected role.
	if r := attackWithRels(wlCaller, assets(policy(on("*"))), nil); hasEscalation(r, "WORKLOAD_SSM_002", wlRole) {
		t.Fatal("an instance with no known role escalated")
	}
	// ec2-002 needs all three calls.
	three := policy(allowOn("ec2:ModifyInstanceAttribute", "*"), allowOn("ec2:StartInstances", "*"), allowOn("ec2:StopInstances", "*"))
	if r := attackWithRels(wlCaller, assets(three), rels); !hasEscalation(r, "WORKLOAD_EC2_002", wlRole) {
		t.Fatal("modify, start and stop must reach the role")
	}
	two := policy(allowOn("ec2:ModifyInstanceAttribute", "*"), allowOn("ec2:StartInstances", "*"))
	if r := attackWithRels(wlCaller, assets(two), rels); hasEscalation(r, "WORKLOAD_EC2_002", wlRole) {
		t.Fatal("ec2-002 escalated without StopInstances")
	}
}

func TestECSTaskEscalation(t *testing.T) {
	def := models.AssetNode{ARN: "arn:aws:ecs:us-east-1:111111111111:task-definition/app:1", AssetType: models.AssetECSTaskDefinition, AccountID: "111111111111", Properties: map[string]any{}}
	task := models.AssetNode{ARN: "arn:aws:ecs:us-east-1:111111111111:task/c/abc", AssetType: models.AssetECSTask, AccountID: "111111111111", Properties: map[string]any{}}
	rels := []models.Relationship{
		{SourceARN: task.ARN, TargetARN: def.ARN, RelType: models.RelECSTaskUsesTaskDef},
		{SourceARN: def.ARN, TargetARN: wlRole, RelType: models.RelECSTaskDefUsesTaskRole},
	}
	assets := func(policy string) []models.AssetNode {
		return []models.AssetNode{controlledRole(wlCaller, policy, ""), controlledRole(wlRole, "", ""), def, task}
	}
	both := `{"Statement":[` + allowOn("ecs:DescribeTasks", "*") + `,` + allowOn("ecs:ExecuteCommand", "*") + `]}`
	if r := attackWithRels(wlCaller, assets(both), rels); !hasEscalation(r, "WORKLOAD_ECS_006", wlRole) {
		t.Fatal("ECS Exec on the task must reach the task role")
	}
	if r := attackWithRels(wlCaller, assets(allowDoc("ecs:ExecuteCommand", "*")), rels); hasEscalation(r, "WORKLOAD_ECS_006", wlRole) {
		t.Fatal("ExecuteCommand without DescribeTasks escalated")
	}
	if r := attackWithRels(wlCaller, assets(both), nil); hasEscalation(r, "WORKLOAD_ECS_006", wlRole) {
		t.Fatal("a task with no known task role escalated")
	}
}
