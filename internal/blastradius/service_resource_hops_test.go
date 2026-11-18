package blastradius

import (
	"strings"
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// TestExistingServiceResourceEscalation checks the three resource types that record their role on a WORKLOAD_RUNS_AS_ROLE
// edge: the caller must be allowed every required call on that resource's own ARN.
func TestExistingServiceResourceEscalation(t *testing.T) {
	cases := []struct {
		kind     string
		asset    models.AssetType
		arn      string
		other    string
		allow    []string
		missing  string // dropping this action must remove the escalation
		resource string
	}{
		{"WORKLOAD_CLOUDFORMATION_002", models.AssetCloudFormationStack, "arn:aws:cloudformation:us-east-1:111111111111:stack/app/0001", "arn:aws:cloudformation:us-east-1:111111111111:stack/other/0002", []string{"cloudformation:UpdateStack"}, "cloudformation:UpdateStack", ""},
		{"WORKLOAD_CLOUDFORMATION_005", models.AssetCloudFormationStack, "arn:aws:cloudformation:us-east-1:111111111111:stack/app/0001", "arn:aws:cloudformation:us-east-1:111111111111:stack/other/0002", []string{"cloudformation:CreateChangeSet", "cloudformation:ExecuteChangeSet"}, "cloudformation:ExecuteChangeSet", ""},
		{"WORKLOAD_CODEBUILD_002", models.AssetCodeBuildProject, "arn:aws:codebuild:us-east-1:111111111111:project/app", "arn:aws:codebuild:us-east-1:111111111111:project/other", []string{"codebuild:StartBuild"}, "codebuild:StartBuild", ""},
		{"WORKLOAD_STATES_002", models.AssetStateMachine, "arn:aws:states:us-east-1:111111111111:stateMachine:app", "arn:aws:states:us-east-1:111111111111:stateMachine:other", []string{"states:UpdateStateMachine", "states:StartExecution"}, "states:StartExecution", ""},
	}
	for _, c := range cases {
		t.Run(c.kind, func(t *testing.T) {
			res := models.AssetNode{ARN: c.arn, AssetType: c.asset, AccountID: "111111111111", Properties: map[string]any{}}
			rels := []models.Relationship{{SourceARN: c.arn, TargetARN: wlRole, RelType: models.RelRunsAsRole}}
			policy := func(resource string, actions []string, extra ...string) string {
				var s []string
				for _, a := range actions {
					s = append(s, allowOn(a, resource))
				}
				return `{"Statement":[` + strings.Join(append(s, extra...), ",") + `]}`
			}
			run := func(policy string, rels []models.Relationship) bool {
				assets := []models.AssetNode{controlledRole(wlCaller, policy, ""), controlledRole(wlRole, "", ""), res}
				return hasEscalation(attackWithRels(wlCaller, assets, rels), c.kind, wlRole)
			}
			if !run(policy("*", c.allow), rels) {
				t.Fatal("every required call on the resource must reach its role")
			}
			if !run(policy(c.arn, c.allow), rels) {
				t.Fatal("a policy naming the resource's own ARN must reach its role")
			}
			if run(policy(c.other, c.allow), rels) {
				t.Fatal("a policy for another resource escalated")
			}
			var fewer []string
			for _, a := range c.allow {
				if a != c.missing {
					fewer = append(fewer, a)
				}
			}
			if run(policy("*", fewer), rels) {
				t.Fatalf("without %s the escalation must not appear", c.missing)
			}
			if run(policy("*", c.allow, `{"Effect":"Deny","Action":"`+c.missing+`","Resource":"*"}`), rels) {
				t.Fatal("an explicit Deny escalated")
			}
			if run(policy("*", c.allow), nil) {
				t.Fatal("a resource with no recorded role escalated")
			}
		})
	}
}
