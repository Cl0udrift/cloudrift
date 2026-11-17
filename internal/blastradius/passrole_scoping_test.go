package blastradius

import (
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func passRoleDoc(target string, statements ...string) string {
	out := `{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"` + target + `"}`
	for _, s := range statements {
		out += "," + s
	}
	return out + "]}"
}

func allowOn(action, resource string) string {
	return `{"Effect":"Allow","Action":"` + action + `","Resource":"` + resource + `"}`
}

func chainFound(caller, target, policy, service, kind string) bool {
	r := analyzeAttack(caller, []models.AssetNode{controlledRole(caller, policy, ""), controlledRole(target, "", serviceTrust(service))}, nil)
	return hasEscalation(r, kind, target)
}

// Each call is checked against the resource type it acts on, so a policy that scopes every call to the right type matches.
func TestPassRoleChainsUseTheResourceTypeOfEachCall(t *testing.T) {
	caller, target := "arn:aws:iam::111111111111:role/A", "arn:aws:iam::111111111111:role/Task"
	ecs := func(cluster, service string) string {
		return passRoleDoc(target, allowOn("ecs:CreateCluster", cluster), allowOn("ecs:CreateService", service), allowOn("ecs:RegisterTaskDefinition", "*"))
	}
	right := ecs("arn:aws:ecs:*:111111111111:cluster/*", "arn:aws:ecs:*:111111111111:service/*/*")
	if !chainFound(caller, target, right, "ecs-tasks.amazonaws.com", "PASS_ROLE_ECS_001") {
		t.Fatal("ECS chain scoped to the right resource types was not found")
	}
	// CreateService scoped to clusters is the wrong type: the call is not allowed, so the chain is not reported.
	wrong := ecs("arn:aws:ecs:*:111111111111:cluster/*", "arn:aws:ecs:*:111111111111:cluster/*")
	if chainFound(caller, target, wrong, "ecs-tasks.amazonaws.com", "PASS_ROLE_ECS_001") {
		t.Fatal("a call scoped to another resource type must not be allowed")
	}
	glue := passRoleDoc(target, allowOn("glue:CreateJob", "arn:aws:glue:*:111111111111:job/*"), allowOn("glue:CreateTrigger", "arn:aws:glue:*:111111111111:trigger/*"))
	if !chainFound(caller, target, glue, "glue.amazonaws.com", "PASS_ROLE_GLUE_004") {
		t.Fatal("Glue chain scoped to job and trigger was not found")
	}
}

// Omics reads the workflow definition from an S3 object the caller chooses, so only the identity policy decides it.
func TestOmicsWorkflowObjectIsDecidedByIdentityPolicy(t *testing.T) {
	caller, target := "arn:aws:iam::111111111111:role/A", "arn:aws:iam::111111111111:role/Run"
	omics := func(get string) string {
		stmts := []string{allowOn("omics:*", "*")}
		if get != "" {
			stmts = append(stmts, allowOn("s3:GetObject", get))
		}
		return passRoleDoc(target, stmts...)
	}
	if !chainFound(caller, target, omics("*"), "omics.amazonaws.com", "PASS_ROLE_OMICS_001") {
		t.Fatal("chain with s3:GetObject allowed was not found")
	}
	if chainFound(caller, target, omics(""), "omics.amazonaws.com", "PASS_ROLE_OMICS_001") {
		t.Fatal("chain without s3:GetObject escalated")
	}
	if chainFound(caller, target, omics("arn:aws:s3:::other-bucket/*"), "omics.amazonaws.com", "PASS_ROLE_OMICS_001") {
		t.Fatal("s3:GetObject scoped to another bucket must not match the probe object")
	}
}

// Unknown hops can fill the transition list; a validated escalation that sorts after them must still be reported.
func TestValidatedHopIsNotDroppedWhenUnknownHopsFillTheList(t *testing.T) {
	caller, target := "arn:aws:iam::111111111111:role/A", "arn:aws:iam::111111111111:role/ZZ"
	assets := []models.AssetNode{controlledRole(caller, passRoleDoc(target, allowOn("ecs:RunTask", "*")), ""), controlledRole(target, "", serviceTrust("ecs-tasks.amazonaws.com"))}
	for i := 0; i < 100; i++ {
		// Roles the caller may not pass: each gives unknown chains that crowd the list before ZZ.
		assets = append(assets, controlledRole("arn:aws:iam::111111111111:role/Filler"+string(rune('A'+i%26))+string(rune('a'+i/26)), "", serviceTrust("ecs-tasks.amazonaws.com")))
	}
	r := analyzeAttack(caller, assets, nil)
	if !hasEscalation(r, "PASS_ROLE_ECS_008", target) {
		t.Fatalf("a validated escalation was dropped; transitions listed: %d, truncated: %v", len(r.Transitions), r.Truncated)
	}
}
