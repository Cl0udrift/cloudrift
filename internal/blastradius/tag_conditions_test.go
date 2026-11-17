package blastradius

import (
	"strings"
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
)

const tgTarget = "arn:aws:iam::111111111111:user/admin"

// taggedUser is a target user whose tags were collected (an empty map means it has none), with a credential report row.
func taggedUser(console bool, keys int, tags map[string]string) models.AssetNode {
	n := credUser(tgTarget, console, keys)
	n.Name = "admin"
	n.Properties["tags_collected"] = true
	if tags != nil {
		n.Properties["tags"] = tags
	}
	return n
}

// keyRotationPolicy is the shape of CloudGoat iam_privesc_by_key_rotation: key management only on users tagged developer=true,
// and the right to tag users.
func keyRotationPolicy(withTagging bool) string {
	stmts := []string{`{"Effect":"Allow","Action":["iam:CreateAccessKey","iam:DeleteAccessKey"],"Resource":"arn:aws:iam::111111111111:user/*","Condition":{"StringEquals":{"aws:ResourceTag/developer":"true"}}}`}
	if withTagging {
		stmts = append(stmts, `{"Effect":"Allow","Action":["iam:TagUser","iam:UntagUser"],"Resource":"arn:aws:iam::111111111111:user/*"}`)
	}
	return `{"Statement":[` + strings.Join(stmts, ",") + `]}`
}

func takeoverHop(doc string, target models.AssetNode) (status, reason string, evidence []string, escalated bool) {
	r := attackFrom([]models.AssetNode{ugUserNode(doc), target})
	for _, tr := range r.Transitions {
		if tr.Technique == "TAKEOVER_USER" && tr.TargetARN == tgTarget {
			status, reason, evidence = tr.Status, tr.Reason, tr.Evidence
		}
	}
	return status, reason, evidence, hasEscalation(r, "USER_TAKEOVER", tgTarget)
}

func TestTagConditionDecidedFromCollectedTags(t *testing.T) {
	// The target has no developer tag today, but the principal may set it: possible after tagging, not validated.
	status, reason, ev, esc := takeoverHop(keyRotationPolicy(true), taggedUser(false, 1, nil))
	if status != "CONDITIONAL" || reason != "satisfiable_by_tagging" || esc {
		t.Fatalf("want CONDITIONAL satisfiable_by_tagging and no validated escalation: %s %s %v", status, reason, esc)
	}
	if !strings.Contains(strings.Join(ev, " "), "developer=true") || !strings.Contains(strings.Join(ev, " "), "iam:TagUser") {
		t.Fatalf("the evidence must name the tag and the tagging permission: %v", ev)
	}
	// Already tagged: the call is allowed now.
	if status, _, _, esc := takeoverHop(keyRotationPolicy(true), taggedUser(false, 1, map[string]string{"developer": "true"})); status != "VALIDATED_ALLOWED" || !esc {
		t.Fatalf("a target that already carries the tag is a validated takeover: %s %v", status, esc)
	}
	// Tagged with another value: still satisfiable by changing it.
	if status, reason, _, _ := takeoverHop(keyRotationPolicy(true), taggedUser(false, 1, map[string]string{"developer": "false"})); status != "CONDITIONAL" || reason != "satisfiable_by_tagging" {
		t.Fatalf("a tag with another value can be changed: %s %s", status, reason)
	}
}

func TestTagConditionWithoutTheRightToTagIsNotSatisfiable(t *testing.T) {
	status, reason, _, esc := takeoverHop(keyRotationPolicy(false), taggedUser(false, 1, nil))
	if reason == "satisfiable_by_tagging" || esc || status == "VALIDATED_ALLOWED" {
		t.Fatalf("without iam:TagUser the tag cannot be set: %s %s %v", status, reason, esc)
	}
	// A principal that may tag only with other keys cannot satisfy a condition on developer.
	scoped := `{"Statement":[` + strings.Split(keyRotationPolicy(false), `"Statement":[`)[1][:len(strings.Split(keyRotationPolicy(false), `"Statement":[`)[1])-2] + `,{"Effect":"Allow","Action":"iam:TagUser","Resource":"*","Condition":{"StringEquals":{"aws:RequestTag/team":"x"}}}]}`
	if _, reason, _, _ := takeoverHop(scoped, taggedUser(false, 1, nil)); reason == "satisfiable_by_tagging" {
		t.Fatal("tagging restricted to another tag key must not satisfy a condition on developer")
	}
}

func TestUnknownTagsStayUnknown(t *testing.T) {
	// An older scan did not collect tags: the condition value is unknown, as before.
	target := credUser(tgTarget, false, 1)
	target.Name = "admin"
	status, reason, _, esc := takeoverHop(keyRotationPolicy(true), target)
	if status != "CONDITIONAL" || reason == "satisfiable_by_tagging" || esc {
		t.Fatalf("uncollected tags must stay a missing-context result: %s %s", status, reason)
	}
}

func TestAbsentTagMeetsANegatedCondition(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":"iam:CreateAccessKey","Resource":"*","Condition":{"StringNotEquals":{"aws:ResourceTag/protected":"true"}}}]}`
	if status, _, _, esc := takeoverHop(doc, taggedUser(false, 1, nil)); status != "VALIDATED_ALLOWED" || !esc {
		t.Fatalf("a target with no protected tag meets StringNotEquals: %s %v", status, esc)
	}
	if status, _, _, _ := takeoverHop(doc, taggedUser(false, 1, map[string]string{"protected": "true"})); status == "VALIDATED_ALLOWED" {
		t.Fatal("a target tagged protected=true must not meet StringNotEquals")
	}
}

func TestTaggingStillHonorsTheCredentialState(t *testing.T) {
	// Two keys held: the takeover needs a deleted key, and DeleteAccessKey is under the same tag condition.
	if _, reason, _, _ := takeoverHop(keyRotationPolicy(true), taggedUser(false, 2, nil)); reason != "satisfiable_by_tagging" {
		t.Fatalf("with DeleteAccessKey also satisfiable by tagging the takeover stays possible: %s", reason)
	}
	noDelete := strings.Replace(keyRotationPolicy(true), `"iam:CreateAccessKey","iam:DeleteAccessKey"`, `"iam:CreateAccessKey"`, 1)
	if status, reason, _, _ := takeoverHop(noDelete, taggedUser(false, 2, nil)); reason != "access_key_limit_reached" || status != "UNKNOWN" {
		t.Fatalf("two keys and no delete must still block: %s %s", status, reason)
	}
	noReport := controlled(models.AssetNode{ARN: tgTarget, AssetType: models.AssetIAMUser, Name: "admin"})
	noReport.Properties["tags_collected"] = true
	if status, reason, _, _ := takeoverHop(keyRotationPolicy(true), noReport); reason != "credential_report_missing" || status != "UNKNOWN" {
		t.Fatalf("a user missing from the credential report must stay UNKNOWN: %s %s", status, reason)
	}
}
