package blastradius

import (
	"context"
	"testing"
	"time"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
)

const (
	ugUser   = "arn:aws:iam::111111111111:user/alice"
	ugGroup  = "arn:aws:iam::111111111111:group/devs"
	ugTarget = "arn:aws:iam::111111111111:role/B"
)

// controlled marks the fixture's other evidence slots as confirmed absent so only
// identity policies decide the result.
func controlled(n models.AssetNode, inline ...string) models.AssetNode {
	n.AccountID = "111111111111"
	n.Properties = map[string]any{
		"inline_policy_documents": inline, "policy_retrieval_status": models.PolicyRetrievalOK,
		"permissions_boundary_status": "confirmed_absent", "permissions_boundary_evidence": "fixture",
		"session_policy_status": "confirmed_absent", "session_policy_evidence": "fixture",
		"scp_status": "confirmed_absent", "scp_evidence": "fixture",
		"rcp_status": "confirmed_absent", "rcp_evidence": "fixture",
	}
	return n
}

func ugUserNode(inline ...string) models.AssetNode {
	return controlled(models.AssetNode{ARN: ugUser, AssetType: models.AssetIAMUser, Name: "alice"}, inline...)
}

func ugGroupNode(inline ...string) models.AssetNode {
	return controlled(models.AssetNode{ARN: ugGroup, AssetType: models.AssetIAMGroup, Name: "devs"}, inline...)
}

func memberOf() models.Relationship {
	return models.Relationship{SourceARN: ugUser, TargetARN: ugGroup, RelType: models.RelMemberOf}
}

func attached(source string, policy models.AssetNode) models.Relationship {
	return models.Relationship{SourceARN: source, TargetARN: policy.ARN, RelType: models.RelPolicyAttachedTo}
}

func managed(arn, doc string) models.AssetNode {
	return models.AssetNode{ARN: arn, AssetType: models.AssetIAMPolicy, Name: arn, Properties: map[string]any{
		"retrieval_status": models.PolicyRetrievalOK, "policy_document": doc,
	}}
}

func userCanAssume(t *testing.T, assets []models.AssetNode, rels []models.Relationship) bool {
	t.Helper()
	report := AnalyzePermissionBlast(PermissionBlastRequest{
		ScanID: permScan, RoleARN: ugUser, AssumedCompromise: true, SessionSource: "assumed",
		Assets: assets, Relationships: rels,
	})
	for _, d := range report.Decisions {
		if d.Action == "sts:AssumeRole" && d.ResourceARN == ugTarget {
			return d.Status == "VALIDATED_ALLOWED"
		}
	}
	return false
}

func target() models.AssetNode {
	return controlled(models.AssetNode{ARN: ugTarget, AssetType: models.AssetIAMRole, Name: "B"})
}

func trusting() models.AssetNode {
	n := target()
	n.Properties["trust_policy_document"] = trustAllow(ugUser)
	return n
}

func TestUserEffectivePolicies(t *testing.T) {
	assume := allowDoc("sts:AssumeRole", ugTarget)
	deny := denyDoc("sts:AssumeRole", ugTarget)
	adminLike := managed("arn:aws:iam::aws:policy/AssumeAll", assume)

	t.Run("group allow plus user inline", func(t *testing.T) {
		// Alice has nothing useful of her own; the group grants the assume.
		assets := []models.AssetNode{ugUserNode(allowDoc("s3:ListAllMyBuckets", "*")), ugGroupNode(assume), trusting()}
		if !userCanAssume(t, assets, []models.Relationship{memberOf()}) {
			t.Fatal("group allow was not inherited by the user")
		}
		if userCanAssume(t, assets, nil) {
			t.Fatal("without membership the group policy must not apply")
		}
	})

	t.Run("managed policy plus inline", func(t *testing.T) {
		user := ugUserNode(allowDoc("s3:ListAllMyBuckets", "*"))
		assets := []models.AssetNode{user, adminLike, trusting()}
		if !userCanAssume(t, assets, []models.Relationship{attached(ugUser, adminLike)}) {
			t.Fatal("attached managed policy was not applied")
		}
	})

	t.Run("inline deny beats an attached allow", func(t *testing.T) {
		user := ugUserNode(deny)
		assets := []models.AssetNode{user, adminLike, trusting()}
		if userCanAssume(t, assets, []models.Relationship{attached(ugUser, adminLike)}) {
			t.Fatal("explicit inline Deny must override the managed Allow")
		}
	})

	t.Run("group allow does not override user deny", func(t *testing.T) {
		assets := []models.AssetNode{ugUserNode(deny), ugGroupNode(assume), trusting()}
		if userCanAssume(t, assets, []models.Relationship{memberOf()}) {
			t.Fatal("user Deny must win over the group Allow")
		}
	})

	t.Run("group deny beats user allow", func(t *testing.T) {
		assets := []models.AssetNode{ugUserNode(assume), ugGroupNode(deny), trusting()}
		if userCanAssume(t, assets, []models.Relationship{memberOf()}) {
			t.Fatal("group Deny must win over the user Allow")
		}
	})

	t.Run("uncollected group is not a silent allow or deny", func(t *testing.T) {
		user := ugUserNode(assume)
		user.Properties["group_membership_complete"] = false
		if userCanAssume(t, []models.AssetNode{user, trusting()}, nil) {
			t.Fatal("a user with an uncollected group must not be validated as allowed")
		}
	})
}

func TestUserAsAttackStart(t *testing.T) {
	assets := []models.AssetNode{ugUserNode(), ugGroupNode(allowDoc("sts:AssumeRole", ugTarget)), trusting()}
	report := AnalyzeIdentityAttack(context.Background(), IdentityAttackRequest{
		ScanID: permScan, InitialPrincipal: ugUser, SessionSource: "assumed",
		Assets: assets, Relationships: []models.Relationship{memberOf()},
	})
	hop := findHop(report, techniqueAssumeRole, ugUser, ugTarget)
	if hop.Feasibility != string(ValidityValidatedPossible) || report.ReachableIdentityCount != 1 {
		t.Fatalf("user did not reach the role through its group: %#v", report.Transitions)
	}
}

func TestRoleAssumers(t *testing.T) {
	assume := allowDoc("sts:AssumeRole", ugTarget)
	assets := []models.AssetNode{
		ugUserNode(), ugGroupNode(assume), trusting(),
		controlled(models.AssetNode{ARN: "arn:aws:iam::111111111111:user/bob", AssetType: models.AssetIAMUser, Name: "bob"}, assume),
		controlled(models.AssetNode{ARN: "arn:aws:iam::111111111111:user/carol", AssetType: models.AssetIAMUser, Name: "carol"}),
	}
	got, evaluated, unknown := RoleAssumers(permScan, assets[2], assets, []models.Relationship{memberOf()}, time.Time{})
	if evaluated != 3 {
		t.Fatalf("evaluated %d, want 3 callers", evaluated)
	}
	// Trust names only alice: bob has the permission but the trust policy does not name him.
	// Carol has no collected policies: she is counted as unknown, not listed and not dropped silently.
	if len(got) != 1 || unknown != 1 || got[0].ARN != ugUser || got[0].Status != "VALIDATED_ALLOWED" {
		t.Fatalf("assumers = %#v", got)
	}
}

func attackFrom(assets []models.AssetNode, rels ...models.Relationship) schema.IdentityAttackReport {
	return AnalyzeIdentityAttack(context.Background(), IdentityAttackRequest{
		ScanID: permScan, InitialPrincipal: ugUser, SessionSource: "assumed", Assets: assets, Relationships: rels,
	})
}

func TestUserTargetedEscalations(t *testing.T) {
	const bob = "arn:aws:iam::111111111111:user/bob"
	bobNode := controlled(models.AssetNode{ARN: bob, AssetType: models.AssetIAMUser, Name: "bob"})
	adminGroup := ugGroupNode(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)

	selfGrant := attackFrom([]models.AssetNode{ugUserNode(allowDoc("iam:AttachUserPolicy", ugUser))})
	if !hasEscalation(selfGrant, "SELF_POLICY_GRANT", ugUser) {
		t.Fatalf("user self grant not found: %#v", selfGrant.Escalations)
	}

	takeover := attackFrom([]models.AssetNode{ugUserNode(allowDoc("iam:CreateAccessKey", bob)), bobNode})
	if !hasEscalation(takeover, "USER_TAKEOVER", bob) || takeover.ReachableIdentityCount != 1 {
		t.Fatalf("takeover: %#v reachable=%d", takeover.Escalations, takeover.ReachableIdentityCount)
	}

	// The group lets its members rewrite the group; alice is a member, so she can grant herself anything.
	viaGroup := attackFrom([]models.AssetNode{ugUserNode(), ugGroupNode(allowDoc("iam:PutGroupPolicy", ugGroup))}, memberOf())
	if !hasEscalation(viaGroup, "SELF_POLICY_GRANT", ugGroup) {
		t.Fatalf("group policy grant not found: %#v", viaGroup.Escalations)
	}
	notMember := attackFrom([]models.AssetNode{ugUserNode(allowDoc("iam:PutGroupPolicy", ugGroup)), ugGroupNode()})
	if len(notMember.Escalations) != 0 {
		t.Fatalf("a group the user is not in is a hop, not an escalation: %#v", notMember.Escalations)
	}

	join := attackFrom([]models.AssetNode{ugUserNode(allowDoc("iam:AddUserToGroup", ugGroup)), adminGroup})
	if !hasEscalation(join, "SELF_GROUP_JOIN", ugGroup) {
		t.Fatalf("join admin group not found: %#v", join.Escalations)
	}
	plain := attackFrom([]models.AssetNode{ugUserNode(allowDoc("iam:AddUserToGroup", ugGroup)), ugGroupNode(allowDoc("s3:ListAllMyBuckets", "*"))})
	if len(plain.Escalations) != 0 {
		t.Fatalf("joining a harmless group is not an escalation: %#v", plain.Escalations)
	}

	denied := attackFrom([]models.AssetNode{ugUserNode(allowDoc("iam:CreateAccessKey", bob), denyDoc("iam:CreateAccessKey", bob)), bobNode})
	if len(denied.Escalations) != 0 {
		t.Fatalf("an explicit Deny must block the takeover: %#v", denied.Escalations)
	}
}

func TestRoleAssumersPendingOrgControls(t *testing.T) {
	alice := ugUserNode(allowDoc("sts:AssumeRole", ugTarget))
	delete(alice.Properties, "scp_status")
	delete(alice.Properties, "scp_evidence")
	got, _, _ := RoleAssumers(permScan, trusting(), []models.AssetNode{alice, trusting()}, nil, time.Time{})
	if len(got) != 1 || got[0].Status != StatusPendingControls {
		t.Fatalf("a caller allowed by policies but with SCPs not collected must be pending, got %#v", got)
	}
}

func TestWhoCanIdentityOnlyAction(t *testing.T) {
	const bobARN = "arn:aws:iam::111111111111:user/bob"
	bob := controlled(models.AssetNode{ARN: bobARN, AssetType: models.AssetIAMUser, Name: "bob"})
	assets := []models.AssetNode{
		ugUserNode(allowDoc("iam:AttachUserPolicy", bobARN)), // alice may attach policies to bob
		bob,
		controlled(models.AssetNode{ARN: "arn:aws:iam::111111111111:user/carol", AssetType: models.AssetIAMUser, Name: "carol"}, allowDoc("s3:ListAllMyBuckets", "*")),
	}
	got, evaluated, _ := WhoCan(permScan, "iam:AttachUserPolicy", bob, assets, nil, time.Time{})
	if len(got) != 1 || got[0].ARN != ugUser || got[0].Status != "VALIDATED_ALLOWED" {
		t.Fatalf("only alice can attach policies to bob: %#v", got)
	}
	if evaluated != 2 { // alice and carol; bob is the target
		t.Fatalf("evaluated %d", evaluated)
	}
}
