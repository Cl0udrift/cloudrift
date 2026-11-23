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

// trustingRoot trusts the whole account, so the caller still needs its own identity Allow.
func trustingRoot() models.AssetNode {
	n := target()
	n.Properties["trust_policy_document"] = trustAllow("arn:aws:iam::111111111111:root")
	return n
}

// A trust policy that names the user is enough in the same account, even with no assume policy.
func TestNamedTrustNeedsNoIdentityAllow(t *testing.T) {
	assets := []models.AssetNode{ugUserNode(allowDoc("s3:ListAllMyBuckets", "*")), trusting()}
	if !userCanAssume(t, assets, nil) {
		t.Fatal("same-account trust naming the user must allow the assume")
	}
	if userCanAssume(t, []models.AssetNode{ugUserNode(allowDoc("s3:ListAllMyBuckets", "*")), trustingRoot()}, nil) {
		t.Fatal("root trust must still need the caller identity Allow")
	}
}

func TestUserEffectivePolicies(t *testing.T) {
	assume := allowDoc("sts:AssumeRole", ugTarget)
	deny := denyDoc("sts:AssumeRole", ugTarget)
	adminLike := managed("arn:aws:iam::aws:policy/AssumeAll", assume)

	t.Run("group allow plus user inline", func(t *testing.T) {
		// Alice has nothing useful of her own; the group grants the assume.
		assets := []models.AssetNode{ugUserNode(allowDoc("s3:ListAllMyBuckets", "*")), ugGroupNode(assume), trustingRoot()}
		if !userCanAssume(t, assets, []models.Relationship{memberOf()}) {
			t.Fatal("group allow was not inherited by the user")
		}
		if userCanAssume(t, assets, nil) {
			t.Fatal("without membership the group policy must not apply")
		}
	})

	t.Run("managed policy plus inline", func(t *testing.T) {
		user := ugUserNode(allowDoc("s3:ListAllMyBuckets", "*"))
		assets := []models.AssetNode{user, adminLike, trustingRoot()}
		if !userCanAssume(t, assets, []models.Relationship{attached(ugUser, adminLike)}) {
			t.Fatal("attached managed policy was not applied")
		}
	})

	t.Run("inline deny beats an attached allow", func(t *testing.T) {
		user := ugUserNode(deny)
		assets := []models.AssetNode{user, adminLike, trustingRoot()}
		if userCanAssume(t, assets, []models.Relationship{attached(ugUser, adminLike)}) {
			t.Fatal("explicit inline Deny must override the managed Allow")
		}
	})

	t.Run("group allow does not override user deny", func(t *testing.T) {
		assets := []models.AssetNode{ugUserNode(deny), ugGroupNode(assume), trustingRoot()}
		if userCanAssume(t, assets, []models.Relationship{memberOf()}) {
			t.Fatal("user Deny must win over the group Allow")
		}
	})

	t.Run("group deny beats user allow", func(t *testing.T) {
		assets := []models.AssetNode{ugUserNode(assume), ugGroupNode(deny), trustingRoot()}
		if userCanAssume(t, assets, []models.Relationship{memberOf()}) {
			t.Fatal("group Deny must win over the user Allow")
		}
	})

	t.Run("uncollected group is not a silent allow or deny", func(t *testing.T) {
		user := ugUserNode(assume)
		user.Properties["group_membership_complete"] = false
		if userCanAssume(t, []models.AssetNode{user, trustingRoot()}, nil) {
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
	bobNode := credUser(bob, false, 1) // the credential state AWS checks: one key, no console password
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
	if evaluated != 3 { // alice, carol and bob: the target is checked too, for an identity-changing action
		t.Fatalf("evaluated %d", evaluated)
	}
}

func TestWhoCanKeepsTheTargetItselfForIdentityActionsAndSkipsServiceLinkedRoles(t *testing.T) {
	const aliceARN = "arn:aws:iam::111111111111:user/alice"
	alice := ugUserNode(allowDoc("iam:AttachUserPolicy", aliceARN)) // alice may attach policies to herself
	slr := controlled(models.AssetNode{ARN: "arn:aws:iam::111111111111:role/aws-service-role/x.amazonaws.com/AWSServiceRoleForX", AssetType: models.AssetIAMRole, Name: "AWSServiceRoleForX"}, allowDoc("iam:AttachUserPolicy", aliceARN))
	got, evaluated, _ := WhoCan(permScan, "iam:AttachUserPolicy", alice, []models.AssetNode{alice, slr}, nil, time.Time{})
	if len(got) != 1 || got[0].ARN != aliceARN || !got[0].Self {
		t.Fatalf("the target acting on itself must be listed and marked: %#v", got)
	}
	if evaluated != 1 {
		t.Fatalf("a service-linked role is never a caller, so it is not checked: %d", evaluated)
	}
}

func TestWhoCanOnABucketUsesTheCallersPolicyAndTheBucketPolicy(t *testing.T) {
	const bucketARN = "arn:aws:s3:::data"
	bucket := readyBucket(bucketARN) // the object, public-access and encryption evidence the evaluator needs before it will say allowed
	bucket.Name = "data"
	whole := controlled(models.AssetNode{ARN: "arn:aws:iam::111111111111:user/whole", AssetType: models.AssetIAMUser, Name: "whole"}, allowDoc("s3:GetObject", bucketARN+"/*"))
	prefix := controlled(models.AssetNode{ARN: "arn:aws:iam::111111111111:user/prefix", AssetType: models.AssetIAMUser, Name: "prefix"}, allowDoc("s3:GetObject", bucketARN+"/logs/*"))
	none := controlled(models.AssetNode{ARN: "arn:aws:iam::111111111111:user/none", AssetType: models.AssetIAMUser, Name: "none"})
	got, _, evaluated := WhoCanOnResource(permScan, "s3:GetObject", bucket, []models.AssetNode{bucket, whole, prefix, none}, nil, time.Time{})
	if len(got) != 1 || got[0].Name != "whole" || got[0].Status != "VALIDATED_ALLOWED" {
		t.Fatalf("only a caller allowed on every object is listed; prefix-only access is not: %#v", got)
	}
	if evaluated != 3 {
		t.Fatalf("every user and role is checked, not the bucket: %d", evaluated)
	}
	if ResourceTargetTypeFor("s3:PutObject") != models.AssetS3Bucket || ResourceTargetTypeFor("kms:Decrypt") != models.AssetKMSKey || ResourceTargetTypeFor("iam:AttachUserPolicy") != "" {
		t.Fatal("data actions map to bucket, secret and key targets only")
	}
}

func TestWhoCanChainFindsCallersTwoStepsAway(t *testing.T) {
	const roleR = "arn:aws:iam::111111111111:role/R"
	trust := func(principal string) string {
		return `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"` + principal + `"},"Action":"sts:AssumeRole"}]}`
	}
	target := controlledRole(ugTarget, "", trust(roleR))
	middle := controlledRole(roleR, allowDoc("sts:AssumeRole", ugTarget), trust(ugUser))
	alice := ugUserNode(allowDoc("sts:AssumeRole", roleR))
	assets := []models.AssetNode{target, middle, alice}

	direct, _, _ := WhoCanDetailed(permScan, "sts:AssumeRole", target, assets, nil, time.Time{})
	if len(direct) != 1 || direct[0].ARN != roleR {
		t.Fatalf("only R can assume the target in one step: %#v", direct)
	}
	got, truncated := WhoCanChain(permScan, target, assets, nil, time.Time{}, 3, 50)
	if truncated || len(got) != 2 {
		t.Fatalf("R directly and alice through R: %#v truncated=%v", got, truncated)
	}
	by := map[string]schema.RoleAssumer{}
	for _, c := range got {
		by[c.ARN] = c
	}
	if by[roleR].Depth != 1 || by[ugUser].Depth != 2 || len(by[ugUser].Chain) != 3 || by[ugUser].Chain[0] != "alice" {
		t.Fatalf("depth and the identities passed through must be set: %#v", by)
	}
	if _, truncated := WhoCanChain(permScan, target, assets, nil, time.Time{}, 3, 1); !truncated {
		t.Fatal("hitting the expansion bound must be reported")
	}
}

func TestWhoCanOnABucketIsAPlainCanWhenOnlyACLAndPublicAccessEvidenceIsMissing(t *testing.T) {
	const bucketARN = "arn:aws:s3:::data"
	bucket := models.AssetNode{ARN: bucketARN, AssetType: models.AssetS3Bucket, Name: "data", AccountID: "111111111111", Properties: map[string]any{
		"bucket_policy_status": "confirmed_absent", "bucket_policy_evidence": "fixture",
		"object_ownership": "BucketOwnerEnforced", "object_ownership_evidence": "fixture", // ACLs are off; Block Public Access was not collected
	}}
	whole := controlled(models.AssetNode{ARN: "arn:aws:iam::111111111111:user/whole", AssetType: models.AssetIAMUser, Name: "whole"}, allowDoc("s3:GetObject", bucketARN+"/*"))
	none := controlled(models.AssetNode{ARN: "arn:aws:iam::111111111111:user/none", AssetType: models.AssetIAMUser, Name: "none"}, allowDoc("s3:ListAllMyBuckets", "*"))
	got, unknown, _ := WhoCanOnResource(permScan, "s3:GetObject", bucket, []models.AssetNode{bucket, whole, none}, nil, time.Time{})
	if len(got) != 1 || got[0].Name != "whole" || got[0].Status != "VALIDATED_ALLOWED" || got[0].Note != "" {
		t.Fatalf("an identity-policy allow is a plain can with no note, since Block Public Access cannot change it: %#v", got)
	}
	// Block Public Access cannot grant anything, so a caller with no allow is simply not a caller.
	if len(unknown) != 0 {
		t.Fatalf("a caller with no allow is not undecided when only Block Public Access is missing: %#v", unknown)
	}

	// With the ACL setting also missing, an ACL could grant access, so a caller with no allow cannot be ruled out.
	delete(bucket.Properties, "object_ownership")
	delete(bucket.Properties, "object_ownership_evidence")
	got, unknown, _ = WhoCanOnResource(permScan, "s3:GetObject", bucket, []models.AssetNode{bucket, whole, none}, nil, time.Time{})
	if len(got) != 1 || got[0].Status != "VALIDATED_ALLOWED" || len(unknown) != 1 || unknown[0].Name != "none" {
		t.Fatalf("missing ACL evidence: allowed caller still can, caller without allow stays undecided: %#v %#v", got, unknown)
	}
}

func TestAttackSearchSkipsServiceLinkedRolesAndListsOneEscalationPerTarget(t *testing.T) {
	const slr = "arn:aws:iam::111111111111:role/aws-service-role/x.amazonaws.com/AWSServiceRoleForX"
	const normal = "arn:aws:iam::111111111111:role/Normal"
	admin := `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	user := ugUserNode(admin)
	got := attackFrom([]models.AssetNode{user, controlledRole(slr, "", ""), controlledRole(normal, "", "")})
	if hasEscalation(got, "TRUST_REWRITE", slr) || hasEscalation(got, "GRANT_ON_REACHABLE_ROLE", slr) {
		t.Fatalf("AWS does not let anyone rewrite or grant on a service-linked role: %#v", got.Escalations)
	}
	for _, tr := range got.Transitions {
		if tr.TargetARN == slr {
			t.Fatalf("no transition may target a service-linked role: %#v", tr)
		}
	}
	if !hasEscalation(got, "TRUST_REWRITE", normal) {
		t.Fatalf("an ordinary role is still reported: %#v", got.Escalations)
	}

	// AttachGroupPolicy and PutGroupPolicy both enable the same step; it is listed once.
	group := ugGroupNode(admin)
	got = attackFrom([]models.AssetNode{ugUserNode(allowDoc("iam:*", ugGroup)), group}, memberOf())
	n := 0
	for _, e := range got.Escalations {
		if e.Kind == "SELF_POLICY_GRANT" && e.TargetARN == ugGroup {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("one escalation per kind and target, got %d: %#v", n, got.Escalations)
	}
}
