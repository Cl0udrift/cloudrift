package collectors

import (
	"context"
	"sort"
	"strings"
	"testing"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestIAMInventoryFlagDefaultsOn(t *testing.T) {
	if !config.Default().Scan.IAMPolicyInventory {
		t.Fatal("iam_policy_inventory must default on: permission analysis needs every role's policies")
	}
}

func TestIAMInventory_InternalRoleWithoutExternalTrust(t *testing.T) {
	role := inventoryRole("111111111111", "AppRole", `{"AWS":"arn:aws:iam::111111111111:root"}`)
	nodes, rels, err := collectTrustFromClient(context.Background(), "111111111111", &fakeIAMAPI{
		roles: []iamtypes.Role{role},
		inlinePolicyDocsByName: map[string]string{
			"Read": `{"Statement":[{"Sid":"AllowRead","Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`,
		},
	}, true, make(chan struct{}, 4))
	if err != nil {
		t.Fatal(err)
	}
	assertAssetTypeCount(t, nodes, models.AssetIAMRole, 1)
	assertAssetTypeCount(t, nodes, models.AssetExternalPrincipal, 0)
	if countRel(rels, models.RelTrusts) != 0 {
		t.Fatalf("internal role must not create external-access trust edges: %#v", rels)
	}
	roleNode := findNode(t, nodes, models.AssetIAMRole)
	if roleNode.Properties["path"] == nil || roleNode.AccountID != "111111111111" {
		t.Fatalf("role identity: %#v", roleNode)
	}
	if !strings.Contains(roleNode.Properties["trust_policy_document"].(string), "AssumeRole") {
		t.Fatalf("trust document: %#v", roleNode.Properties["trust_policy_document"])
	}
	if countRel(rels, models.RelPolicyPermissionCandidate) != 1 {
		t.Fatalf("expected one candidate, got %#v", rels)
	}
	for _, n := range nodes {
		if n.ARN == "*" || n.AssetType == models.AssetS3Bucket {
			t.Fatalf("wildcard resource became an asset: %#v", n)
		}
	}
}

func TestIAMInventory_FlagOffSkipsInternalRole(t *testing.T) {
	role := inventoryRole("111111111111", "AppRole", `{"AWS":"arn:aws:iam::111111111111:root"}`)
	nodes, rels, err := collectTrustFromClient(context.Background(), "111111111111", &fakeIAMAPI{
		roles: []iamtypes.Role{role},
	}, false, make(chan struct{}, 4))
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 0 || len(rels) != 0 {
		t.Fatalf("flag off must keep the external-trust filter, got nodes=%d rels=%d", len(nodes), len(rels))
	}
}

func TestIAMInventory_ExternalTrustStillEmitsTrusts(t *testing.T) {
	role := inventoryRole("111111111111", "VendorRole", `{"AWS":"arn:aws:iam::222222222222:root"}`)
	nodes, rels, err := collectTrustFromClient(context.Background(), "111111111111", &fakeIAMAPI{
		roles:               []iamtypes.Role{role},
		attachedPolicyNames: []string{"ReadOnlyAccess"},
		attachedPolicyARNs:  []string{"arn:aws:iam::aws:policy/ReadOnlyAccess"},
		managedDocs: map[string]string{
			"arn:aws:iam::aws:policy/ReadOnlyAccess": `{"Statement":[{"Sid":"Read","Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::data/*"}]}`,
		},
		managedVersions: map[string]string{"arn:aws:iam::aws:policy/ReadOnlyAccess": "v3"},
	}, true, make(chan struct{}, 4))
	if err != nil {
		t.Fatal(err)
	}
	assertAssetTypeCount(t, nodes, models.AssetExternalPrincipal, 1)
	if countRel(rels, models.RelTrusts) != 1 {
		t.Fatalf("external trust: %#v", rels)
	}
	policy := findNode(t, nodes, models.AssetIAMPolicy)
	if policy.Properties["policy_version_id"] != "v3" || policy.Properties["retrieval_status"] != models.PolicyRetrievalOK {
		t.Fatalf("managed policy: %#v", policy.Properties)
	}
	if !strings.Contains(policy.Properties["policy_document"].(string), "s3:GetObject") {
		t.Fatalf("raw document dropped")
	}
}

func TestIAMInventory_InlineAllowDenyAndWildcards(t *testing.T) {
	role := models.AssetNode{ARN: "arn:aws:iam::111111111111:role/App", Name: "App", AccountID: "111111111111"}
	nodes, rels := policyEvidenceGraph(role, []collectedPolicy{
		{
			Name: "Wide", PolicyType: models.PolicyTypeInline, RetrievalStatus: models.PolicyRetrievalOK, AccountID: role.AccountID,
			Document: `{"Statement":[
				{"Sid":"AllowStar","Effect":"Allow","Action":"*","Resource":"*"},
				{"Sid":"DenyWrite","Effect":"Deny","Action":["s3:PutObject","s3:DeleteObject"],"NotResource":"arn:aws:s3:::keep","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"false"}}}
			]}`,
		},
	})
	if countType(nodes, models.AssetIAMPolicyStatement) != 2 {
		t.Fatalf("statements: %#v", nodes)
	}
	allows, denies := 0, 0
	for _, rel := range rels {
		if rel.RelType != models.RelPolicyPermissionCandidate {
			continue
		}
		if rel.Properties["evaluation_status"] != models.EvaluationUnevaluated {
			t.Fatalf("candidate evaluated: %#v", rel.Properties)
		}
		if rel.TargetARN == "*" || strings.Contains(rel.TargetARN, "s3") {
			t.Fatalf("resource expression became the candidate target: %s", rel.TargetARN)
		}
		switch rel.Properties["effect"] {
		case "Allow":
			allows++
			if rel.Properties["action_value"] != "*" || rel.Properties["resource_is_expression_only"] != true {
				t.Fatalf("allow wildcard: %#v", rel.Properties)
			}
		case "Deny":
			denies++
			if rel.Properties["has_condition"] != true {
				t.Fatalf("deny condition: %#v", rel.Properties)
			}
		}
	}
	if allows != 1 || denies != 1 {
		t.Fatalf("allow=%d deny=%d", allows, denies)
	}
	for _, n := range nodes {
		if n.ARN == "*" {
			t.Fatal("wildcard resource was stored as an asset")
		}
	}
}

func TestIAMInventory_NotActionAndConcreteResourceStaysExpression(t *testing.T) {
	role := models.AssetNode{ARN: "arn:aws:iam::111111111111:role/App", Name: "App", AccountID: "111111111111"}
	nodes, rels := policyEvidenceGraph(role, []collectedPolicy{{
		Name: "Except", PolicyType: models.PolicyTypeInline, RetrievalStatus: models.PolicyRetrievalOK,
		Document: `{"Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"arn:aws:s3:::missing-bucket"}]}`,
	}})
	stmt := findNode(t, nodes, models.AssetIAMPolicyStatement)
	actions, _ := stmt.Properties["not_action"].([]string)
	if len(actions) != 1 || actions[0] != "iam:*" {
		t.Fatalf("not action: %#v", stmt.Properties["not_action"])
	}
	var candidate models.Relationship
	for _, rel := range rels {
		if rel.RelType == models.RelPolicyPermissionCandidate {
			candidate = rel
		}
	}
	if candidate.TargetARN != stmt.ARN {
		t.Fatalf("candidate target %s statement %s", candidate.TargetARN, stmt.ARN)
	}
	for _, n := range nodes {
		if n.ARN == "arn:aws:s3:::missing-bucket" {
			t.Fatal("a resource ARN absent from inventory was manufactured as an asset")
		}
	}
}

func TestIAMInventory_MissingAndMalformedDocuments(t *testing.T) {
	role := inventoryRole("111111111111", "AppRole", `{"Service":"ec2.amazonaws.com"}`)
	client := &fakeIAMAPI{
		roles:               []iamtypes.Role{role},
		attachedPolicyNames: []string{"MissingPolicy", "BadPolicy"},
		attachedPolicyARNs: []string{
			"arn:aws:iam::111111111111:policy/MissingPolicy",
			"arn:aws:iam::111111111111:policy/BadPolicy",
		},
		missingManaged: map[string]bool{"arn:aws:iam::111111111111:policy/MissingPolicy": true},
		managedDocs:    map[string]string{"arn:aws:iam::111111111111:policy/BadPolicy": "{not-json"},
		inlinePolicyDocsByName: map[string]string{
			"BrokenInline": "{",
		},
	}
	nodes, rels, err := collectTrustFromClient(context.Background(), "111111111111", client, true, make(chan struct{}, 4))
	if err != nil {
		t.Fatal(err)
	}
	if countType(nodes, models.AssetIAMPolicyStatement) != 0 || countRel(rels, models.RelPolicyPermissionCandidate) != 0 {
		t.Fatal("failed retrieval must not become an empty permission set or invented statements")
	}
	var missing, malformed int
	for _, n := range nodes {
		if n.AssetType != models.AssetIAMPolicy {
			continue
		}
		switch n.Properties["retrieval_status"] {
		case models.PolicyRetrievalMissing:
			missing++
		case models.PolicyRetrievalMalformed:
			malformed++
			if n.Properties["policy_document"] == "" && n.Name == "BadPolicy" {
				t.Fatal("malformed managed document was discarded")
			}
		}
	}
	if missing != 1 || malformed < 1 {
		t.Fatalf("missing=%d malformed=%d nodes=%#v", missing, malformed, nodes)
	}
	roleNode := findNode(t, nodes, models.AssetIAMRole)
	if roleNode.Properties["policy_retrieval_status"] == models.PolicyRetrievalOK || roleNode.Properties["policy_parse_ok"] != false {
		t.Fatalf("role retrieval: %#v", roleNode.Properties)
	}
}

func TestIAMInventory_PaginationAndRepeatedIngestion(t *testing.T) {
	first := inventoryRole("111111111111", "ARole", `{"AWS":"arn:aws:iam::111111111111:root"}`)
	second := inventoryRole("111111111111", "BRole", `{"AWS":"arn:aws:iam::111111111111:root"}`)
	client := &fakeIAMAPI{
		roles:      []iamtypes.Role{first},
		extraRoles: []iamtypes.Role{second},
		inlinePolicyDocsByName: map[string]string{
			"Read": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`,
		},
	}
	nodes, rels, err := collectTrustFromClient(context.Background(), "111111111111", client, true, make(chan struct{}, 4))
	if err != nil {
		t.Fatal(err)
	}
	if countType(nodes, models.AssetIAMRole) != 2 {
		t.Fatalf("pagination dropped a role: %d", countType(nodes, models.AssetIAMRole))
	}
	againClient := &fakeIAMAPI{
		roles:      []iamtypes.Role{first},
		extraRoles: []iamtypes.Role{second},
		inlinePolicyDocsByName: map[string]string{
			"Read": `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`,
		},
	}
	againNodes, againRels, err := collectTrustFromClient(context.Background(), "111111111111", againClient, true, make(chan struct{}, 4))
	if err != nil {
		t.Fatal(err)
	}
	if keysOf(nodes, rels) != keysOf(againNodes, againRels) {
		t.Fatal("repeated collection changed the role or candidate set")
	}
}

func TestIAMInventory_MultiAccount(t *testing.T) {
	old := newIAMClient
	t.Cleanup(func() { newIAMClient = old })
	newIAMClient = func(cfg awsv2.Config) IAMAPI {
		accountID := cfg.Region
		return &fakeIAMAPI{
			roles: []iamtypes.Role{inventoryRole(accountID, "AppRole", `{"AWS":"arn:aws:iam::`+accountID+`:root"}`)},
			inlinePolicyDocsByName: map[string]string{
				"Read": `{"Statement":[{"Effect":"Allow","Action":"ec2:DescribeInstances","Resource":"*"}]}`,
			},
		}
	}
	cfg := defaultCollectorConfig()
	cfg.Scan.IAMPolicyInventory = true
	sessionA := awsv2.Config{Region: "111111111111"}
	sessionB := awsv2.Config{Region: "222222222222"}
	nodes, rels, err := CollectTrustWithConfig(context.Background(), cfg, []Account{
		{ID: "111111111111", Session: &sessionA},
		{ID: "222222222222", Session: &sessionB},
	})
	if err != nil {
		t.Fatal(err)
	}
	if countType(nodes, models.AssetIAMRole) != 2 {
		t.Fatalf("roles: %d", countType(nodes, models.AssetIAMRole))
	}
	seen := map[string]int{}
	for _, n := range nodes {
		if n.AssetType == models.AssetIAMRole {
			seen[n.AccountID]++
		}
	}
	if seen["111111111111"] != 1 || seen["222222222222"] != 1 {
		t.Fatalf("accounts: %#v", seen)
	}
	if countRel(rels, models.RelTrusts) != 0 {
		t.Fatal("same-account trust must not become an external-access relationship")
	}
	if countRel(rels, models.RelPolicyPermissionCandidate) != 2 {
		t.Fatalf("candidates: %d", countRel(rels, models.RelPolicyPermissionCandidate))
	}
}

func inventoryRole(accountID, name, principalJSON string) iamtypes.Role {
	return iamtypes.Role{
		Arn:                      awsv2.String("arn:aws:iam::" + accountID + ":role/" + name),
		RoleName:                 awsv2.String(name),
		Path:                     awsv2.String("/"),
		AssumeRolePolicyDocument: awsv2.String(encodedPolicy(singleStatement(principalJSON))),
	}
}

func countType(nodes []models.AssetNode, assetType models.AssetType) int {
	n := 0
	for _, node := range nodes {
		if node.AssetType == assetType {
			n++
		}
	}
	return n
}

func countRel(rels []models.Relationship, relType models.RelType) int {
	n := 0
	for _, rel := range rels {
		if rel.RelType == relType {
			n++
		}
	}
	return n
}

func findNode(t *testing.T, nodes []models.AssetNode, assetType models.AssetType) models.AssetNode {
	t.Helper()
	for _, n := range nodes {
		if n.AssetType == assetType {
			return n
		}
	}
	t.Fatalf("missing %s", assetType)
	return models.AssetNode{}
}

func keysOf(nodes []models.AssetNode, rels []models.Relationship) string {
	var parts []string
	for _, n := range nodes {
		parts = append(parts, "n:"+n.ARN)
	}
	for _, r := range rels {
		parts = append(parts, "r:"+r.SourceARN+"|"+string(r.RelType)+"|"+r.TargetARN)
	}
	sort.Strings(parts)
	return strings.Join(parts, "\n")
}
