package inventory

import (
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
)

const (
	acct = "111111111111"
	reg  = "us-east-1"
)

func sg(id string, open ...string) models.AssetNode {
	p := map[string]any{}
	if len(open) > 0 {
		p["world_open_ports"] = open
	}
	return models.AssetNode{ARN: "arn:aws:ec2:" + reg + ":" + acct + ":security-group/" + id, AssetType: models.AssetSecurityGroup, Name: id, AccountID: acct, Region: reg, Properties: p}
}
func use(src models.AssetNode, g models.AssetNode) models.Relationship {
	return models.Relationship{SourceARN: src.ARN, TargetARN: g.ARN, RelType: models.RelUsesSecurityGroup}
}

func TestExposureNeedsAWorldOpenRuleNotJustAPublicFlag(t *testing.T) {
	open, closed := sg("sg-open", "tcp/80"), sg("sg-closed")
	lbPub := models.AssetNode{ARN: "arn:lb/pub", AssetType: models.AssetLoadBalancer, Name: "pub", AccountID: acct, Properties: map[string]any{"scheme": "internet-facing"}}
	lbPubClosed := models.AssetNode{ARN: "arn:lb/pubclosed", AssetType: models.AssetLoadBalancer, Name: "pubclosed", AccountID: acct, Properties: map[string]any{"scheme": "internet-facing"}}
	lbInternal := models.AssetNode{ARN: "arn:lb/int", AssetType: models.AssetLoadBalancer, Name: "int", AccountID: acct, Properties: map[string]any{"scheme": "internal"}}
	db := models.AssetNode{ARN: "arn:db", AssetType: models.AssetRDSInstance, Name: "db", AccountID: acct, Properties: map[string]any{"publicly_accessible": true}}
	dbClosed := models.AssetNode{ARN: "arn:dbc", AssetType: models.AssetRDSInstance, Name: "dbc", AccountID: acct, Properties: map[string]any{"publicly_accessible": true}}
	inst := models.AssetNode{ARN: "arn:aws:ec2:" + reg + ":" + acct + ":instance/i-1", AssetType: models.AssetEC2Instance, Name: "i-1", AccountID: acct, Properties: map[string]any{"public_ip": "3.3.3.3"}}
	behind := models.AssetNode{ARN: "arn:aws:ec2:" + reg + ":" + acct + ":instance/i-2", AssetType: models.AssetEC2Instance, Name: "i-2", AccountID: acct, Properties: map[string]any{}}
	noIP := models.AssetNode{ARN: "arn:aws:ec2:" + reg + ":" + acct + ":instance/i-3", AssetType: models.AssetEC2Instance, Name: "i-3", AccountID: acct, Properties: map[string]any{}}
	assets := []models.AssetNode{open, closed, lbPub, lbPubClosed, lbInternal, db, dbClosed, inst, behind, noIP}
	rels := []models.Relationship{use(lbPub, open), use(lbPubClosed, closed), use(lbInternal, open), use(db, open), use(dbClosed, closed), use(inst, open), use(noIP, open),
		{SourceARN: lbPub.ARN, TargetARN: behind.ARN, RelType: models.RelRoutesTo}}
	got := exposureIndex(assets, rels)
	want := map[string]bool{lbPub.ARN: true, db.ARN: true, inst.ARN: true, behind.ARN: true}
	for _, a := range assets {
		if got[a.ARN].Internet != want[a.ARN] {
			t.Errorf("%s: internet=%v want %v (%s)", a.Name, got[a.ARN].Internet, want[a.ARN], got[a.ARN].Detail)
		}
	}
	if got[lbPubClosed.ARN].Kind != "restricted" || got[db.ARN].Kind != "internet" || got[noIP.ARN].Kind != "" {
		t.Errorf("kinds: pubclosed=%q db=%q noIP=%q", got[lbPubClosed.ARN].Kind, got[db.ARN].Kind, got[noIP.ARN].Kind)
	}
	if got[open.ARN].Internet || got[open.ARN].Detail == "" {
		t.Errorf("a security group is described, never marked reachable: %+v", got[open.ARN])
	}
}

func TestOwnerUsesConfiguredKeysCaseInsensitively(t *testing.T) {
	a := models.AssetNode{Properties: map[string]any{"tags": map[string]string{"Team": "payments", "owner": ""}}}
	if got := ownerOf(a, []string{"owner", "team"}); got != "payments" {
		t.Fatalf("an empty owner tag must fall through to team, got %q", got)
	}
	if got := ownerOf(a, nil); got != "" {
		t.Fatalf("no configured keys gives no owner, got %q", got)
	}
}

func TestChangesCountsAddedAndRemovedResources(t *testing.T) {
	mk := func(n string) models.AssetNode {
		return models.AssetNode{ARN: "arn:aws:s3:::" + n, AssetType: models.AssetS3Bucket, Name: n}
	}
	c := Changes("prev", []models.AssetNode{mk("a"), mk("b")}, []models.AssetNode{mk("b"), mk("c"), mk("d")})
	if c.Added != 2 || c.Removed != 1 || len(c.RemovedNames) != 1 || c.RemovedNames[0] != "a" {
		t.Fatalf("got %+v", c)
	}
}

func TestFiltersForInternetFacingOwnerAndNew(t *testing.T) {
	g := sg("sg-open", "tcp/443")
	i1 := models.AssetNode{ARN: "arn:aws:ec2:" + reg + ":" + acct + ":instance/i-1", AssetType: models.AssetEC2Instance, Name: "i-1", AccountID: acct, Region: reg,
		Properties: map[string]any{"public_ip": "1.1.1.1", "tags": map[string]string{"owner": "payments"}}}
	i2 := models.AssetNode{ARN: "arn:aws:ec2:" + reg + ":" + acct + ":instance/i-2", AssetType: models.AssetEC2Instance, Name: "i-2", AccountID: acct, Region: reg, Properties: map[string]any{}}
	assets, rels := []models.AssetNode{g, i1, i2}, []models.Relationship{use(i1, g)}
	names := func(f Filter) []string {
		var out []string
		for _, r := range Build(assets, rels, nil, f) {
			if r.ResourceType == "ec2_instance" {
				out = append(out, r.Name)
			}
		}
		return out
	}
	if got := names(Filter{InternetFacing: true}); len(got) != 1 || got[0] != "i-1" {
		t.Errorf("internet-facing: %v", got)
	}
	if got := names(Filter{OwnerKeys: []string{"owner"}, Owner: "none"}); len(got) != 1 || got[0] != "i-2" {
		t.Errorf("no owner: %v", got)
	}
	if got := names(Filter{PreviousARNs: map[string]bool{i1.ARN: true}, NewResources: true}); len(got) != 1 || got[0] != "i-2" {
		t.Errorf("new since previous: %v", got)
	}
	if got := names(Filter{NewResources: true}); len(got) != 2 && got != nil {
		t.Errorf("with no previous scan nothing can be new: %v", got)
	}
}

func TestSecurityGroupDetailShowsRulesFactsAndWorldFlag(t *testing.T) {
	g := sg("sg-web", "tcp/80")
	g.Properties["group_name"] = "web"
	g.Properties["ingress_rules"] = []any{
		map[string]any{"protocol": "tcp", "ports": "80", "sources": []any{"0.0.0.0/0"}},
		map[string]any{"protocol": "tcp", "ports": "22", "sources": []any{"10.0.0.0/8"}},
	}
	i := models.AssetNode{ARN: "arn:aws:ec2:" + reg + ":" + acct + ":instance/i-1", AssetType: models.AssetEC2Instance, Name: "i-1", AccountID: acct, Region: reg, Properties: map[string]any{}}
	d, ok := Detail("s", g.ARN, []models.AssetNode{g, i}, []models.Relationship{use(i, g)}, nil)
	if !ok || len(d.InboundRules) != 2 || !d.InboundRules[0].World || d.InboundRules[1].World {
		t.Fatalf("rules and the world flag: %+v", d.InboundRules)
	}
	found := map[string]string{}
	for _, f := range d.Facts {
		found[f.Label] = f.Value
	}
	if found["Group name"] != "web" || found["Inbound rules"] != "2" || found["Attached to"] != "1 resource(s)" {
		t.Fatalf("facts: %v", found)
	}
}
