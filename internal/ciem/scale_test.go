package ciem

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/Zero0x00/cloudrift/internal/blastradius"
	"github.com/Zero0x00/cloudrift/internal/iamauth"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// TestScaleOfTheScanTimeSearch measures the cost of the work that grows with the number of principals: the scan-time escalation
// search, "who can assume this role", and the role list. It builds a synthetic account and prints timings. It is skipped unless
// CLOUDRIFT_SCALE_USERS is set (for example 5000), so it never slows CI:
//
//	CLOUDRIFT_SCALE_USERS=5000 go test ./internal/ciem -run ScaleOfTheScanTimeSearch -v
func TestScaleOfTheScanTimeSearch(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("CLOUDRIFT_SCALE_USERS"))
	if n == 0 {
		t.Skip("set CLOUDRIFT_SCALE_USERS to measure")
	}
	roles := n / 4
	var nodes []models.AssetNode
	var extraRels []models.Relationship
	for i := 0; i < 5; i++ {
		nodes = append(nodes, escRole(fmt.Sprintf("Admin%d", i), adminDoc, svcTrust("lambda.amazonaws.com")))
	}
	for i := 0; i < roles; i++ {
		doc := readDoc
		if i%10 == 0 { // one in ten can pass an administrative role to a service
			doc = passRoleTo([]string{"Admin0"}, "lambda:CreateFunction", "lambda:InvokeFunction")
		}
		nodes = append(nodes, escRole(fmt.Sprintf("App%d", i), doc, svcTrust("ec2.amazonaws.com")))
	}
	for i := 0; i < n; i++ {
		u := escUser(fmt.Sprintf("user%d", i), i%3 == 0, i%2 == 0)
		nodes = append(nodes, u)
	}
	// Existing resources that run as a role: one stack per tenth role.
	for i := 0; i < roles; i += 10 {
		arn := fmt.Sprintf("arn:aws:cloudformation:us-east-1:%s:stack/s%d/1", escAcct, i)
		nodes = append(nodes, models.AssetNode{ARN: arn, AssetType: models.AssetCloudFormationStack, AccountID: escAcct, Properties: map[string]any{}})
		extraRels = append(extraRels, models.Relationship{SourceARN: arn, TargetARN: fmt.Sprintf("arn:aws:iam::%s:role/App%d", escAcct, i), RelType: models.RelRunsAsRole})
	}
	// Every fiftieth role trusts a tenth of the users, so "who can assume" has real callers.
	assets, rels := withPolicies(nodes)
	rels = append(rels, extraRels...)
	t.Logf("principals: %d users, %d roles; %d assets, %d relationships", n, roles+5, len(assets), len(rels))

	start := time.Now()
	budget := 120 * time.Second // the product default; CLOUDRIFT_SCALE_BUDGET_SECONDS overrides it
	if b, _ := strconv.Atoi(os.Getenv("CLOUDRIFT_SCALE_BUDGET_SECONDS")); b > 0 {
		budget = time.Duration(b) * time.Second
	}
	findings, stats := ScoreEscalations(context.Background(), assets, rels, budget, time.Now())
	t.Logf("ScoreEscalations (budget %s): %s for %d principals (%d searched, %d not reached, %d findings)", budget, time.Since(start).Round(time.Millisecond), stats.Principals, stats.Searched, stats.NotSearched, len(findings))

	target := models.AssetNode{ARN: "arn:aws:iam::" + escAcct + ":role/App0", AssetType: models.AssetIAMRole, AccountID: escAcct}
	for _, a := range assets {
		if a.ARN == target.ARN {
			target = a
		}
	}
	start = time.Now()
	callers, unknown, evaluated := blastradius.WhoCanDetailed("scale", iamauth.ActionAssumeRole, target, assets, rels, time.Time{})
	t.Logf("WhoCanDetailed (one role): %s for %d callers (%d allowed, %d unknown)", time.Since(start).Round(time.Millisecond), evaluated, len(callers), len(unknown))

	start = time.Now()
	items := ListRoles(assets, rels, InventoryFilter{})
	t.Logf("ListRoles: %s for %d roles", time.Since(start).Round(time.Millisecond), len(items))
}
