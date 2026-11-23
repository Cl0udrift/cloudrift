package scorers

import (
	"context"
	"strings"
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func probeOf(states map[string]string) BucketProbe {
	return func(_ context.Context, n string) string {
		if s, ok := states[n]; ok {
			return s
		}
		return "exists"
	}
}

func TestBucketNamesInIgnoresWildcardsAndTemplates(t *testing.T) {
	got := map[string]bool{}
	bucketNamesIn(map[string]any{"resource": []string{"arn:aws:s3:::logs-prod/*", "arn:aws:s3:::logs-*", "arn:aws:s3:::${aws:username}", "s3://backup.example/key", "arn:aws:s3:::*"}}, got)
	if len(got) != 2 || !got["logs-prod"] || !got["backup.example"] {
		t.Fatalf("only exact names count: %v", got)
	}
}

func TestUnownedReferencedBucketIsReclaimableAndEdgeIsCritical(t *testing.T) {
	assets := []models.AssetNode{
		{ARN: "arn:aws:s3:::mine", AssetType: models.AssetS3Bucket, Name: "mine", AccountID: "1"},
		{ARN: "arn:aws:cloudfront::1:distribution/D1", AssetType: models.AssetCloudFrontDist, Name: "d1.cloudfront.net", AccountID: "1", Properties: map[string]any{"origins": []string{"gone-site.s3.amazonaws.com", "mine.s3.amazonaws.com"}}},
		{ARN: "arn:aws:iam::1:policy/p/stmt", AssetType: models.AssetIAMPolicyStatement, Name: "s", AccountID: "1", Properties: map[string]any{"resource": []string{"arn:aws:s3:::old-backups/*", "arn:aws:s3:::mine/*", "arn:aws:s3:::still-there/*"}}},
	}
	f := ScoreResourceTakeover(context.Background(), assets, probeOf(map[string]string{"gone-site": "missing", "old-backups": "missing"}), nil)
	if len(f) != 2 {
		t.Fatalf("expected the two missing buckets only, got %d", len(f))
	}
	by := map[string]models.Finding{}
	for _, x := range f {
		by[x.Hostname] = x
	}
	if by["gone-site"].Severity != models.SeverityCritical || by["old-backups"].Severity != models.SeverityHigh {
		t.Fatalf("a distribution origin is critical, a policy reference high: %s %s", by["gone-site"].Severity, by["old-backups"].Severity)
	}
	if by["gone-site"].Claimability != models.ClaimReclaimable || !strings.Contains(by["gone-site"].RemediationCmd, "create-bucket --bucket gone-site") {
		t.Fatalf("finding incomplete: %+v", by["gone-site"])
	}
}

func TestNoBucketProbeMeansNoBucketFindings(t *testing.T) {
	assets := []models.AssetNode{{ARN: "a", AssetType: models.AssetCloudFrontDist, Name: "d", Properties: map[string]any{"origins": []string{"x.s3.amazonaws.com"}}}}
	if f := ScoreResourceTakeover(context.Background(), assets, nil, nil); len(f) != 0 {
		t.Fatal("with probing off, an unchecked name must not become a finding")
	}
}

func TestDeletedCloudFrontOrigin(t *testing.T) {
	assets := []models.AssetNode{{ARN: "arn:aws:cloudfront::1:distribution/D1", AssetType: models.AssetCloudFrontDist, Name: "d1.cloudfront.net", AccountID: "1", Properties: map[string]any{"origins": []string{"old.us-east-1.elasticbeanstalk.com", "ok.example.com"}}}}
	probe := func(_ context.Context, _, target, service string) (string, bool, bool) {
		if service == "elasticbeanstalk" {
			return "target_deleted_elasticbeanstalk", true, true
		}
		return "", false, false
	}
	f := ScoreResourceTakeover(context.Background(), assets, nil, probe)
	if len(f) != 1 || f[0].Claimability != models.ClaimReclaimable || f[0].Evidence["origin"] != "old.us-east-1.elasticbeanstalk.com" {
		t.Fatalf("one reclaimable origin expected: %+v", f)
	}
}

func TestDeletedTrustPrincipalIsLowAndNotATakeover(t *testing.T) {
	role := models.AssetNode{ARN: "arn:aws:iam::1:role/r", AssetType: models.AssetIAMRole, Name: "r", AccountID: "1", Properties: map[string]any{"trust_policy_document": `{"Statement":[{"Principal":{"AWS":"AROAABCDEFGHIJKLMNOP"},"Action":"sts:AssumeRole"}]}`}}
	healthy := models.AssetNode{ARN: "arn:aws:iam::1:role/h", AssetType: models.AssetIAMRole, Name: "h", Properties: map[string]any{"trust_policy_document": `{"Statement":[{"Principal":{"AWS":"arn:aws:iam::1:root"}}]}`}}
	f := ScoreDeletedTrustPrincipals([]models.AssetNode{role, healthy})
	if len(f) != 1 || f[0].Severity != models.SeverityLow || f[0].Claimability != models.ClaimDangling || !strings.Contains(f[0].Impact, "not a takeover") {
		t.Fatalf("expected one Low dangling finding: %+v", f)
	}
}
