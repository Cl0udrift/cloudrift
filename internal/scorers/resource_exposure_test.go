package scorers

import (
	"testing"

	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func bucketAndPrincipal() []models.AssetNode {
	return []models.AssetNode{
		{ARN: "arn:aws:s3:::data-bucket", AssetType: models.AssetS3Bucket, Name: "data-bucket", AccountID: "111111111111"},
		{ARN: "arn:cloudrift:external-principal:::aws_account/x", AssetType: models.AssetExternalPrincipal, Name: "arn:aws:iam::222222222222:root"},
	}
}

func grantRel(props map[string]any) models.Relationship {
	return models.Relationship{
		SourceARN:  "arn:aws:s3:::data-bucket",
		TargetARN:  "arn:cloudrift:external-principal:::aws_account/x",
		RelType:    models.RelTrusts,
		Properties: props,
	}
}

func TestScoreResourceExposure_Severities(t *testing.T) {
	cfg := config.Default()
	cfg.Trust.ApprovedExternalAccounts = []string{"333333333333"}

	cases := []struct {
		name      string
		props     map[string]any
		wantSev   models.Severity
		wantVerd  string
	}{
		{"public write", map[string]any{"source_kind": "s3_bucket_policy", "is_public": true, "write_access": true}, models.SeverityCritical, "public_write"},
		{"public read", map[string]any{"source_kind": "s3_bucket_policy", "is_public": true}, models.SeverityHigh, "public_read"},
		{"external write", map[string]any{"source_kind": "s3_bucket_policy", "write_access": true, "external_account_id": "222222222222"}, models.SeverityHigh, "external_write"},
		{"external read", map[string]any{"source_kind": "s3_bucket_policy", "external_account_id": "222222222222"}, models.SeverityMedium, "external_read"},
		{"aws elb log delivery", map[string]any{"source_kind": "s3_bucket_policy", "write_access": true, "external_account_id": "127311923021", "actions": []string{"s3:putobject"}}, models.SeverityInfo, "aws_log_delivery"},
		{"aws elb account with broader grant", map[string]any{"source_kind": "s3_bucket_policy", "write_access": true, "external_account_id": "127311923021", "actions": []string{"s3:putobject", "s3:deleteobject"}}, models.SeverityHigh, "external_write"},
		{"approved vendor", map[string]any{"source_kind": "s3_bucket_policy", "external_account_id": "333333333333"}, models.SeverityLow, "approved_vendor_grant"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := ScoreResourceExposure(bucketAndPrincipal(), []models.Relationship{grantRel(tc.props)}, cfg)
			if len(f) != 1 {
				t.Fatalf("expected 1 finding, got %d", len(f))
			}
			if f[0].Severity != tc.wantSev {
				t.Errorf("severity: want %s got %s", tc.wantSev, f[0].Severity)
			}
			if v, _ := f[0].Evidence["verdict"].(string); v != tc.wantVerd {
				t.Errorf("verdict: want %s got %s", tc.wantVerd, v)
			}
			if f[0].Module != models.ModuleExternalAccess {
				t.Errorf("module: want external_access got %s", f[0].Module)
			}
		})
	}
}

func TestScoreResourceExposure_IgnoresNonBucketPolicyRels(t *testing.T) {
	cfg := config.Default()
	// A plain IAM-role trust rel (no source_kind) must not be scored here.
	rel := models.Relationship{
		SourceARN: "arn:aws:iam::111111111111:role/R",
		TargetARN: "arn:cloudrift:external-principal:::aws_account/x",
		RelType:   models.RelTrusts,
	}
	if f := ScoreResourceExposure(bucketAndPrincipal(), []models.Relationship{rel}, cfg); len(f) != 0 {
		t.Fatalf("expected 0 findings for non-bucket-policy rel, got %+v", f)
	}
}
