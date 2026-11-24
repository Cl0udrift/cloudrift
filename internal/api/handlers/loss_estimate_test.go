package handlers

import (
	"testing"

	"github.com/Zero0x00/cloudrift/internal/business"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func lossSettings() business.Loss {
	return business.Loss{
		Currency:           "USD",
		StoreCost:          business.Range{Low: 100000, High: 400000},
		HostnameCost:       business.Range{Low: 10000, High: 50000},
		LikelihoodCritical: business.Range{Low: 0.2, High: 0.5},
		LikelihoodHigh:     business.Range{Low: 0.05, High: 0.2},
	}
}

func store(acct, name string, t models.AssetType) models.AssetNode {
	return models.AssetNode{ARN: "arn:" + name, AssetType: t, Name: name, AccountID: acct}
}

func TestNoMoneyUntilTheValuesAreEntered(t *testing.T) {
	f := []models.Finding{idf("1", "arn:user/a", "a", "user_administrative_access", models.SeverityHigh)}
	est, per := estimateLoss(f, nil, business.Defaults().Loss)
	if est.Configured || est.High != 0 || len(per) != 0 {
		t.Fatalf("nothing may be estimated without the customer's values: %+v", est)
	}
}

func TestAdministratorLossIsLikelihoodTimesWhatItCanReachAsARange(t *testing.T) {
	f := models.Finding{ID: "1", Title: "t", Severity: models.SeverityHigh, Hostname: "alice", AccountID: "111111111111", AffectedARN: "arn:user/alice",
		Evidence: map[string]any{"issue_category": "user_administrative_access"}}
	assets := []models.AssetNode{store("111111111111", "b1", models.AssetS3Bucket), store("111111111111", "db", models.AssetRDSInstance), store("999999999999", "other", models.AssetS3Bucket)}
	est, per := estimateLoss([]models.Finding{f}, assets, lossSettings())
	// two stores in the account: impact 200k to 800k; a high finding: 5% to 20% a year.
	if est.Low != 10000 || est.High != 160000 {
		t.Fatalf("expected 10,000 to 160,000, got %v to %v", est.Low, est.High)
	}
	if r := per["arn:user/alice"]; r.low != 10000 || r.high != 160000 || est.Items[0].Why != "2 data stores in the account" {
		t.Fatalf("per identity: %+v %+v", r, est.Items)
	}
}

func TestWhatItCannotValueIsCountedNotGuessed(t *testing.T) {
	noStores := models.Finding{ID: "1", Severity: models.SeverityHigh, AccountID: "111111111111", AffectedARN: "arn:user/a", Evidence: map[string]any{"issue_category": "user_administrative_access"}}
	mfa := models.Finding{ID: "2", Severity: models.SeverityHigh, AccountID: "111111111111", AffectedARN: "arn:user/b", Evidence: map[string]any{"issue_category": "user_console_without_mfa"}}
	est, _ := estimateLoss([]models.Finding{noStores, mfa}, nil, lossSettings())
	if est.High != 0 || est.NotEstimated != 2 {
		t.Fatalf("an admin with no data stores found, and a finding with no known reach, are not valued: %+v", est)
	}
}

func TestTakeoverAndPublicBucketUseTheirOwnValue(t *testing.T) {
	take := models.Finding{ID: "1", Severity: models.SeverityHigh, Module: models.ModuleOrphanedEdge, Claimability: models.ClaimReclaimable, AccountID: "1", AffectedARN: "arn:dns/x", Hostname: "x.example.com"}
	pub := models.Finding{ID: "2", Severity: models.SeverityCritical, AccountID: "1", AffectedARN: "arn:s3:::b", Evidence: map[string]any{"is_public": true, "resource_type": "s3_bucket"}}
	est, per := estimateLoss([]models.Finding{take, pub}, nil, lossSettings())
	if r := per["arn:dns/x"]; r.low != 500 || r.high != 10000 {
		t.Fatalf("hostname: 10k to 50k at 5%% to 20%%: %+v", r)
	}
	if r := per["arn:s3:::b"]; r.low != 20000 || r.high != 200000 {
		t.Fatalf("bucket: 100k to 400k at 20%% to 50%%: %+v", r)
	}
	if est.Low != 20500 || est.High != 210000 {
		t.Fatalf("total: %+v", est)
	}
}
