package collectors

import (
	"context"
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestManagedPolicyVersionProvenance(t *testing.T) {
	arn := "arn:aws:iam::aws:policy/ExampleS3"
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`
	verified := fetchManagedPolicy(context.Background(), &fakeIAMAPI{managedDocs: map[string]string{arn: doc}, managedVersions: map[string]string{arn: "v2"}}, arn, "ExampleS3", "111111111111")
	if verified.VersionVerification != models.PolicyVersionVerified || verified.VersionID != "v2" || verified.RetrievalStatus != models.PolicyRetrievalOK {
		t.Fatalf("%+v", verified)
	}
	mismatch := fetchManagedPolicy(context.Background(), &fakeIAMAPI{managedDocs: map[string]string{arn: doc}, managedVersions: map[string]string{arn: "v2"}, returnedVersionID: "v9"}, arn, "ExampleS3", "111111111111")
	if mismatch.VersionVerification != models.PolicyVersionMismatch {
		t.Fatalf("%+v", mismatch)
	}
	flipping := fetchManagedPolicy(context.Background(), &fakeIAMAPI{managedDocs: map[string]string{arn: doc}, defaultVersions: []string{"v1", "v2", "v1", "v2", "v1", "v2"}}, arn, "ExampleS3", "111111111111")
	if flipping.VersionVerification != models.PolicyVersionIndeterminate {
		t.Fatalf("%+v", flipping)
	}
	missing := fetchManagedPolicy(context.Background(), &fakeIAMAPI{missingManaged: map[string]bool{arn: true}}, arn, "ExampleS3", "111111111111")
	if missing.VersionVerification != models.PolicyVersionMissing || missing.RetrievalStatus != models.PolicyRetrievalMissing {
		t.Fatalf("%+v", missing)
	}
}

func TestManagedPolicyCacheConcurrentFetch(t *testing.T) {
	arn := "arn:aws:iam::aws:policy/ExampleS3"
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
	client := &fakeIAMAPI{managedDocs: map[string]string{arn: doc}}
	cache := newManagedPolicyCache()
	done := make(chan collectedPolicy, 8)
	for i := 0; i < 8; i++ {
		go func() {
			done <- cache.get(context.Background(), client, arn, "ExampleS3", "111111111111")
		}()
	}
	for i := 0; i < 8; i++ {
		got := <-done
		if got.VersionVerification != models.PolicyVersionVerified {
			t.Fatalf("%+v", got)
		}
	}
	if calls := client.getPolicyCalls.Load(); calls != 2 {
		t.Fatalf("cache calls %d", calls)
	}
}
