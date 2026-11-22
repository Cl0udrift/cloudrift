package collectors

import (
	"context"
	"errors"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/Zero0x00/cloudrift/internal/models"
)

type fakeLive struct {
	keys     map[string][]iamtypes.AccessKeyMetadata
	lastUsed map[string]time.Time
	password map[string]time.Time
	deny     bool
	calls    int
}

func (f *fakeLive) ListAccessKeys(_ context.Context, in *iam.ListAccessKeysInput, _ ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	f.calls++
	if f.deny {
		return nil, errors.New("AccessDenied")
	}
	return &iam.ListAccessKeysOutput{AccessKeyMetadata: f.keys[awsv2.ToString(in.UserName)]}, nil
}

func (f *fakeLive) GetAccessKeyLastUsed(_ context.Context, in *iam.GetAccessKeyLastUsedInput, _ ...func(*iam.Options)) (*iam.GetAccessKeyLastUsedOutput, error) {
	f.calls++
	t := f.lastUsed[awsv2.ToString(in.AccessKeyId)]
	return &iam.GetAccessKeyLastUsedOutput{AccessKeyLastUsed: &iamtypes.AccessKeyLastUsed{LastUsedDate: &t, ServiceName: awsv2.String("ec2")}}, nil
}

func (f *fakeLive) GetUser(_ context.Context, in *iam.GetUserInput, _ ...func(*iam.Options)) (*iam.GetUserOutput, error) {
	f.calls++
	t := f.password[awsv2.ToString(in.UserName)]
	return &iam.GetUserOutput{User: &iamtypes.User{PasswordLastUsed: &t}}, nil
}

func liveUser(name string) models.AssetNode {
	return models.AssetNode{ARN: "arn:aws:iam::1:user/" + name, Name: name, AssetType: models.AssetIAMUser, Properties: map[string]any{
		"credential_report": "collected", "console_enabled": true, "password_last_used": "2026-11-04T16:57:10Z",
		"access_keys": []map[string]any{{"slot": "access_key_1", "active": true, "last_rotated": "2026-11-04T17:04:31Z", "last_used": "2026-11-19T04:35:00Z", "last_service": "s3"}, {"slot": "access_key_2", "active": false}},
	}}
}

func TestLiveLastUsedReplacesAStaleReportValueButNeverLowersOne(t *testing.T) {
	created := time.Date(2026, 11, 4, 17, 4, 31, 0, time.UTC)
	api := &fakeLive{
		keys:     map[string][]iamtypes.AccessKeyMetadata{"u": {{AccessKeyId: awsv2.String("AKIA1"), Status: iamtypes.StatusTypeActive, CreateDate: &created}}},
		lastUsed: map[string]time.Time{"AKIA1": time.Date(2026, 11, 22, 7, 34, 0, 0, time.UTC)},
		password: map[string]time.Time{"u": time.Date(2026, 11, 20, 1, 0, 0, 0, time.UTC)},
	}
	users := []models.AssetNode{liveUser("u")}
	skipped, err := refreshLiveActivity(context.Background(), api, users, 400, time.Date(2026, 11, 22, 8, 0, 0, 0, time.UTC))
	if err != nil || skipped != 0 {
		t.Fatal(err, skipped)
	}
	key := users[0].Properties["access_keys"].([]map[string]any)[0]
	if key["last_used"] != "2026-11-22T07:34:00Z" || key["last_service"] != "ec2" || key["last_used_source"] != "live" {
		t.Fatalf("the live date is newer and must win: %+v", key)
	}
	if users[0].Properties["password_last_used"] != "2026-11-20T01:00:00Z" || users[0].Properties["live_activity_checked_at"] == nil {
		t.Fatalf("%+v", users[0].Properties)
	}

	// A live value older than the report's must not replace it.
	api.lastUsed["AKIA1"] = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	users = []models.AssetNode{liveUser("u")}
	_, _ = refreshLiveActivity(context.Background(), api, users, 400, time.Now())
	if got := users[0].Properties["access_keys"].([]map[string]any)[0]["last_used"]; got != "2026-11-19T04:35:00Z" {
		t.Fatalf("a live date older than the report's must not lower it: %v", got)
	}
}

func TestLiveLastUsedStopsAtTheBudgetAndOnDenial(t *testing.T) {
	api := &fakeLive{keys: map[string][]iamtypes.AccessKeyMetadata{}}
	users := []models.AssetNode{liveUser("a"), liveUser("b"), liveUser("c")}
	skipped, err := refreshLiveActivity(context.Background(), api, users, 4, time.Now()) // one user needs 3 calls
	if err != nil || skipped != 2 {
		t.Fatalf("want 2 users skipped by the budget: %d %v", skipped, err)
	}
	denied := &fakeLive{deny: true}
	users = []models.AssetNode{liveUser("a")}
	if _, err := refreshLiveActivity(context.Background(), denied, users, 400, time.Now()); err == nil {
		t.Fatal("a refused call must be reported so the status says why")
	}
	if got := users[0].Properties["access_keys"].([]map[string]any)[0]["last_used"]; got != "2026-11-19T04:35:00Z" {
		t.Fatalf("the report's value must stay when the live check is refused: %v", got)
	}
}
