package collectors

import (
	"context"
	"sort"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestCollectActivity_RecentlyUsedRole(t *testing.T) {
	now := time.Date(2026, 4, 18, 0, 0, 0, 0, time.UTC)
	restoreNow := setActivityNow(now)
	defer restoreNow()

	c := fakeActivityIAM{
		listRoles: []iamtypes.Role{
			{Arn: awsv2.String("arn:aws:iam::111111111111:role/Recent"), RoleName: awsv2.String("Recent")},
		},
		getRoleByName: map[string]iamtypes.Role{
			"Recent": {
				Arn:      awsv2.String("arn:aws:iam::111111111111:role/Recent"),
				RoleName: awsv2.String("Recent"),
				RoleLastUsed: &iamtypes.RoleLastUsed{
					LastUsedDate: awsv2.Time(now.AddDate(0, 0, -7)),
				},
			},
		},
	}

	results, err := collectActivityFromClient(context.Background(), "111111111111", &c, make(chan struct{}, 4))
	if err != nil {
		t.Fatalf("collectActivityFromClient error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 activity result, got %d", len(results))
	}
	if results[0].DaysSinceUsed != 7 {
		t.Fatalf("expected days_since_used=7, got %d", results[0].DaysSinceUsed)
	}
}

func TestCollectActivity_AgingRole(t *testing.T) {
	now := time.Date(2026, 4, 18, 0, 0, 0, 0, time.UTC)
	restoreNow := setActivityNow(now)
	defer restoreNow()

	c := fakeActivityIAM{
		listRoles: []iamtypes.Role{
			{Arn: awsv2.String("arn:aws:iam::111111111111:role/Aging"), RoleName: awsv2.String("Aging")},
		},
		getRoleByName: map[string]iamtypes.Role{
			"Aging": {
				Arn:      awsv2.String("arn:aws:iam::111111111111:role/Aging"),
				RoleName: awsv2.String("Aging"),
				RoleLastUsed: &iamtypes.RoleLastUsed{
					LastUsedDate: awsv2.Time(now.AddDate(0, 0, -120)),
				},
			},
		},
	}

	results, err := collectActivityFromClient(context.Background(), "111111111111", &c, make(chan struct{}, 4))
	if err != nil {
		t.Fatalf("collectActivityFromClient error: %v", err)
	}
	if results[0].DaysSinceUsed != 120 {
		t.Fatalf("expected days_since_used=120, got %d", results[0].DaysSinceUsed)
	}
}

func TestCollectActivity_StaleRole(t *testing.T) {
	now := time.Date(2026, 4, 18, 0, 0, 0, 0, time.UTC)
	restoreNow := setActivityNow(now)
	defer restoreNow()

	c := fakeActivityIAM{
		listRoles: []iamtypes.Role{
			{Arn: awsv2.String("arn:aws:iam::111111111111:role/Stale"), RoleName: awsv2.String("Stale")},
		},
		getRoleByName: map[string]iamtypes.Role{
			"Stale": {
				Arn:      awsv2.String("arn:aws:iam::111111111111:role/Stale"),
				RoleName: awsv2.String("Stale"),
				RoleLastUsed: &iamtypes.RoleLastUsed{
					LastUsedDate: awsv2.Time(now.AddDate(0, 0, -400)),
				},
			},
		},
	}

	results, err := collectActivityFromClient(context.Background(), "111111111111", &c, make(chan struct{}, 4))
	if err != nil {
		t.Fatalf("collectActivityFromClient error: %v", err)
	}
	if results[0].DaysSinceUsed != 400 {
		t.Fatalf("expected days_since_used=400, got %d", results[0].DaysSinceUsed)
	}
}

func TestCollectActivity_NeverUsedRole(t *testing.T) {
	c := fakeActivityIAM{
		listRoles: []iamtypes.Role{
			{Arn: awsv2.String("arn:aws:iam::111111111111:role/Never"), RoleName: awsv2.String("Never")},
		},
		getRoleByName: map[string]iamtypes.Role{
			"Never": {
				Arn:          awsv2.String("arn:aws:iam::111111111111:role/Never"),
				RoleName:     awsv2.String("Never"),
				RoleLastUsed: nil,
			},
		},
	}

	results, err := collectActivityFromClient(context.Background(), "111111111111", &c, make(chan struct{}, 4))
	if err != nil {
		t.Fatalf("collectActivityFromClient error: %v", err)
	}
	if results[0].DaysSinceUsed != -1 {
		t.Fatalf("expected days_since_used=-1, got %d", results[0].DaysSinceUsed)
	}
}

func TestCollectActivity_NilLastUsedDateHandledSafely(t *testing.T) {
	c := fakeActivityIAM{
		listRoles: []iamtypes.Role{
			{Arn: awsv2.String("arn:aws:iam::111111111111:role/NilDate"), RoleName: awsv2.String("NilDate")},
		},
		getRoleByName: map[string]iamtypes.Role{
			"NilDate": {
				Arn:      awsv2.String("arn:aws:iam::111111111111:role/NilDate"),
				RoleName: awsv2.String("NilDate"),
				RoleLastUsed: &iamtypes.RoleLastUsed{
					LastUsedDate: nil,
				},
			},
		},
	}

	results, err := collectActivityFromClient(context.Background(), "111111111111", &c, make(chan struct{}, 4))
	if err != nil {
		t.Fatalf("collectActivityFromClient error: %v", err)
	}
	if results[0].DaysSinceUsed != -1 {
		t.Fatalf("expected days_since_used=-1 for nil LastUsedDate, got %d", results[0].DaysSinceUsed)
	}
}

func TestCollectActivityWithConfig_DeterministicSortedOutput(t *testing.T) {
	oldFactory := newIAMActivityClient
	t.Cleanup(func() { newIAMActivityClient = oldFactory })

	now := time.Date(2026, 4, 18, 0, 0, 0, 0, time.UTC)
	restoreNow := setActivityNow(now)
	defer restoreNow()

	newIAMActivityClient = func(cfg awsv2.Config) IAMActivityAPI {
		return &fakeActivityIAM{
			listRoles: []iamtypes.Role{
				{Arn: awsv2.String("arn:aws:iam::111111111111:role/ZRole"), RoleName: awsv2.String("ZRole")},
				{Arn: awsv2.String("arn:aws:iam::111111111111:role/ARole"), RoleName: awsv2.String("ARole")},
			},
			getRoleByName: map[string]iamtypes.Role{
				"ARole": {
					Arn:      awsv2.String("arn:aws:iam::111111111111:role/ARole"),
					RoleName: awsv2.String("ARole"),
					RoleLastUsed: &iamtypes.RoleLastUsed{
						LastUsedDate: awsv2.Time(now.AddDate(0, 0, -10)),
					},
				},
				"ZRole": {
					Arn:      awsv2.String("arn:aws:iam::111111111111:role/ZRole"),
					RoleName: awsv2.String("ZRole"),
					RoleLastUsed: &iamtypes.RoleLastUsed{
						LastUsedDate: awsv2.Time(now.AddDate(0, 0, -20)),
					},
				},
			},
		}
	}

	cfg := config.Default()
	cfg.Scan.RoleAssumptionConcurrency = 2
	sessionCfg := awsv2.Config{Region: "us-east-1"}
	out, err := CollectActivityWithConfig(context.Background(), cfg, []Account{
		{ID: "111111111111", Session: &sessionCfg},
	})
	if err != nil {
		t.Fatalf("CollectActivityWithConfig error: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 activity records, got %d", len(out))
	}

	sorted := make([]string, 0, len(out))
	for _, r := range out {
		sorted = append(sorted, r.RoleARN)
	}
	if !sort.StringsAreSorted(sorted) {
		t.Fatalf("expected sorted output by RoleARN, got %v", sorted)
	}
}

type fakeActivityIAM struct {
	listRoles     []iamtypes.Role
	getRoleByName map[string]iamtypes.Role
}

func (f *fakeActivityIAM) ListRoles(_ context.Context, _ *iam.ListRolesInput, _ ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	return &iam.ListRolesOutput{
		Roles:       f.listRoles,
		IsTruncated: false,
	}, nil
}

func (f *fakeActivityIAM) GetRole(_ context.Context, in *iam.GetRoleInput, _ ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	role, ok := f.getRoleByName[awsv2.ToString(in.RoleName)]
	if !ok {
		return &iam.GetRoleOutput{}, nil
	}
	return &iam.GetRoleOutput{Role: &role}, nil
}


func TestCollectActivityRecordsIAMReportedStatus(t *testing.T) {
	now := time.Date(2026, 4, 18, 0, 0, 0, 0, time.UTC)
	defer setActivityNow(now)()
	arn := func(n string) *string { return awsv2.String("arn:aws:iam::111111111111:role/" + n) }
	c := fakeActivityIAM{
		listRoles: []iamtypes.Role{{Arn: arn("Used"), RoleName: awsv2.String("Used")}, {Arn: arn("Idle"), RoleName: awsv2.String("Idle")}, {Arn: arn("NoField"), RoleName: awsv2.String("NoField")}},
		getRoleByName: map[string]iamtypes.Role{
			"Used":    {Arn: arn("Used"), RoleName: awsv2.String("Used"), RoleLastUsed: &iamtypes.RoleLastUsed{LastUsedDate: awsv2.Time(now.AddDate(0, 0, -3)), Region: awsv2.String("us-east-1")}},
			"Idle":    {Arn: arn("Idle"), RoleName: awsv2.String("Idle"), RoleLastUsed: &iamtypes.RoleLastUsed{}},
			"NoField": {Arn: arn("NoField"), RoleName: awsv2.String("NoField")},
		},
	}
	rows, err := collectActivityFromClient(context.Background(), "111111111111", &c, make(chan struct{}, 4))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]RoleActivity{}
	for _, r := range rows {
		got[r.RoleName] = r
	}
	if got["Used"].Status != ActivityUsed || got["Used"].LastUsedRegion != "us-east-1" || got["Used"].DaysSinceUsed != 3 {
		t.Fatalf("used: %+v", got["Used"])
	}
	if got["Idle"].Status != ActivityNotUsedInWindow || got["Idle"].DaysSinceUsed != -1 {
		t.Fatalf("idle: %+v", got["Idle"])
	}
	if got["NoField"].Status != ActivityNotReported {
		t.Fatalf("nofield: %+v", got["NoField"])
	}
}

// A role without an activity record is not_collected, never "not used".
func TestStampRoleActivityNeverInfersUnused(t *testing.T) {
	used := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	mk := func(n string) models.AssetNode {
		return models.AssetNode{ARN: "arn:aws:iam::1:role/" + n, AssetType: models.AssetIAMRole}
	}
	assets := []models.AssetNode{mk("A"), mk("B"), mk("C"), {ARN: "arn:aws:s3:::b", AssetType: models.AssetS3Bucket}}
	StampRoleActivity(assets, []RoleActivity{
		{RoleARN: assets[0].ARN, LastUsedAt: &used, DaysSinceUsed: 17, Status: ActivityUsed, LastUsedRegion: "eu-west-1"},
		{RoleARN: assets[1].ARN, DaysSinceUsed: -1, Status: ActivityNotUsedInWindow},
	})
	if assets[0].Properties["role_last_used_status"] != ActivityUsed || assets[0].Properties["role_last_used_region"] != "eu-west-1" || assets[0].Properties["role_days_since_used"] != 17 {
		t.Fatalf("%v", assets[0].Properties)
	}
	if assets[1].Properties["role_last_used_status"] != ActivityNotUsedInWindow || assets[1].Properties["role_last_used"] != nil {
		t.Fatalf("%v", assets[1].Properties)
	}
	if assets[2].Properties["role_last_used_status"] != ActivityNotCollected {
		t.Fatalf("missing record must be not_collected: %v", assets[2].Properties)
	}
	if assets[3].Properties != nil {
		t.Fatalf("non-role asset touched: %v", assets[3].Properties)
	}
}
