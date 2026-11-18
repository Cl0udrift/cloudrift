package blastradius

import (
	"testing"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestObservedAssumersMatchRolesWithAPathAndKeepStrangers(t *testing.T) {
	target := models.AssetNode{ARN: "arn:aws:iam::111111111111:role/Target", AssetType: models.AssetIAMRole, Name: "Target"}
	dev := models.AssetNode{ARN: "arn:aws:iam::111111111111:role/team/Dev", AssetType: models.AssetIAMRole, Name: "Dev"}
	rels := []models.Relationship{
		// A session ARN has no path, so the caller arrives as role/Dev.
		{SourceARN: "arn:aws:iam::111111111111:role/Dev", TargetARN: target.ARN, RelType: models.RelObservedAssumeRole, Properties: map[string]any{"count": 4, "last_seen": "2026-11-10T00:00:00Z", "window_days": 30}},
		{SourceARN: "arn:aws:iam::999999999999:root", TargetARN: target.ARN, RelType: models.RelObservedAssumeRole, Properties: map[string]any{"count": 1, "last_seen": "2026-11-01T00:00:00Z", "caller_type": "account"}},
		{SourceARN: "arn:aws:iam::111111111111:role/Dev", TargetARN: "arn:aws:iam::111111111111:role/Other", RelType: models.RelObservedAssumeRole, Properties: map[string]any{"count": 9}},
	}
	obs := ObservedAssumers(target, []models.AssetNode{target, dev}, rels)
	if len(obs) != 2 || !obs[0].InScan || obs[0].Count != 4 || obs[1].InScan {
		t.Fatalf("a caller outside the scan must still be listed, other roles' callers must not: %+v", obs)
	}
	list := []schema.RoleAssumer{{ARN: dev.ARN}, {ARN: "arn:aws:iam::111111111111:user/none"}}
	AttachObserved(list, obs)
	if list[0].Observed == nil || list[0].Observed.Count != 4 || list[1].Observed != nil {
		t.Fatalf("%+v", list)
	}
}
