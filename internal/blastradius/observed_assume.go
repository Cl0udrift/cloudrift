package blastradius

import (
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// identityKey names a user or role so a CloudTrail caller can be matched to the inventory. A role session ARN carries the
// role's name but not its path, so a role is keyed by account and name.
func identityKey(arn string) string {
	if i := strings.Index(arn, ":role/"); i >= 0 {
		rest := arn[i+len(":role/"):]
		return arn[:i] + ":role/" + rest[strings.LastIndex(rest, "/")+1:]
	}
	return arn
}

// HasAssumeHistory reports whether the scan read CloudTrail assume-role history for any account and Region.
func HasAssumeHistory(assets []models.AssetNode) bool {
	for _, a := range assets {
		if a.AssetType == "collection_status" && a.Properties["collector"] == "assume_activity" {
			return true
		}
	}
	return false
}

// ObservedAssumers lists every caller seen assuming the role in CloudTrail history, with whether the caller is a user or role
// in this scan. A caller seen but not allowed by stored policy is the interesting case, so none is dropped.
func ObservedAssumers(role models.AssetNode, assets []models.AssetNode, rels []models.Relationship) []schema.ObservedCaller {
	inScan := map[string]models.AssetNode{}
	for _, a := range assets {
		if a.AssetType == models.AssetIAMRole || a.AssetType == models.AssetIAMUser {
			inScan[identityKey(a.ARN)] = a
		}
	}
	want := identityKey(role.ARN)
	out := []schema.ObservedCaller{}
	for _, r := range rels {
		if r.RelType != models.RelObservedAssumeRole || identityKey(r.TargetARN) != want {
			continue
		}
		c := schema.ObservedCaller{Caller: r.SourceARN, FirstSeen: str(r.Properties["first_seen"]), LastSeen: str(r.Properties["last_seen"]), CallerType: str(r.Properties["caller_type"])}
		c.Count, _ = r.Properties["count"].(int)
		c.WindowDays, _ = r.Properties["window_days"].(int)
		if f, ok := r.Properties["count"].(float64); ok { // read back from JSON
			c.Count = int(f)
		}
		if f, ok := r.Properties["window_days"].(float64); ok {
			c.WindowDays = int(f)
		}
		switch ips := r.Properties["source_ips"].(type) {
		case []string:
			c.SourceIPs = ips
		case []any: // read back from JSON
			for _, v := range ips {
				if ip, ok := v.(string); ok {
					c.SourceIPs = append(c.SourceIPs, ip)
				}
			}
		}
		if a, ok := inScan[identityKey(r.SourceARN)]; ok {
			c.InScan, c.Name = true, a.Name
		} else {
			c.Name = r.SourceARN
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen > out[j].LastSeen })
	return out
}

// AttachObserved sets Observed on each caller that was seen assuming the role.
func AttachObserved(list []schema.RoleAssumer, observed []schema.ObservedCaller) {
	by := map[string]schema.ObservedCaller{}
	for _, o := range observed {
		by[identityKey(o.Caller)] = o
	}
	for i := range list {
		if o, ok := by[identityKey(list[i].ARN)]; ok {
			list[i].Observed = &schema.ObservedUse{Count: o.Count, FirstSeen: o.FirstSeen, LastSeen: o.LastSeen, WindowDays: o.WindowDays}
		}
	}
}

func str(v any) string { s, _ := v.(string); return s }
