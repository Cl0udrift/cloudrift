package ciem

import (
	"sort"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// categoryService maps a declared candidate category to its IAM access advisor service namespace.
// Administrative wildcards span every service, so no single service answers them.
var categoryService = map[string]string{
	"broad_s3_access":         "s3",
	"s3_wildcard":             "s3",
	"s3_read":                 "s3",
	"s3_write":                "s3",
	"s3_delete":               "s3",
	"assume_role":             "sts",
	"broad_assume_role":       "sts",
	"pass_role":               "iam",
	"broad_passrole":          "iam",
	"iam_policy_modification": "iam",
}

// categoryAction maps a category to an action IAM can track at action level. S3 and STS data
// events are not tracked, so those stay service-level.
var categoryAction = map[string]string{
	"pass_role": "PassRole", "broad_passrole": "PassRole", "iam_policy_modification": "AttachRolePolicy",
}

// serviceAccessFromRole reads the stored access advisor evidence. An empty status means collection
// was not requested for the scan, which older scans also show.
func serviceAccessFromRole(role models.AssetNode) (status, completed string, entries []schema.ServiceAccessEntry) {
	status = strProp(role, "service_last_accessed_status")
	completed = strProp(role, "service_last_accessed_completed")
	add := func(m map[string]any) {
		get := func(k string) string { s, _ := m[k].(string); return s }
		entry := schema.ServiceAccessEntry{
			ServiceNamespace: get("service_namespace"), ServiceName: get("service_name"),
			LastAuthenticated: get("last_authenticated"), LastAuthenticatedRegion: get("last_authenticated_region"),
		}
		addAction := func(a map[string]any) {
			name, _ := a["action_name"].(string)
			when, _ := a["last_accessed_time"].(string)
			entry.TrackedActions = append(entry.TrackedActions, schema.TrackedActionEntry{ActionName: name, LastAccessedTime: when})
		}
		switch acts := m["tracked_actions"].(type) {
		case []map[string]any:
			for _, a := range acts {
				addAction(a)
			}
		case []any:
			for _, v := range acts {
				if a, ok := v.(map[string]any); ok {
					addAction(a)
				}
			}
		}
		entries = append(entries, entry)
	}
	switch list := role.Properties["service_last_accessed"].(type) {
	case []map[string]any:
		for _, m := range list {
			add(m)
		}
	case []any:
		for _, v := range list {
			if m, ok := v.(map[string]any); ok {
				add(m)
			}
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ServiceNamespace < entries[j].ServiceNamespace })
	return status, completed, entries
}

// annotateServiceActivity labels declared candidates against service access. It never says a
// permission is safe or unused unless IAM listed the service and reported no access in its window.
func annotateServiceActivity(items []schema.PermissionCandidate, status string, entries []schema.ServiceAccessEntry) {
	if status == "" {
		return
	}
	for i := range items {
		ns := categoryService[items[i].Category]
		if ns == "" || (items[i].Outcome != models.EvidenceDeclared && items[i].Outcome != models.EvidenceConditional) {
			continue
		}
		if status != "complete" {
			items[i].ServiceActivity = "unknown"
			continue
		}
		items[i].ServiceActivity = "not_reported"
		for _, e := range entries {
			if e.ServiceNamespace != ns {
				continue
			}
			items[i].ServiceActivityScope = "service"
			if e.LastAuthenticated != "" {
				items[i].ServiceActivity, items[i].ServiceLastAccessed = "accessed", e.LastAuthenticated
			} else {
				items[i].ServiceActivity = "not_accessed_in_window"
			}
			// Action-level evidence only upgrades a result when IAM tracked that exact action with a time.
			for _, act := range e.TrackedActions {
				if want := categoryAction[items[i].Category]; want != "" && act.ActionName == want && act.LastAccessedTime != "" {
					items[i].ServiceActivity, items[i].ServiceLastAccessed, items[i].ServiceActivityScope = "accessed", act.LastAccessedTime, "action"
				}
			}
			break
		}
	}
}
