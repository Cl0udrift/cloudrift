package handlers

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/blastradius"
	"github.com/Zero0x00/cloudrift/internal/ciem"
	"github.com/Zero0x00/cloudrift/internal/iamauth"
	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/scans"
)

func ListIdentities(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scanID, assets, rels, ok := loadIdentityScan(w, r, outputDir)
		if !ok {
			return
		}
		page, pageSize, err := parsePagination(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_pagination", err.Error(), nil)
			return
		}
		items := ciem.ListRoles(assets, rels, ciem.InventoryFilter{
			AccountID:    strings.TrimSpace(r.URL.Query().Get("account_id")),
			Purpose:      strings.TrimSpace(r.URL.Query().Get("purpose")),
			Trust:        strings.TrimSpace(r.URL.Query().Get("trust")),
			Broad:        strings.TrimSpace(r.URL.Query().Get("broad")),
			Evidence:     strings.TrimSpace(r.URL.Query().Get("evidence")),
			Search:       strings.TrimSpace(r.URL.Query().Get("q")),
			Workload:     strings.TrimSpace(r.URL.Query().Get("workload")),
			WorkloadType: strings.TrimSpace(r.URL.Query().Get("type")),
			Region:       strings.TrimSpace(r.URL.Query().Get("region")),
			Category:     strings.TrimSpace(r.URL.Query().Get("category")),
			Unknown:      r.URL.Query().Get("unknown") == "true",
			Idle:         r.URL.Query().Get("idle") == "true",
			IdleDays:     idleDaysParam(r.URL.Query().Get("idle_days")),
		})
		total := len(items)
		totalPages := 0
		if total > 0 {
			totalPages = (total + pageSize - 1) / pageSize
		}
		start := (page - 1) * pageSize
		if start > total {
			start = total
		}
		end := start + pageSize
		if end > total {
			end = total
		}
		pageItems := items[start:end]
		if pageItems == nil {
			pageItems = []schema.IdentityListItem{}
		}
		writeJSON(w, http.StatusOK, schema.IdentityListResponse{
			ScanID: scanID, Items: pageItems, Page: page, PageSize: pageSize,
			TotalItems: total, TotalPages: totalPages,
			CoverageNote: "This list is the IAM roles stored in the scan. Accounts that were not scanned are absent. Opening the list does not evaluate authorization.",
		})
	}
}

// ListPrincipals returns the IAM users and groups stored in the scan.
func ListPrincipals(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scanID, assets, rels, ok := loadIdentityScan(w, r, outputDir)
		if !ok {
			return
		}
		writeJSON(w, http.StatusOK, schema.PrincipalListResponse{
			ScanID: scanID, Items: ciem.ListPrincipals(scanID, assets, rels, time.Now()),
			Note: "Users and groups come from iam:GetAccountAuthorizationDetails. An empty list can also mean that call was denied; check the iam_users_groups collection status.",
		})
	}
}

// GetPrincipalPolicies returns every policy applying to one user or group and where it came from.
func GetPrincipalPolicies(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scanID, assets, rels, ok := loadIdentityScan(w, r, outputDir)
		if !ok {
			return
		}
		principal, found := ciem.FindPrincipal(assets, strings.TrimSpace(r.URL.Query().Get("arn")))
		if !found {
			writeError(w, http.StatusNotFound, "principal_not_found", "iam user or group was not collected in this scan", nil)
			return
		}
		writeJSON(w, http.StatusOK, ciem.PrincipalPolicies(scanID, principal, ciem.ScanIndex(assets), rels, time.Now()))
	}
}

// GetRoleUsage returns who (users and roles) can assume a role and which workloads run as it.
func GetRoleUsage(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scanID, assets, rels, ok := loadIdentityScan(w, r, outputDir)
		if !ok {
			return
		}
		role, found := findIAMRole(assets, r.URL.Query().Get("arn"))
		if !found {
			writeError(w, http.StatusNotFound, "role_not_found", "iam role was not collected in this scan", nil)
			return
		}
		assumers, evaluated, unknown := blastradius.RoleAssumers(scanID, role, assets, rels, time.Time{})
		out := schema.RoleUsageResponse{
			ScanID: scanID, RoleARN: role.ARN, Assumers: assumers, Evaluated: evaluated, Unknown: unknown,
			Workloads: ciem.WorkloadsForRole(role.ARN, assets, rels),
			Notes: []string{
				"Callers are users and roles in this scan, checked against the trust policy and their own policies. Principals in accounts that were not scanned, and federated or service principals, are not listed here.",
				"This shows what stored policies allow. It does not show who assumed the role. That needs CloudTrail.",
			},
		}
		if out.Assumers == nil {
			out.Assumers = []schema.RoleAssumer{} // JSON null would crash the page
		}
		if out.Workloads == nil {
			out.Workloads = []schema.WorkloadAttachment{}
		}
		for _, a := range assumers {
			switch a.Status {
			case iamauth.StatusAllowed:
				out.Allowed++
			default:
				out.Possible++
			}
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// whoCanActions are the actions the explorer evaluates: role assumption and the identity-only IAM actions.
func whoCanAction(action string) bool {
	if action == iamauth.ActionAssumeRole {
		return true
	}
	for _, c := range iamauth.Catalog() {
		if c.Action == action && c.Evaluation == iamauth.EvalIdentityOnly && c.Support == iamauth.SupportEvaluated {
			return true
		}
	}
	return false
}

// GetWhoCan lists the users and roles that stored policies allow to perform an action on a user, group or role.
func GetWhoCan(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scanID, assets, rels, ok := loadIdentityScan(w, r, outputDir)
		if !ok {
			return
		}
		action := strings.TrimSpace(r.URL.Query().Get("action"))
		if !whoCanAction(action) {
			writeError(w, http.StatusBadRequest, "unsupported_action", "this action is not evaluated by who-can: use sts:AssumeRole or an identity-only IAM action such as iam:AttachUserPolicy", nil)
			return
		}
		arn := strings.TrimSpace(r.URL.Query().Get("arn"))
		var target models.AssetNode
		found := false
		for _, a := range assets {
			if a.ARN == arn && (a.AssetType == models.AssetIAMRole || a.AssetType == models.AssetIAMUser || a.AssetType == models.AssetIAMGroup) {
				target, found = a, true
				break
			}
		}
		if !found {
			writeError(w, http.StatusNotFound, "target_not_found", "that user, group or role was not collected in this scan", nil)
			return
		}
		callers, evaluated, unknown := blastradius.WhoCan(scanID, action, target, assets, rels, time.Time{})
		out := schema.WhoCanResponse{
			ScanID: scanID, Action: action, TargetARN: target.ARN, Callers: callers, Evaluated: evaluated, Unknown: unknown,
			Notes: []string{
				"Callers are users and roles in this scan, checked against their own policies, permissions boundary and any collected SCPs. Principals in accounts that were not scanned are not listed.",
				"This shows what stored policies allow, not what anyone did.",
			},
		}
		if out.Callers == nil {
			out.Callers = []schema.RoleAssumer{}
		}
		for _, c := range callers {
			if c.Status == iamauth.StatusAllowed {
				out.Allowed++
			} else {
				out.Possible++
			}
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// idleDaysParam accepts 1 to 3650; anything else falls back to the default threshold.
func idleDaysParam(raw string) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n < 1 || n > 3650 {
		return 0
	}
	return n
}

func GetIdentityProfile(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scanID, assets, rels, ok := loadIdentityScan(w, r, outputDir)
		if !ok {
			return
		}
		role, found := findIAMRole(assets, r.URL.Query().Get("arn"))
		if !found {
			writeError(w, http.StatusNotFound, "role_not_found", "iam role was not collected in this scan", nil)
			return
		}
		profile := ciem.Profile(scanID, role, assets, rels)
		if truthy(r.URL.Query().Get("impact")) {
			impact := ciem.Impact(r.Context(), scanID, role, assets, rels)
			if workload := strings.TrimSpace(r.URL.Query().Get("workload_arn")); workload != "" {
				impact.Kind = "workload_credential_compromise"
				impact.Assumption = workloadAssumption(workload, role.ARN, ciem.WorkloadsForRole(role.ARN, assets, rels))
			}
			profile.Impact = &impact
			profile.EvaluatedCount = impact.ValidatedAllowed + impact.ValidatedDenied + impact.Conditional + impact.Unknown
			profile.ValidatedTransitions = impact.ValidatedTransitions
		}
		writeJSON(w, http.StatusOK, profile)
	}
}

func ListWorkloads(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scanID, assets, rels, ok := loadIdentityScan(w, r, outputDir)
		if !ok {
			return
		}
		page, pageSize, err := parsePagination(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_pagination", err.Error(), nil)
			return
		}
		items := ciem.ListWorkloads(assets, rels,
			strings.TrimSpace(r.URL.Query().Get("account_id")),
			strings.TrimSpace(r.URL.Query().Get("region")),
			strings.TrimSpace(r.URL.Query().Get("type")),
			strings.TrimSpace(r.URL.Query().Get("role_arn")),
		)
		roles := map[string]int{}
		workloads := map[string]struct{}{}
		for _, item := range items {
			workloads[item.WorkloadARN] = struct{}{}
			if item.RoleARN != "" {
				roles[item.RoleARN]++
			}
		}
		shared := 0
		for _, count := range roles {
			if count > 1 {
				shared++
			}
		}
		total := len(items)
		totalPages := 0
		if total > 0 {
			totalPages = (total + pageSize - 1) / pageSize
		}
		start := (page - 1) * pageSize
		if start > total {
			start = total
		}
		end := start + pageSize
		if end > total {
			end = total
		}
		pageItems := items[start:end]
		if pageItems == nil {
			pageItems = []schema.WorkloadAttachment{}
		}
		writeJSON(w, http.StatusOK, schema.WorkloadListResponse{
			ScanID: scanID, Items: pageItems, Page: page, PageSize: pageSize,
			TotalItems: total, TotalPages: totalPages,
			UniqueWorkloads: len(workloads), UniqueRoles: len(roles), SharedRoleCount: shared,
			CoverageNote: "Workload rows are configured attachments. They are not attacker transitions. Unique role impact is not multiplied by the number of workloads.",
		})
	}
}

func loadIdentityScan(w http.ResponseWriter, r *http.Request, outputDir string) (string, []models.AssetNode, []models.Relationship, bool) {
	scanID, ok := scanIDFromPath(outputDir, chi.URLParam(r, "id"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_scan_id", "invalid scan id", nil)
		return "", nil, nil, false
	}
	if _, err := os.Stat(filepath.Join(outputDir, scanID, "scan-metadata.json")); err != nil {
		writeError(w, http.StatusNotFound, "scan_not_found", "scan was not found", nil)
		return "", nil, nil, false
	}
	assets, err := scans.LoadAssets(outputDir, scanID)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusInternalServerError, "scan_load_error", "failed to load scan assets", nil)
		return "", nil, nil, false
	}
	rels, err := scans.LoadRelationships(outputDir, scanID)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusInternalServerError, "scan_load_error", "failed to load scan relationships", nil)
		return "", nil, nil, false
	}
	return scanID, assets, rels, true
}

func findIAMRole(assets []models.AssetNode, arn string) (models.AssetNode, bool) {
	arn = strings.TrimSpace(arn)
	if arn == "" {
		return models.AssetNode{}, false
	}
	for _, asset := range assets {
		if asset.AssetType == models.AssetIAMRole && asset.ARN == arn {
			return asset, true
		}
	}
	return models.AssetNode{}, false
}

func workloadAssumption(workload, roleARN string, items []schema.WorkloadAttachment) string {
	mechanism := ""
	for _, item := range items {
		if item.WorkloadARN == workload {
			mechanism = item.Mechanism
			break
		}
	}
	switch mechanism {
	case "ecs_execution_role":
		return "A usable session for the ECS execution role " + roleARN + " configured on " + workload + " is compromised. This role is used by ECS infrastructure, not application containers. This is not observed credential theft."
	case "ecs_task_role":
		return "A usable session for the ECS task role " + roleARN + " configured on " + workload + " is compromised. This is the application task identity for that configuration. This is not observed task compromise or network reachability."
	case "eks_pod_identity":
		return "A usable session for role " + roleARN + " named by the EKS Pod Identity association " + workload + " is compromised. A running Pod was not observed. This is not observed credential theft."
	case "irsa":
		return "A usable session for role " + roleARN + " is compromised under the IRSA trust configuration " + workload + ". Kubernetes attachment was not collected, and AssumeRoleWithWebIdentity is not modeled as sts:AssumeRole. This is not an observed Pod."
	default:
		return "A usable AWS credential session associated with " + workload + " and configured role " + roleARN + " is compromised. This is not observed credential theft, and it is not network reachability."
	}
}

func truthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}
