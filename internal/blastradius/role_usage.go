package blastradius

import (
	"sort"
	"time"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/iamauth"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// StatusPendingControls marks a caller whose identity and trust policies allow the call but
// whose organization controls were not collected, so the result cannot be validated.
const StatusPendingControls = "ALLOWED_PENDING_CONTROLS"

// RoleAssumers evaluates sts:AssumeRole on target for every collected user and role in the
// scan, using the trust policy and each caller's identity policies, boundary and SCPs.
// Denied callers, and callers that cannot be evaluated for lack of evidence, are counted but not listed. The result is a hypothesis
// about what the stored policies allow, not a record of who did assume the role.
func RoleAssumers(scanID string, target models.AssetNode, assets []models.AssetNode, rels []models.Relationship, when time.Time) (list []schema.RoleAssumer, evaluated, unknown int) {
	return WhoCan(scanID, iamauth.ActionAssumeRole, target, assets, rels, when)
}

// WhoCan evaluates one action on target for every collected user and role. It supports sts:AssumeRole and
// the identity-only IAM actions in the catalog (those decided by the caller's own policies), and the
// result says what stored policies allow, not what anyone did.
func WhoCan(scanID, action string, target models.AssetNode, assets []models.AssetNode, rels []models.Relationship, when time.Time) (list []schema.RoleAssumer, evaluated, unknown int) {
	if when.IsZero() {
		when = time.Unix(0, 0).UTC()
	}
	var trust iamauth.PolicySlot
	resourceEvidence := "this action does not use a resource policy"
	if action == iamauth.ActionAssumeRole {
		trust = trustSlot(target)
		resourceEvidence = "role assumption is governed by the trust policy"
	}
	for _, caller := range assets {
		if caller.ARN == target.ARN || (caller.AssetType != models.AssetIAMRole && caller.AssetType != models.AssetIAMUser) {
			continue
		}
		identity, _ := identitySlot(caller, assets, rels)
		req := iamauth.AuthorizationRequest{
			ScanID: scanID, PrincipalARN: caller.ARN, Action: action,
			ResourceARN: target.ARN, ResourceAccountID: target.AccountID, EvaluatedAt: when,
			Identity: identity, TrustPolicy: trust,
			PermissionsBoundary: boundaryFromRole(caller),
			// A session policy can only narrow access, so none is assumed for this question.
			SessionPolicies: iamauth.PolicySlot{State: iamauth.EvidenceAbsent, Evidence: "no session policy assumed; session policies only narrow access"},
			SCPs:            orgControlSlot(caller, "scp"),
			RCPs:            rcpForResource(assets, caller, target, action, iamauth.PolicySlot{}),
			ResourcePolicy:  iamauth.PolicySlot{State: iamauth.EvidenceAbsent, Evidence: resourceEvidence},
		}
		decision := iamauth.Evaluate(req)
		evaluated++
		status, reason := decision.Status, decision.Reason
		if status == iamauth.StatusUnknown && reason != iamauth.ReasonNoAllow {
			// Organization controls are often not collected. Check whether the identity and
			// trust policies alone allow the call, and say that the controls were not checked.
			probe := req
			probe.SCPs = iamauth.PolicySlot{State: iamauth.EvidenceAbsent, Evidence: "not checked: SCPs were not collected"}
			probe.RCPs = iamauth.PolicySlot{State: iamauth.EvidenceAbsent, Evidence: "not checked: RCPs were not collected"}
			if again := iamauth.Evaluate(probe); again.Status == iamauth.StatusAllowed {
				status, reason = StatusPendingControls, "identity and trust policies allow it; organization controls (SCP/RCP) were not checked"
			}
		}
		if status == iamauth.StatusDenied || reason == iamauth.ReasonNoAllow {
			continue
		}
		if status == iamauth.StatusUnknown {
			unknown++
			continue
		}
		kind := "role"
		if caller.AssetType == models.AssetIAMUser {
			kind = "user"
		}
		list = append(list, schema.RoleAssumer{
			ARN: caller.ARN, Name: caller.Name, Kind: kind, AccountID: caller.AccountID,
			Status: status, Reason: reason,
		})
	}
	rank := map[string]int{iamauth.StatusAllowed: 0, StatusPendingControls: 1, iamauth.StatusConditional: 2}
	sort.Slice(list, func(i, j int) bool {
		if rank[list[i].Status] != rank[list[j].Status] {
			return rank[list[i].Status] < rank[list[j].Status]
		}
		return list[i].ARN < list[j].ARN
	})
	return list, evaluated, unknown
}
