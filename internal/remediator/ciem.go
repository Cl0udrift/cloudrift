package remediator

import "github.com/Zero0x00/cloudrift/internal/api/schema"

// RoleRemediationInput is evidence the CIEM view already collected.
// Recommendations stay read-only. Stale RoleLastUsed metadata does not justify deletion.
type RoleRemediationInput struct {
	RoleARN          string
	Principal        string
	PrincipalClass   string
	Breadth          string
	AdminCandidates  []string
	BoundaryMissing  bool
	StaleActivity    bool
	HasTrustDocument bool
}

// RoleRecommendations returns locally actionable candidates for an externally trusted role.
func RoleRecommendations(in RoleRemediationInput) []schema.CIEMRecommendation {
	var out []schema.CIEMRecommendation
	if in.Breadth == "entire_external_account" || in.Breadth == "public_or_wildcard" {
		out = append(out, schema.CIEMRecommendation{
			ID: "restrict-trust-principal", Title: "Restrict the trust principal",
			Issue:        "The trust names an account or wildcard rather than one intended principal.",
			Evidence:     []string{"principal class " + in.PrincipalClass, "delegation " + in.Breadth},
			ChangeTarget: in.RoleARN + " trust policy", Affected: in.Principal,
			ExpectedReduction: "Fewer identities in the trusted account would match the trust.",
			OperationalRisk:   "A workload that assumes this role from another principal in that account would fail.",
			Verification:      "Rescan and confirm the trust principal list names only the intended identity.",
		})
	}
	if in.HasTrustDocument && in.PrincipalClass == "external_aws_account" {
		out = append(out, schema.CIEMRecommendation{
			ID: "review-trust-conditions", Title: "Review trust-policy conditions",
			Issue:        "An account trust without a confirmed condition lets any matching principal in that account present the request.",
			Evidence:     []string{"collected trust policy on " + in.RoleARN},
			ChangeTarget: in.RoleARN + " trust policy", Affected: in.Principal,
			ExpectedReduction: "A supported condition such as sts:ExternalId can reject confused-deputy calls when the caller can send it.",
			OperationalRisk:   "Adding a condition the caller cannot satisfy removes a working integration.",
			Verification:      "Confirm the caller sends the condition, then rescan the trust document.",
		})
	}
	if len(in.AdminCandidates) > 0 {
		out = append(out, schema.CIEMRecommendation{
			ID: "reduce-role-permissions", Title: "Reduce excessive role permissions",
			Issue:    "The role has a broad administrative policy candidate.",
			Evidence: in.AdminCandidates, ChangeTarget: in.RoleARN + " identity policies", Affected: in.RoleARN,
			ExpectedReduction: "A compromised session would no longer carry the candidate administrative grant.",
			OperationalRisk:   "Removing a policy the workload uses will break that workload. This is not a generated least-privilege policy.",
			Verification:      "Rescan policy documents and the hypothetical impact for this role.",
		})
	}
	if in.BoundaryMissing {
		out = append(out, schema.CIEMRecommendation{
			ID: "review-boundary", Title: "Review the permissions boundary",
			Issue:        "Boundary evidence is missing, so an identity Allow is not effective authorization.",
			Evidence:     []string{"permissions boundary was not confirmed for " + in.RoleARN},
			ChangeTarget: in.RoleARN, Affected: in.RoleARN,
			ExpectedReduction: "A boundary can cap the session if one is appropriate for this role.",
			OperationalRisk:   "A boundary that omits a required action blocks the workload.",
			Verification:      "Collect the boundary document and re-evaluate the supported actions.",
		})
	}
	if in.StaleActivity {
		out = append(out, schema.CIEMRecommendation{
			ID: "review-stale-trust", Title: "Review stale external access without deleting it from RoleLastUsed alone",
			Issue:        "Activity metadata suggests the role is unused. That metadata is not sufficient to delete the trust.",
			Evidence:     []string{"RoleLastUsed or a missing activity join is not proof the integration is obsolete"},
			ChangeTarget: in.RoleARN + " trust policy", Affected: in.Principal,
			ExpectedReduction: "An owner can remove the trust after confirming the integration is unused.",
			OperationalRisk:   "Deleting access from stale metadata can break an infrequent caller.",
			Verification:      "Confirm with the owner, then rescan. Do not execute a delete from this recommendation.",
		})
	}
	return out
}

// InternalReviewInput is declared entitlement evidence for one collected role.
type InternalReviewInput struct {
	RoleARN         string
	AccountID       string
	Classifications []string
	Candidates      []string
	BoundaryMissing bool
	OrgMissing      bool
	SessionMissing  bool
	LastUsed        string
	WorkloadCount   int
	UnresolvedRoles int
	LambdaCount     int
	InstanceCount   int
	ECSTaskCount    int
	ECSExecCount    int
	PodIdentity     int
	IRSAWildcard    int
	SameECSRoles    bool
}

// InternalRoleRecommendations returns read-only review items. None detach a policy or delete a role.
func InternalRoleRecommendations(in InternalReviewInput) []schema.CIEMRecommendation {
	var out []schema.CIEMRecommendation
	has := func(id string) bool {
		for _, candidate := range in.Candidates {
			if candidate == id {
				return true
			}
		}
		return false
	}
	if has("administrative_wildcard") {
		out = append(out, review("review-wildcard-admin", "Review excessive wildcard IAM permissions", in,
			"Policy text grants an administrative wildcard.", "Removing the wildcard can remove access the workload still uses. This is not a generated least-privilege policy."))
	}
	if has("broad_assume_role") {
		out = append(out, review("review-broad-assume", "Investigate broad role-assumption scope", in,
			"Policy text allows sts:AssumeRole on a broad resource.", "Narrowing AssumeRole can break a reporting or deployment workflow that assumes another role."))
	}
	if has("broad_passrole") {
		out = append(out, review("review-passrole", "Review broad iam:PassRole grants", in,
			"iam:PassRole is declared. Passing a role is not control of that role by itself.", "A service that receives this role at launch would fail if the grant is removed."))
	}
	if containsLabel(in.Classifications, "EXTERNAL_DELEGATED") || containsLabel(in.Classifications, "INTERNAL_CROSS_ACCOUNT") || containsLabel(in.Classifications, "MIXED_TRUST") {
		out = append(out, review("review-trust", "Validate intended role trust relationships", in,
			"The trust configuration names another account or a mix of principal types. Configured trust is not proof the caller can assume the role.", "Changing the trust can block the intended caller."))
	}
	if in.BoundaryMissing {
		out = append(out, review("review-boundary", "Review permissions boundaries", in,
			"Boundary evidence is missing or was not collected, so an identity Allow is not effective authorization.", "Attaching a boundary that omits a required action blocks the workload."))
	}
	if in.OrgMissing {
		out = append(out, review("review-org-evidence", "Investigate missing Organizations authorization evidence", in,
			"SCP evidence is missing. Missing evidence is not full access and it is not a deny.", "Collecting organization policies does not change the role until an administrator edits a policy."))
	}
	if in.LastUsed != "" {
		out = append(out, review("review-activity", "Review role activity without treating it as unused permission", in,
			"Role last-used metadata was stored. Absence of recent use is not proof a permission is unused.", "Deleting a role from last-used metadata can break an infrequent caller."))
	}
	if in.WorkloadCount > 1 && has("administrative_wildcard") {
		out = append(out, review("review-shared-privileged-role", "Investigate a highly privileged role used by several workloads", in,
			"More than one collected workload is configured to use a role whose policy text matches an administrative wildcard. Sharing a role is not itself a misconfiguration.",
			"Changing this role changes every workload configured to use it."))
	}
	if in.InstanceCount > 0 && has("administrative_wildcard") {
		out = append(out, review("review-instance-profile", "Review the instance profile association", in,
			"An EC2 instance profile resolves to a role with a broad declared entitlement. The association is configuration, not stolen instance-metadata credentials.",
			"Removing the instance profile removes the credentials the instance receives at launch."))
	}
	if in.LambdaCount > 0 && (has("administrative_wildcard") || has("broad_passrole")) {
		out = append(out, review("review-lambda-execution-role", "Review sensitive Lambda execution-role permissions", in,
			"A Lambda function configuration names this role. A privileged execution role does not mean the function is externally invokable.",
			"Narrowing the execution role can stop the function from calling AWS APIs it still uses."))
	}
	if in.UnresolvedRoles > 0 {
		out = append(out, review("review-unresolved-attachment", "Investigate unresolved role attachments", in,
			"A workload references a role that was not present in the collected role inventory.",
			"The reference may be a collection gap. Do not delete the workload configuration from this recommendation."))
	}
	if in.ECSTaskCount > 0 && has("administrative_wildcard") {
		out = append(out, review("review-ecs-task-role", "Review excessive ECS task role privileges", in,
			"An ECS task definition names this role as the application task role, and the policy text matches an administrative wildcard.",
			"Narrowing the task role changes what application containers can call. The execution role is a separate privilege set."))
	}
	if in.SameECSRoles {
		out = append(out, review("review-ecs-role-confusion", "Investigate task and execution role confusion", in,
			"The same IAM role is configured as both an ECS task role and an ECS execution role.",
			"Splitting the roles can remove infrastructure permissions from application containers, or application permissions from the execution path."))
	}
	if in.ECSTaskCount > 1 && has("administrative_wildcard") {
		out = append(out, review("review-shared-ecs-task-role", "Review a role shared by several ECS task configurations", in,
			"More than one ECS task configuration uses this role, and the policy text matches an administrative wildcard. Sharing a role is not itself a misconfiguration.",
			"Changing the role changes every task definition, service, and task configured to use it."))
	}
	if in.PodIdentity > 0 && has("administrative_wildcard") {
		out = append(out, review("review-pod-identity", "Review an EKS Pod Identity association with broad permissions", in,
			"An EKS Pod Identity association names this role. The association is configuration. A running Pod was not observed.",
			"Changing the role changes every association that names it. Do not assume a service account exists in the cluster."))
	}
	if in.IRSAWildcard > 0 {
		out = append(out, review("review-irsa-wildcard", "Review a broad IRSA OIDC subject condition", in,
			"The role trust allows AssumeRoleWithWebIdentity for a wildcard service account subject. Kubernetes attachment was not collected.",
			"Narrowing the subject can block a service account that still needs the role. This is not an observed Pod."))
	}
	if in.SessionMissing {
		out = append(out, review("review-session", "Session restrictions were not observed", in,
			"The modeled session does not have a confirmed session policy. The impact hypothesis does not treat that as absence.", "A session policy added at AssumeRole time would further limit a real session."))
	}
	return out
}

func review(id, title string, in InternalReviewInput, issue, risk string) schema.CIEMRecommendation {
	return schema.CIEMRecommendation{
		ID: id, Title: title, Issue: issue,
		Evidence:     []string{"role " + in.RoleARN, "account " + in.AccountID},
		ChangeTarget: in.RoleARN, Affected: in.RoleARN,
		ExpectedReduction: "A narrower grant reduces what a compromised session of this role could do, after the owner confirms the workload.",
		OperationalRisk:   risk,
		Verification:      "Rescan the role and review the hypothetical impact. Do not execute a change from this recommendation.",
	}
}

func containsLabel(labels []string, want string) bool {
	for _, label := range labels {
		if label == want {
			return true
		}
	}
	return false
}

// ResourcePolicyRecommendations covers an external S3 grant that is not a role assumption.
func ResourcePolicyRecommendations(bucketARN string) []schema.CIEMRecommendation {
	return []schema.CIEMRecommendation{{
		ID: "review-bucket-grant", Title: "Review the bucket policy grant",
		Issue:        "An external principal is named by a resource policy. This is not an IAM role trust finding.",
		Evidence:     []string{"resource policy on " + bucketARN},
		ChangeTarget: bucketARN, Affected: bucketARN,
		ExpectedReduction: "Removing or narrowing the grant reduces who the bucket policy allows.",
		OperationalRisk:   "The external workload that reads or writes the bucket would lose that path.",
		Verification:      "Rescan the bucket policy after the change.",
	}}
}
