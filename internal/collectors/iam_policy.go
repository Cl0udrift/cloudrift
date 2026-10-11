package collectors

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// IdentityPolicyInput is one inline or managed policy document for a role.
// RetrievalStatus missing or malformed keeps the policy visible and emits no statements.
type IdentityPolicyInput struct {
	ARN             string
	Name            string
	PolicyType      string
	VersionID       string
	Document        string
	RetrievalStatus string
}

// BuildIdentityPolicyEvidence projects policy, statement, and unevaluated candidate
// relationships with the same identities the live IAM collector uses.
// It does not call AWS and does not record an authorization decision.
func BuildIdentityPolicyEvidence(role models.AssetNode, policies []IdentityPolicyInput) ([]models.AssetNode, []models.Relationship) {
	collected := make([]collectedPolicy, 0, len(policies))
	for _, policy := range policies {
		collected = append(collected, collectedPolicy{
			ARN:             policy.ARN,
			Name:            policy.Name,
			PolicyType:      policy.PolicyType,
			VersionID:       policy.VersionID,
			Document:        policy.Document,
			RetrievalStatus: policy.RetrievalStatus,
			RoleARN:         role.ARN,
			AccountID:       role.AccountID,
		})
	}
	return policyEvidenceGraph(role, collected)
}

// collectedPolicy is one inline or managed policy retrieved for a role.
// RetrievalStatus missing or malformed keeps the policy visible and emits no statements.
type collectedPolicy struct {
	ARN             string
	Name            string
	PolicyType      string
	VersionID       string
	Document        string
	RetrievalStatus string
	RoleARN         string
	AccountID       string
}

func policyEvidenceGraph(role models.AssetNode, policies []collectedPolicy) ([]models.AssetNode, []models.Relationship) {
	nodes := make([]models.AssetNode, 0, len(policies))
	rels := make([]models.Relationship, 0, len(policies))
	seenPolicy := map[string]struct{}{}
	for _, p := range policies {
		policyARN := strings.TrimSpace(p.ARN)
		if policyARN == "" {
			policyARN = inlinePolicyARN(role.AccountID, role.Name, p.Name)
		}
		if _, ok := seenPolicy[policyARN]; ok {
			continue
		}
		seenPolicy[policyARN] = struct{}{}
		status := p.RetrievalStatus
		if status == "" {
			status = models.PolicyRetrievalOK
		}
		policyNode := models.AssetNode{
			ARN:       policyARN,
			AssetType: models.AssetIAMPolicy,
			Name:      p.Name,
			AccountID: role.AccountID,
			Region:    "global",
			Properties: map[string]any{
				"policy_type":       p.PolicyType,
				"policy_version_id": p.VersionID,
				"retrieval_status":  status,
				"policy_document":   p.Document,
				"attached_role_arn": role.ARN,
				"resolution_status": "collected",
				"evaluation_status": models.EvaluationUnevaluated,
			},
		}
		nodes = append(nodes, policyNode)
		rels = append(rels, models.Relationship{
			SourceARN: role.ARN,
			TargetARN: policyARN,
			RelType:   models.RelPolicyAttachedTo,
			Properties: map[string]any{
				"policy_type":       p.PolicyType,
				"policy_version_id": p.VersionID,
				"retrieval_status":  status,
				"evaluation_status": models.EvaluationUnevaluated,
				"scan_scope":        "identity_policy",
			},
		})
		if status != models.PolicyRetrievalOK {
			continue
		}
		statements, err := models.NormalizeIdentityPolicy(policyARN, p.PolicyType, role.AccountID, p.Document)
		if err != nil {
			policyNode.Properties["retrieval_status"] = models.PolicyRetrievalMalformed
			policyNode.Properties["retrieval_error"] = err.Error()
			nodes[len(nodes)-1] = policyNode
			rels[len(rels)-1].Properties["retrieval_status"] = models.PolicyRetrievalMalformed
			continue
		}
		for _, stmt := range statements {
			stmtARN := statementARN(policyARN, stmt.StatementID)
			condJSON, _ := json.Marshal(stmt.Condition)
			nodes = append(nodes, models.AssetNode{
				ARN:       stmtARN,
				AssetType: models.AssetIAMPolicyStatement,
				Name:      stmt.StatementID,
				AccountID: role.AccountID,
				Region:    "global",
				Properties: map[string]any{
					"policy_id":                   stmt.PolicyID,
					"statement_id":                stmt.StatementID,
					"policy_type":                 stmt.PolicyType,
					"effect":                      stmt.Effect,
					"action":                      stmt.Action,
					"not_action":                  stmt.NotAction,
					"resource":                    stmt.Resource,
					"not_resource":                stmt.NotResource,
					"condition":                   stmt.Condition,
					"evaluation_status":           models.EvaluationUnevaluated,
					"evaluation_completeness":     models.EvaluationIdentityPolicyOnly,
					"evidence_ref":                stmt.EvidenceRef,
					"resource_is_expression_only": stmt.ResourceIsExpressionOnly,
					"resolution_status":           "collected",
					"inventory_kind":              "policy_statement",
				},
			})
			rels = append(rels, models.Relationship{
				SourceARN: policyARN,
				TargetARN: stmtARN,
				RelType:   models.RelPolicyContainsStatement,
				Properties: map[string]any{
					"statement_id":      stmt.StatementID,
					"effect":            stmt.Effect,
					"evaluation_status": models.EvaluationUnevaluated,
				},
			})
			props := map[string]any{
				"principal_arn":               role.ARN,
				"effect":                      stmt.Effect,
				"action":                      stmt.Action,
				"not_action":                  stmt.NotAction,
				"resource_expression":         stmt.Resource,
				"not_resource":                stmt.NotResource,
				"policy_source":               stmt.PolicyType,
				"policy_id":                   stmt.PolicyID,
				"statement_id":                stmt.StatementID,
				"statement_ref":               stmt.EvidenceRef,
				"condition":                   stmt.Condition,
				"condition_json":              string(condJSON),
				"has_condition":               len(stmt.Condition) > 0,
				"evaluation_status":           models.EvaluationUnevaluated,
				"evaluation_completeness":     models.EvaluationIdentityPolicyOnly,
				"evidence":                    "identity policy statement; Allow is not effective authorization",
				"resource_is_expression_only": stmt.ResourceIsExpressionOnly,
			}
			if len(stmt.Action) == 1 {
				props["action_value"] = stmt.Action[0]
			}
			rels = append(rels, models.Relationship{
				SourceARN:  role.ARN,
				TargetARN:  stmtARN,
				RelType:    models.RelPolicyPermissionCandidate,
				Properties: props,
			})
		}
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ARN < nodes[j].ARN })
	sort.Slice(rels, func(i, j int) bool {
		if rels[i].SourceARN == rels[j].SourceARN {
			if rels[i].RelType == rels[j].RelType {
				return rels[i].TargetARN < rels[j].TargetARN
			}
			return rels[i].RelType < rels[j].RelType
		}
		return rels[i].SourceARN < rels[j].SourceARN
	})
	return nodes, rels
}

func inlinePolicyARN(accountID, roleName, policyName string) string {
	return "arn:cloudrift:iam-inline-policy:::" + accountID + "/role/" + roleName + "/" + policyName
}

func statementARN(policyARN, statementID string) string {
	sum := sha256.Sum256([]byte(policyARN + "\n" + statementID))
	return "arn:cloudrift:iam-policy-statement:::" + hex.EncodeToString(sum[:8])
}
