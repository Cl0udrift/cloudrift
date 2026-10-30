package models

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const (
	PolicyTypeInline  = "inline"
	PolicyTypeManaged = "managed"

	PolicyRetrievalOK        = "ok"
	PolicyRetrievalMissing   = "missing"
	PolicyRetrievalMalformed = "malformed"
	PolicyRetrievalPartial   = "partial"

	// EvaluationUnevaluated means the statement was collected, not authorized.
	// Allow is not effective permission.
	EvaluationUnevaluated = "unevaluated"
	// EvaluationIdentityPolicyOnly means SCP, RCP, permission boundary, session
	// policy, and resource policy were not evaluated.
	EvaluationIdentityPolicyOnly = "identity_policy_document_only"

	// Candidate evidence states. They are not authorization outcomes.
	EvidenceDeclared    = "DECLARED"
	EvidenceConditional = "CONDITIONAL"
	EvidenceUnknown     = "UNKNOWN_EVIDENCE"
	EvidenceUnsupported = "UNSUPPORTED_CONSTRUCT"
	EvidenceDeny        = "DENY_EVIDENCE"

	// Policy version verification describes the snapshot, not the policy as it exists now.
	PolicyVersionVerified      = "verified"
	PolicyVersionUnverified    = "unverified"
	PolicyVersionMismatch      = "mismatch"
	PolicyVersionIndeterminate = "indeterminate"
	PolicyVersionMissing       = "missing"
	PolicyVersionNotApplicable = "not_applicable"
)

// IAMPolicyStatement is one normalized identity-policy statement.
// Action, NotAction, Resource, and NotResource keep IAM's string-or-array shape as lists.
// A resource value of "*" stays an expression. It is not an asset ARN.
type IAMPolicyStatement struct {
	PolicyID                 string         `json:"policy_id"`
	StatementID              string         `json:"statement_id"`
	PolicyType               string         `json:"policy_type"`
	Effect                   string         `json:"effect"`
	Action                   []string       `json:"action,omitempty"`
	NotAction                []string       `json:"not_action,omitempty"`
	Resource                 []string       `json:"resource,omitempty"`
	NotResource              []string       `json:"not_resource,omitempty"`
	Condition                map[string]any `json:"condition,omitempty"`
	Principal                map[string]any `json:"principal,omitempty"`
	NotPrincipal             map[string]any `json:"not_principal,omitempty"`
	SourceAccount            string         `json:"source_account,omitempty"`
	EvaluationCompleteness   string         `json:"evaluation_completeness"`
	EvaluationStatus         string         `json:"evaluation_status"`
	EvidenceRef              string         `json:"evidence_ref,omitempty"`
	ResourceIsExpressionOnly bool           `json:"resource_is_expression_only"`
}

// NormalizeIdentityPolicy parses an identity policy document.
// Malformed JSON returns an error. A document with no statements returns an empty slice and no error.
// Deny, NotAction, NotResource, and Condition are retained.
func NormalizeIdentityPolicy(policyID, policyType, sourceAccount, raw string) ([]IAMPolicyStatement, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty policy document")
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil, fmt.Errorf("malformed policy document: %w", err)
	}
	statements, ok := policyStatementValues(doc["Statement"])
	if !ok {
		return nil, fmt.Errorf("malformed policy document: Statement is not an object or array")
	}
	out := make([]IAMPolicyStatement, 0, len(statements))
	for i, rawStmt := range statements {
		stmt, ok := rawStmt.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("malformed policy document: statement %d is not an object", i)
		}
		sid := strings.TrimSpace(stringField(stmt, "Sid"))
		if sid == "" {
			sid = fmt.Sprintf("stmt-%d", i+1)
		}
		actions := policyStringList(stmt["Action"])
		notActions := policyStringList(stmt["NotAction"])
		resources := policyStringList(stmt["Resource"])
		notResources := policyStringList(stmt["NotResource"])
		out = append(out, IAMPolicyStatement{
			PolicyID:                 policyID,
			StatementID:              sid,
			PolicyType:               policyType,
			Effect:                   strings.TrimSpace(stringField(stmt, "Effect")),
			Action:                   actions,
			NotAction:                notActions,
			Resource:                 resources,
			NotResource:              notResources,
			Condition:                objectField(stmt["Condition"]),
			Principal:                principalField(stmt["Principal"]),
			NotPrincipal:             principalField(stmt["NotPrincipal"]),
			SourceAccount:            sourceAccount,
			EvaluationCompleteness:   EvaluationIdentityPolicyOnly,
			EvaluationStatus:         EvaluationUnevaluated,
			EvidenceRef:              policyID + "#" + sid,
			ResourceIsExpressionOnly: resourceExpressionOnly(resources, notResources),
		})
	}
	return out, nil
}

func policyStatementValues(v any) ([]any, bool) {
	switch t := v.(type) {
	case nil:
		return nil, true
	case map[string]any:
		return []any{t}, true
	case []any:
		return t, true
	default:
		return nil, false
	}
}

func policyStringList(v any) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return nil
		}
		return []string{s}
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			s, ok := item.(string)
			if !ok {
				continue
			}
			s = strings.TrimSpace(s)
			if s != "" {
				out = append(out, s)
			}
		}
		sort.Strings(out)
		return out
	default:
		return nil
	}
}

func stringField(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func principalField(v any) map[string]any {
	switch t := v.(type) {
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return nil
		}
		return map[string]any{"AWS": s}
	case map[string]any:
		return objectField(t)
	default:
		return nil
	}
}

func objectField(v any) map[string]any {
	m, _ := v.(map[string]any)
	if len(m) == 0 {
		return nil
	}
	return m
}

func resourceExpressionOnly(resources, notResources []string) bool {
	if len(resources) == 0 && len(notResources) == 0 {
		return true
	}
	for _, r := range append(append([]string{}, resources...), notResources...) {
		if strings.Contains(r, "*") || !strings.HasPrefix(r, "arn:") {
			return true
		}
	}
	return false
}
