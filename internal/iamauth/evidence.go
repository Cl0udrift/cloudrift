package iamauth

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// SlotFromStatus maps a collected observation onto an evaluator slot.
// Confirmed absence without supporting evidence stays missing.
// A named policy without its document stays missing.
func SlotFromStatus(status, evidence string, docs []PolicyDocument) PolicySlot {
	evidence = strings.TrimSpace(evidence)
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "present", EvidencePresent:
		if !documentsHaveBody(docs) {
			note := evidence
			if note == "" {
				note = "policy was identified but its document was not collected"
			}
			return PolicySlot{State: EvidenceMissing, Evidence: note}
		}
		return PolicySlot{State: EvidencePresent, Evidence: evidence, Documents: docs}
	case "confirmed_absent", EvidenceAbsent:
		if evidence == "" {
			return PolicySlot{State: EvidenceMissing, Evidence: "confirmed absence requires supporting evidence"}
		}
		return PolicySlot{State: EvidenceAbsent, Evidence: evidence}
	case "unsupported":
		if evidence == "" {
			evidence = "control is not supported by the evaluator"
		}
		return PolicySlot{State: EvidenceMissing, Evidence: evidence}
	default:
		return PolicySlot{State: EvidenceMissing, Evidence: evidence}
	}
}

func documentsHaveBody(docs []PolicyDocument) bool {
	for _, doc := range docs {
		if strings.TrimSpace(doc.Raw) != "" || len(doc.Statements) > 0 {
			return true
		}
	}
	return false
}

// EvidenceFingerprint identifies the evidence used for one request.
// A policy change produces a different fingerprint, so a stored decision
// with the old fingerprint is not current.
func EvidenceFingerprint(req AuthorizationRequest) string {
	var b strings.Builder
	writeSlot(&b, "identity", req.Identity)
	writeSlot(&b, "resource", req.ResourcePolicy)
	writeSlot(&b, "trust", req.TrustPolicy)
	writeSlot(&b, "boundary", req.PermissionsBoundary)
	writeSlot(&b, "session", req.SessionPolicies)
	writeSlot(&b, "scp", req.SCPs)
	writeSlot(&b, "rcp", req.RCPs)
	b.WriteString("acl=")
	b.WriteString(req.S3ObjectACL)
	b.WriteString("\nbpa=")
	b.WriteString(req.S3BlockPublicAccess)
	b.WriteString("\nkms=")
	b.WriteString(req.S3KMSKeyPolicy)
	b.WriteString("\nctx=")
	b.WriteString(canonicalContext(req.RequestContext))
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:8])
}

// DecisionCurrent reports whether a stored decision still matches the evidence
// that would be evaluated now.
func DecisionCurrent(storedFingerprint string, req AuthorizationRequest) bool {
	storedFingerprint = strings.TrimSpace(storedFingerprint)
	return storedFingerprint != "" && storedFingerprint == EvidenceFingerprint(req)
}

func writeSlot(b *strings.Builder, name string, slot PolicySlot) {
	b.WriteString(name)
	b.WriteString("=")
	b.WriteString(slot.State)
	b.WriteString("|")
	b.WriteString(slot.Evidence)
	if slot.HierarchyComplete {
		b.WriteString("|hierarchy=complete")
	} else {
		b.WriteString("|hierarchy=unrecorded")
	}
	targets := append([]string{}, slot.RequiredTargets...)
	sort.Strings(targets)
	b.WriteString("|targets=")
	b.WriteString(strings.Join(targets, ","))
	ids := make([]string, 0, len(slot.Documents))
	for _, doc := range slot.Documents {
		ids = append(ids, doc.ID+"\n"+doc.AttachmentLevel+"\n"+doc.AttachmentTarget+"\n"+doc.Raw+"\n"+statementCanon(doc.Statements))
	}
	sort.Strings(ids)
	for _, id := range ids {
		b.WriteString("\n")
		b.WriteString(id)
	}
	b.WriteString("\n")
}

func statementCanon(stmts []StatementView) string {
	parts := make([]string, 0, len(stmts))
	for _, stmt := range stmts {
		parts = append(parts, stmt.PolicyID+"|"+stmt.StatementID+"|"+stmt.Effect+"|"+strings.Join(stmt.Action, ",")+"|"+strings.Join(stmt.Resource, ","))
	}
	sort.Strings(parts)
	return strings.Join(parts, ";")
}
