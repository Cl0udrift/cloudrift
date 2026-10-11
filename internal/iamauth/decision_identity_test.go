package iamauth

import "testing"

func TestDecisionIdentity_ContextAndEvidence(t *testing.T) {
	first := Evaluate(baseGet())
	again := Evaluate(baseGet())
	if first.ID == "" || first.ID != again.ID || first.EvidenceFingerprint != again.EvidenceFingerprint {
		t.Fatalf("identical request changed identity: %s %s", first.ID, again.ID)
	}

	session := baseGet()
	session.SessionPolicies = PolicySlot{State: EvidencePresent, Documents: []PolicyDocument{{
		ID: "session", PolicyType: "session",
		Statements: []StatementView{{Effect: "Allow", Action: []string{"s3:GetObject"}, Resource: []string{"arn:aws:s3:::data/readme.txt"}}},
	}}}
	if Evaluate(session).ID == first.ID {
		t.Fatal("a different session policy reused the decision")
	}

	mfa := baseGet()
	mfa.RequestContext = map[string]string{"aws:MultiFactorAuthPresent": "true"}
	otherMFA := baseGet()
	otherMFA.RequestContext = map[string]string{"aws:MultiFactorAuthPresent": "false"}
	if Evaluate(mfa).ID == Evaluate(otherMFA).ID || Evaluate(mfa).ID == first.ID {
		t.Fatal("MFA context did not change the decision")
	}

	scp := baseGet()
	scp.SCPs = PolicySlot{State: EvidencePresent, Documents: []PolicyDocument{{
		ID: "scp", PolicyType: "scp", Raw: `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
	}}}
	if Evaluate(scp).ID == first.ID || DecisionCurrent(first.EvidenceFingerprint, scp) {
		t.Fatal("changed SCP reused the allow")
	}

	policy := baseGet()
	policy.Identity = statements("id", "Allow", "Allow", []string{"s3:GetObject"}, []string{"arn:aws:s3:::data/other"}, nil)
	if Evaluate(policy).ID == first.ID {
		t.Fatal("changed identity policy reused the decision")
	}

	otherScan := baseGet()
	otherScan.ScanID = "scan-b"
	if Evaluate(otherScan).ID == first.ID {
		t.Fatal("a different scan reused the decision")
	}

	missing := baseGet()
	missing.Identity = PolicySlot{State: EvidenceMissing, Evidence: "documents were not collected"}
	if DecisionCurrent(first.EvidenceFingerprint, missing) || Evaluate(missing).Status == StatusAllowed {
		t.Fatal("missing evidence reused a historical allow")
	}
}
