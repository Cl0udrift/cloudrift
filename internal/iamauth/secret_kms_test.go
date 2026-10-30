package iamauth

import "testing"

const (
	secretARN = "arn:aws:secretsmanager:us-east-1:111111111111:secret:db-AbCdEf"
	keyARN    = "arn:aws:kms:us-east-1:111111111111:key/k1"
	roleARN   = "arn:aws:iam::111111111111:role/App"
)

func slotOf(stmts ...StatementView) PolicySlot {
	return PolicySlot{State: EvidencePresent, Documents: []PolicyDocument{{ID: "doc", PolicyType: "inline", Statements: stmts}}}
}

func keyStmt(effect string, principal any, cond map[string]any) StatementView {
	return StatementView{
		PolicyID: "key", StatementID: "k", Effect: effect, Action: []string{"kms:*"}, Resource: []string{"*"},
		Principal: map[string]any{"AWS": principal}, Condition: cond,
	}
}

func secretReq(identityActions ...string) AuthorizationRequest {
	req := baseGet()
	req.Action = "secretsmanager:GetSecretValue"
	req.ResourceARN = secretARN
	req.Identity = slotOf(
		stmt("id", "S", "Allow", []string{"secretsmanager:GetSecretValue"}, []string{secretARN}, nil),
		stmt("id", "K", "Allow", identityActions, []string{keyARN}, nil),
	)
	req.SecretKMS = &SecretKMSEvidence{Mode: SecretKeyCustomerManaged, KeyARN: keyARN,
		KeyPolicy: slotOf(keyStmt("Allow", "arn:aws:iam::111111111111:root", nil))}
	return req
}

func TestSecret_AWSManagedKey(t *testing.T) {
	req := baseGet()
	req.Action = "secretsmanager:GetSecretValue"
	req.ResourceARN = secretARN
	req.Identity = statements("id", "S", "Allow", []string{"secretsmanager:GetSecretValue"}, []string{secretARN}, nil)
	req.SecretKMS = &SecretKMSEvidence{Mode: SecretKeyAWSManaged}
	if d := Evaluate(req); d.Status != StatusAllowed {
		t.Fatalf("same account aws/secretsmanager: %+v", d)
	}
	req.PrincipalARN = "arn:aws:iam::222222222222:role/Other"
	req.Identity = statements("id", "S", "Allow", []string{"secretsmanager:GetSecretValue"}, []string{secretARN}, nil)
	req.ResourcePolicy = slotOf(StatementView{PolicyID: "rp", StatementID: "x", Effect: "Allow", Action: []string{"secretsmanager:GetSecretValue"}, Resource: []string{"*"},
		Principal: map[string]any{"AWS": req.PrincipalARN}})
	if d := Evaluate(req); d.Status != StatusUnknown || d.Reason != ReasonKMSCrossAccountAWS {
		t.Fatalf("cross account needs a customer key: %+v", d)
	}
}

func TestSecret_CustomerKeyLegs(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*AuthorizationRequest)
		status string
		reason string
	}{
		{"root delegation plus identity", func(r *AuthorizationRequest) {}, StatusAllowed, ReasonAllowed},
		{"key evidence nil", func(r *AuthorizationRequest) { r.SecretKMS = nil }, StatusUnknown, ReasonMissingKMS},
		{"key policy missing", func(r *AuthorizationRequest) {
			r.SecretKMS.KeyPolicy = PolicySlot{State: EvidenceMissing}
		}, StatusUnknown, ReasonMissingKMS},
		{"root delegation but identity lacks decrypt", func(r *AuthorizationRequest) {
			r.Identity = statements("id", "S", "Allow", []string{"secretsmanager:GetSecretValue"}, []string{secretARN}, nil)
		}, StatusUnknown, ReasonKMSNotAllowed},
		{"direct key grant needs no identity decrypt", func(r *AuthorizationRequest) {
			r.Identity = statements("id", "S", "Allow", []string{"secretsmanager:GetSecretValue"}, []string{secretARN}, nil)
			r.SecretKMS.KeyPolicy = slotOf(keyStmt("Allow", roleARN, nil))
		}, StatusAllowed, ReasonAllowed},
		{"key policy names someone else", func(r *AuthorizationRequest) {
			r.SecretKMS.KeyPolicy = slotOf(keyStmt("Allow", "arn:aws:iam::111111111111:role/Other", nil))
		}, StatusUnknown, ReasonKMSNotAllowed},
		{"key policy deny", func(r *AuthorizationRequest) {
			r.SecretKMS.KeyPolicy = slotOf(keyStmt("Allow", "arn:aws:iam::111111111111:root", nil), keyStmt("Deny", roleARN, nil))
		}, StatusDenied, ReasonExplicitDeny},
		{"deny aimed at account root", func(r *AuthorizationRequest) {
			r.SecretKMS.KeyPolicy = slotOf(keyStmt("Allow", "arn:aws:iam::111111111111:root", nil), keyStmt("Deny", "arn:aws:iam::111111111111:root", nil))
		}, StatusDenied, ReasonExplicitDeny}, // a Deny on an account root covers every principal in that account
		{"boundary allows secret but not decrypt", func(r *AuthorizationRequest) {
			r.PermissionsBoundary = statements("b", "B", "Allow", []string{"secretsmanager:*"}, []string{"*"}, nil)
		}, StatusUnknown, ReasonBoundaryNoAllow},
		{"viaservice condition is satisfied by the call", func(r *AuthorizationRequest) {
			r.SecretKMS.KeyPolicy = slotOf(keyStmt("Allow", "arn:aws:iam::111111111111:root", map[string]any{
				"StringEquals": map[string]any{"kms:ViaService": "secretsmanager.us-east-1.amazonaws.com", "kms:CallerAccount": "111111111111"},
			}))
		}, StatusAllowed, ReasonAllowed},
		{"viaservice for another service", func(r *AuthorizationRequest) {
			r.SecretKMS.KeyPolicy = slotOf(keyStmt("Allow", "arn:aws:iam::111111111111:root", map[string]any{
				"StringEquals": map[string]any{"kms:ViaService": "s3.us-east-1.amazonaws.com"},
			}))
		}, StatusUnknown, ReasonKMSNotAllowed},
		{"bad secret arn", func(r *AuthorizationRequest) { r.ResourceARN = "arn:aws:s3:::bucket/key" }, StatusUnknown, ReasonResourceShape},
	}
	for _, c := range cases {
		req := secretReq("kms:Decrypt")
		c.mutate(&req)
		d := Evaluate(req)
		if d.Status != c.status || (c.reason != "" && d.Reason != c.reason) {
			t.Errorf("%s: got %s/%s want %s/%s", c.name, d.Status, d.Reason, c.status, c.reason)
		}
	}
}

func TestSecret_CrossAccountNeedsBothSides(t *testing.T) {
	req := secretReq("kms:Decrypt")
	req.PrincipalARN = "arn:aws:iam::222222222222:role/Ext"
	req.ResourceAccountID = "111111111111"
	req.Identity = slotOf(
		stmt("id", "S", "Allow", []string{"secretsmanager:GetSecretValue"}, []string{secretARN}, nil),
		stmt("id", "K", "Allow", []string{"kms:Decrypt"}, []string{keyARN}, nil),
	)
	req.ResourcePolicy = slotOf(StatementView{PolicyID: "rp", StatementID: "x", Effect: "Allow", Action: []string{"secretsmanager:GetSecretValue"}, Resource: []string{"*"},
		Principal: map[string]any{"AWS": "arn:aws:iam::222222222222:role/Ext"}})
	// key policy trusts only the key owner account root: the external role is not granted
	if d := Evaluate(req); d.Status == StatusAllowed {
		t.Fatalf("external role must not decrypt through the owner's root: %+v", d)
	}
	req.SecretKMS.KeyPolicy = slotOf(keyStmt("Allow", "arn:aws:iam::222222222222:root", nil))
	if d := Evaluate(req); d.Status != StatusAllowed {
		t.Fatalf("key policy delegating to the caller account plus identity allow: %+v", d)
	}
	req.Identity = statements("id", "S", "Allow", []string{"secretsmanager:GetSecretValue"}, []string{secretARN}, nil)
	if d := Evaluate(req); d.Status == StatusAllowed {
		t.Fatalf("cross-account decrypt needs the caller identity policy too: %+v", d)
	}
}

func TestKMSDecryptDirect(t *testing.T) {
	req := baseGet()
	req.Action = "kms:Decrypt"
	req.ResourceARN = keyARN
	req.Identity = statements("id", "K", "Allow", []string{"kms:Decrypt"}, []string{keyARN}, nil)
	req.ResourcePolicy = slotOf(keyStmt("Allow", "arn:aws:iam::111111111111:root", nil))
	if d := Evaluate(req); d.Status != StatusAllowed {
		t.Fatalf("root delegation plus identity: %+v", d)
	}
	req.Identity = statements("id", "K", "Allow", []string{"s3:GetObject"}, []string{"*"}, nil)
	if d := Evaluate(req); d.Status != StatusUnknown {
		t.Fatalf("root delegation without identity allow: %+v", d)
	}
	req.ResourcePolicy = PolicySlot{State: EvidenceAbsent, Evidence: "x"}
	if d := Evaluate(req); d.Status != StatusUnknown || d.Reason != ReasonMissingKMS {
		t.Fatalf("a key always has a policy; absence is invalid: %+v", d)
	}
}

func TestSecretFingerprintCoversKeyEvidence(t *testing.T) {
	a := secretReq("kms:Decrypt")
	b := secretReq("kms:Decrypt")
	b.SecretKMS.KeyPolicy = slotOf(keyStmt("Allow", roleARN, nil))
	if EvidenceFingerprint(a) == EvidenceFingerprint(b) {
		t.Fatal("changing the key policy must change the evidence fingerprint")
	}
}

func TestEC2Instances(t *testing.T) {
	const inst = "arn:aws:ec2:us-east-1:111111111111:instance/i-0abc"
	req := baseGet()
	req.Action = "ec2:StopInstances"
	req.ResourceARN = inst
	req.Identity = statements("id", "E", "Allow", []string{"ec2:StopInstances"}, []string{"*"}, nil)
	if d := Evaluate(req); d.Status != StatusAllowed {
		t.Fatalf("identity allow: %+v", d)
	}
	req.Identity = statements("id", "E", "Allow", []string{"ec2:StopInstances"}, []string{"*"}, map[string]any{
		"StringEquals": map[string]any{"ec2:ResourceTag/env": "dev"},
	})
	if d := Evaluate(req); d.Status != StatusConditional {
		t.Fatalf("tag condition without tags must be conditional: %+v", d)
	}
	req.Identity = slotOf(
		stmt("id", "E", "Allow", []string{"ec2:*"}, []string{"*"}, nil),
		stmt("id", "D", "Deny", []string{"ec2:TerminateInstances"}, []string{"*"}, nil),
	)
	req.Action = "ec2:TerminateInstances"
	if d := Evaluate(req); d.Status != StatusDenied {
		t.Fatalf("explicit deny: %+v", d)
	}
	req.PrincipalARN = "arn:aws:iam::222222222222:role/Ext"
	if d := Evaluate(req); d.Status == StatusAllowed || d.Status == StatusDenied && d.Reason != ReasonExplicitDeny {
		t.Fatalf("cross-account instance access cannot be validated: %+v", d)
	}
	req.ResourceARN = "arn:aws:s3:::bucket/key"
	if d := Evaluate(req); d.Status != StatusUnknown || d.Reason != ReasonResourceShape {
		t.Fatalf("shape: %+v", d)
	}
}

func TestKMSGrants(t *testing.T) {
	req := baseGet()
	req.Action = "kms:Decrypt"
	req.ResourceARN = keyARN
	req.Identity = statements("id", "X", "Allow", []string{"s3:GetObject"}, []string{"*"}, nil)
	req.ResourcePolicy = slotOf(keyStmt("Allow", "arn:aws:iam::999999999999:role/Someone", nil))
	if d := Evaluate(req); d.Status == StatusAllowed {
		t.Fatalf("no grant yet: %+v", d)
	}
	req.KMSGrants = []KMSGrant{{GranteePrincipal: roleARN, Operations: []string{"Decrypt"}, Constrained: true}}
	if d := Evaluate(req); d.Status == StatusAllowed {
		t.Fatalf("a constrained grant must not validate access: %+v", d)
	}
	req.KMSGrants = []KMSGrant{{GranteePrincipal: "arn:aws:iam::111111111111:role/Other", Operations: []string{"Decrypt"}}}
	if d := Evaluate(req); d.Status == StatusAllowed {
		t.Fatalf("grant to another principal: %+v", d)
	}
	req.KMSGrants = []KMSGrant{{GranteePrincipal: roleARN, Operations: []string{"Decrypt"}}}
	if d := Evaluate(req); d.Status != StatusAllowed {
		t.Fatalf("unconstrained grant to the caller: %+v", d)
	}
	req.ResourcePolicy = slotOf(keyStmt("Deny", roleARN, nil))
	if d := Evaluate(req); d.Status != StatusDenied {
		t.Fatalf("a key policy deny beats a grant: %+v", d)
	}
}

func TestSecretUsesKeyGrant(t *testing.T) {
	req := secretReq("s3:GetObject") // identity has no kms:Decrypt
	req.SecretKMS.KeyPolicy = slotOf(keyStmt("Allow", "arn:aws:iam::999999999999:role/Someone", nil))
	if d := Evaluate(req); d.Status == StatusAllowed {
		t.Fatalf("setup should not allow: %+v", d)
	}
	req.SecretKMS.Grants = []KMSGrant{{GranteePrincipal: roleARN, Operations: []string{"Decrypt"}}}
	if d := Evaluate(req); d.Status != StatusAllowed {
		t.Fatalf("grant on the secret's key: %+v", d)
	}
}

func TestLambdaFunctionPolicy(t *testing.T) {
	const fn = "arn:aws:lambda:us-east-1:111111111111:function:demo"
	req := baseGet()
	req.Action = "lambda:UpdateFunctionCode"
	req.ResourceARN = fn
	req.Identity = statements("id", "L", "Allow", []string{"lambda:UpdateFunctionCode"}, []string{fn}, nil)
	req.ResourcePolicy = PolicySlot{State: EvidenceAbsent, Evidence: "GetPolicy returned ResourceNotFound"}
	if d := Evaluate(req); d.Status != StatusAllowed {
		t.Fatalf("identity allow, no function policy: %+v", d)
	}
	req.ResourcePolicy = PolicySlot{State: EvidenceMissing}
	if d := Evaluate(req); d.Status != StatusUnknown || d.Reason != ReasonMissingResource {
		t.Fatalf("an uncollected function policy could hold a Deny: %+v", d)
	}
	req.ResourcePolicy = slotOf(StatementView{PolicyID: "fp", StatementID: "d", Effect: "Deny", Action: []string{"lambda:UpdateFunctionCode"}, Resource: []string{fn},
		Principal: map[string]any{"AWS": "*"}})
	if d := Evaluate(req); d.Status != StatusDenied {
		t.Fatalf("function policy deny: %+v", d)
	}
	req.PrincipalARN = "arn:aws:iam::222222222222:role/Ext"
	req.ResourcePolicy = PolicySlot{State: EvidenceAbsent, Evidence: "none"}
	if d := Evaluate(req); d.Status == StatusAllowed {
		t.Fatalf("cross-account needs the function policy: %+v", d)
	}
}

func TestRDSInstances(t *testing.T) {
	const db = "arn:aws:rds:us-east-1:111111111111:db:orders"
	req := baseGet()
	req.Action = "rds:DeleteDBInstance"
	req.ResourceARN = db
	req.Identity = statements("id", "R", "Allow", []string{"rds:Delete*"}, []string{"*"}, nil)
	if d := Evaluate(req); d.Status != StatusAllowed {
		t.Fatalf("%+v", d)
	}
	req.PermissionsBoundary = statements("b", "B", "Allow", []string{"s3:*"}, []string{"*"}, nil)
	if d := Evaluate(req); d.Status == StatusAllowed {
		t.Fatalf("boundary without rds must block: %+v", d)
	}
	req.PermissionsBoundary = PolicySlot{State: EvidenceAbsent}
	req.ResourceARN = "arn:aws:rds:us-east-1:111111111111:cluster:orders"
	if d := Evaluate(req); d.Reason != ReasonResourceShape {
		t.Fatalf("cluster ARN is not a DB instance: %+v", d)
	}
}
