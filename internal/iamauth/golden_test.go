package iamauth

import "testing"

// The golden corpus pins evaluator results to behavior AWS documents. A case names its source.
// The suite fails on any mismatch and, separately, on any false allow: a request expected to
// be anything other than VALIDATED_ALLOWED must never come back VALIDATED_ALLOWED.
const (
	docEval   = "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html"
	docCross  = "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic-cross-account.html"
	docBound  = "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html"
	docSCP    = "https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_evaluation.html"
	docKMS    = "https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html"
	docElem   = "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html"
	docCond   = "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html"
	docVars   = "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_variables.html"
	docAssume = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use.html"
)

type goldenCase struct {
	name   string
	source string
	want   string
	build  func() AuthorizationRequest
}

func bucketPolicy(effect, principal string, actions ...string) PolicySlot {
	return slotOf(StatementView{PolicyID: "bp", StatementID: "b", Effect: effect, Action: actions, Resource: []string{"arn:aws:s3:::data/*"},
		Principal: map[string]any{"AWS": principal}})
}

func getReq(mut func(*AuthorizationRequest)) func() AuthorizationRequest {
	return func() AuthorizationRequest {
		r := baseGet()
		if mut != nil {
			mut(&r)
		}
		return r
	}
}

func assumeReq(mut func(*AuthorizationRequest)) func() AuthorizationRequest {
	return func() AuthorizationRequest {
		r := baseGet()
		r.Action = ActionAssumeRole
		r.ResourceARN = "arn:aws:iam::111111111111:role/Target"
		r.Identity = statements("id", "A", "Allow", []string{"sts:AssumeRole"}, []string{r.ResourceARN}, nil)
		r.TrustPolicy = slotOf(StatementView{PolicyID: "trust", StatementID: "t", Effect: "Allow", Action: []string{"sts:AssumeRole"},
			Principal: map[string]any{"AWS": r.PrincipalARN}})
		if mut != nil {
			mut(&r)
		}
		return r
	}
}

func goldenCases() []goldenCase {
	const obj = "arn:aws:s3:::data/readme.txt"
	idAllow := func(actions []string, res []string, cond map[string]any) func(*AuthorizationRequest) {
		return func(r *AuthorizationRequest) { r.Identity = statements("id", "A", "Allow", actions, res, cond) }
	}
	return []goldenCase{
		{"same account identity allow", docEval, StatusAllowed, getReq(nil)},
		{"no matching allow is implicit, not a deny", docEval, StatusUnknown, getReq(idAllow([]string{"s3:GetObject"}, []string{"arn:aws:s3:::other/*"}, nil))},
		{"action wildcard", docEval, StatusAllowed, getReq(idAllow([]string{"s3:Get*"}, []string{obj}, nil))},
		{"action names are case-insensitive", docEval, StatusAllowed, getReq(idAllow([]string{"S3:getobject"}, []string{obj}, nil))},
		{"object keys are case-sensitive", docEval, StatusUnknown, getReq(idAllow([]string{"s3:GetObject"}, []string{"arn:aws:s3:::data/README.TXT"}, nil))},
		{"explicit identity deny beats allow", docEval, StatusDenied, getReq(func(r *AuthorizationRequest) {
			r.Identity = slotOf(stmt("id", "A", "Allow", []string{"s3:*"}, []string{"*"}, nil), stmt("id", "D", "Deny", []string{"s3:GetObject"}, []string{obj}, nil))
		})},
		{"explicit resource-policy deny beats identity allow", docEval, StatusDenied, getReq(func(r *AuthorizationRequest) {
			r.ResourcePolicy = bucketPolicy("Deny", "*", "s3:GetObject")
		})},
		{"same account resource policy alone grants", docCross, StatusAllowed, getReq(func(r *AuthorizationRequest) {
			r.Identity = PolicySlot{State: EvidenceAbsent, Evidence: "role has no policies"}
			r.ResourcePolicy = bucketPolicy("Allow", "arn:aws:iam::111111111111:role/App", "s3:GetObject")
		})},
		{"cross account needs both: identity only", docCross, StatusUnknown, getReq(func(r *AuthorizationRequest) {
			r.PrincipalARN = "arn:aws:iam::222222222222:role/Ext"
			r.Identity = statements("id", "A", "Allow", []string{"s3:GetObject"}, []string{obj}, nil)
		})},
		{"cross account needs both: resource only", docCross, StatusUnknown, getReq(func(r *AuthorizationRequest) {
			r.PrincipalARN = "arn:aws:iam::222222222222:role/Ext"
			r.Identity = PolicySlot{State: EvidenceAbsent, Evidence: "none"}
			r.ResourcePolicy = bucketPolicy("Allow", "arn:aws:iam::222222222222:role/Ext", "s3:GetObject")
		})},
		{"cross account with both sides", docCross, StatusAllowed, getReq(func(r *AuthorizationRequest) {
			r.PrincipalARN = "arn:aws:iam::222222222222:role/Ext"
			r.ResourcePolicy = bucketPolicy("Allow", "arn:aws:iam::222222222222:role/Ext", "s3:GetObject")
		})},
		{"boundary that does not allow", docBound, StatusUnknown, getReq(func(r *AuthorizationRequest) {
			r.PermissionsBoundary = statements("b", "B", "Allow", []string{"dynamodb:*"}, []string{"*"}, nil)
		})},
		{"boundary that allows", docBound, StatusAllowed, getReq(func(r *AuthorizationRequest) {
			r.PermissionsBoundary = statements("b", "B", "Allow", []string{"s3:*"}, []string{"*"}, nil)
		})},
		{"boundary deny", docBound, StatusDenied, getReq(func(r *AuthorizationRequest) {
			r.PermissionsBoundary = slotOf(stmt("b", "B", "Allow", []string{"s3:*"}, []string{"*"}, nil), stmt("b", "D", "Deny", []string{"s3:GetObject"}, []string{"*"}, nil))
		})},
		{"missing boundary evidence is not allowed", docBound, StatusUnknown, getReq(func(r *AuthorizationRequest) {
			r.PermissionsBoundary = PolicySlot{State: EvidenceMissing}
		})},
		{"SCP deny", docSCP, StatusDenied, getReq(func(r *AuthorizationRequest) {
			r.SCPs = statements("scp", "D", "Deny", []string{"s3:*"}, []string{"*"}, nil)
		})},
		{"SCP without an allow", docSCP, StatusUnknown, getReq(func(r *AuthorizationRequest) {
			r.SCPs = completeOrg(orgDoc("p-1", "acct", "111111111111", "Allow", []string{"dynamodb:*"}))
		})},
		{"missing SCP evidence is not allowed", docSCP, StatusUnknown, getReq(func(r *AuthorizationRequest) { r.SCPs = PolicySlot{State: EvidenceMissing} })},
		{"session policy narrows", docEval, StatusUnknown, getReq(func(r *AuthorizationRequest) {
			r.SessionPolicies = statements("s", "S", "Allow", []string{"s3:ListBucket"}, []string{"*"}, nil)
		})},
		{"NotAction allows other actions", docElem, StatusAllowed, getReq(func(r *AuthorizationRequest) {
			r.Identity = slotOf(StatementView{PolicyID: "id", StatementID: "N", Effect: "Allow", NotAction: []string{"s3:DeleteObject"}, Resource: []string{"*"}})
		})},
		{"condition satisfied", docCond, StatusAllowed, getReq(func(r *AuthorizationRequest) {
			idAllow([]string{"s3:GetObject"}, []string{obj}, map[string]any{"StringEquals": map[string]any{"aws:PrincipalTag/team": "data"}})(r)
			r.RequestContext = map[string]string{"aws:PrincipalTag/team": "data"}
		})},
		{"condition not satisfied", docCond, StatusUnknown, getReq(func(r *AuthorizationRequest) {
			idAllow([]string{"s3:GetObject"}, []string{obj}, map[string]any{"StringEquals": map[string]any{"aws:PrincipalTag/team": "data"}})(r)
			r.RequestContext = map[string]string{"aws:PrincipalTag/team": "ops"}
		})},
		{"condition key absent is conditional", docCond, StatusConditional, getReq(idAllow([]string{"s3:GetObject"}, []string{obj}, map[string]any{"Bool": map[string]any{"aws:SecureTransport": "true"}}))},
		{"IP condition inside range", docCond, StatusAllowed, getReq(func(r *AuthorizationRequest) {
			idAllow([]string{"s3:GetObject"}, []string{obj}, map[string]any{"IpAddress": map[string]any{"aws:SourceIp": "203.0.113.0/24"}})(r)
			r.RequestContext = map[string]string{"aws:SourceIp": "203.0.113.9"}
		})},
		{"IP condition outside range", docCond, StatusUnknown, getReq(func(r *AuthorizationRequest) {
			idAllow([]string{"s3:GetObject"}, []string{obj}, map[string]any{"IpAddress": map[string]any{"aws:SourceIp": "203.0.113.0/24"}})(r)
			r.RequestContext = map[string]string{"aws:SourceIp": "198.51.100.9"}
		})},
		{"unsupported operator cannot be decided", docCond, StatusUnknown, getReq(idAllow([]string{"s3:GetObject"}, []string{obj}, map[string]any{"DateGreaterThan": map[string]any{"aws:CurrentTime": "2020-01-01T00:00:00Z"}}))},
		{"deny with an unsupported condition cannot be ruled out", docEval, StatusUnknown, getReq(func(r *AuthorizationRequest) {
			r.Identity = slotOf(stmt("id", "A", "Allow", []string{"s3:*"}, []string{"*"}, nil),
				stmt("id", "D", "Deny", []string{"s3:GetObject"}, []string{"*"}, map[string]any{"DateLessThan": map[string]any{"aws:CurrentTime": "2030-01-01T00:00:00Z"}}))
		})},
		{"policy variable resolves", docVars, StatusAllowed, getReq(func(r *AuthorizationRequest) {
			r.ResourceARN = "arn:aws:s3:::data/home/ann/f.txt"
			idAllow([]string{"s3:GetObject"}, []string{"arn:aws:s3:::data/home/${aws:username}/*"}, nil)(r)
			r.RequestContext = map[string]string{"aws:username": "ann"}
		})},
		{"policy variable for another user", docVars, StatusUnknown, getReq(func(r *AuthorizationRequest) {
			r.ResourceARN = "arn:aws:s3:::data/home/ann/f.txt"
			idAllow([]string{"s3:GetObject"}, []string{"arn:aws:s3:::data/home/${aws:username}/*"}, nil)(r)
			r.RequestContext = map[string]string{"aws:username": "bob"}
		})},
		{"assume role needs identity and trust", docAssume, StatusAllowed, assumeReq(nil)},
		{"assume role: trust alone is not enough", docAssume, StatusUnknown, assumeReq(func(r *AuthorizationRequest) { r.Identity = PolicySlot{State: EvidenceAbsent, Evidence: "none"} })},
		{"assume role: identity alone is not enough", docAssume, StatusUnknown, assumeReq(func(r *AuthorizationRequest) {
			r.TrustPolicy = slotOf(StatementView{PolicyID: "trust", StatementID: "t", Effect: "Allow", Action: []string{"sts:AssumeRole"}, Principal: map[string]any{"AWS": "arn:aws:iam::111111111111:role/Someone"}})
		})},
		{"assume role: trust names the account root", docAssume, StatusAllowed, assumeReq(func(r *AuthorizationRequest) {
			r.TrustPolicy = slotOf(StatementView{PolicyID: "trust", StatementID: "t", Effect: "Allow", Action: []string{"sts:AssumeRole"}, Principal: map[string]any{"AWS": "arn:aws:iam::111111111111:root"}})
		})},
		{"kms root delegation needs the identity policy", docKMS, StatusUnknown, func() AuthorizationRequest {
			r := baseGet()
			r.Action, r.ResourceARN = "kms:Decrypt", keyARN
			r.Identity = statements("id", "A", "Allow", []string{"s3:*"}, []string{"*"}, nil)
			r.ResourcePolicy = slotOf(keyStmt("Allow", "arn:aws:iam::111111111111:root", nil))
			return r
		}},
		{"kms key policy naming the role grants without identity", docKMS, StatusAllowed, func() AuthorizationRequest {
			r := baseGet()
			r.Action, r.ResourceARN = "kms:Decrypt", keyARN
			r.Identity = statements("id", "A", "Allow", []string{"s3:*"}, []string{"*"}, nil)
			r.ResourcePolicy = slotOf(keyStmt("Allow", roleARN, nil))
			return r
		}},
		{"secret with aws managed key", docEval, StatusAllowed, func() AuthorizationRequest {
			r := baseGet()
			r.Action, r.ResourceARN = "secretsmanager:GetSecretValue", secretARN
			r.Identity = statements("id", "A", "Allow", []string{"secretsmanager:GetSecretValue"}, []string{secretARN}, nil)
			r.SecretKMS = &SecretKMSEvidence{Mode: SecretKeyAWSManaged}
			return r
		}},
		{"ec2 instance identity allow", docEval, StatusAllowed, func() AuthorizationRequest {
			r := baseGet()
			r.Action, r.ResourceARN = "ec2:StopInstances", "arn:aws:ec2:us-east-1:111111111111:instance/i-1"
			r.Identity = statements("id", "A", "Allow", []string{"ec2:StopInstances"}, []string{"*"}, nil)
			return r
		}},
		{"malformed policy is never an allow", docEval, StatusUnknown, getReq(func(r *AuthorizationRequest) {
			r.Identity = PolicySlot{State: EvidencePresent, Documents: []PolicyDocument{{ID: "bad", PolicyType: "inline", Raw: "{not json"}}}
		})},
	}
}

func TestGoldenCorpus(t *testing.T) {
	cases := goldenCases()
	var falseAllow, expectedAllow, gotAllow int
	for _, c := range cases {
		d := Evaluate(c.build())
		if c.want == StatusAllowed {
			expectedAllow++
		}
		if d.Status == StatusAllowed {
			gotAllow++
			if c.want != StatusAllowed {
				falseAllow++
				t.Errorf("FALSE ALLOW %q (%s)", c.name, c.source)
			}
		}
		if d.Status != c.want {
			t.Errorf("%q: want %s got %s (%s)\n  source: %s", c.name, c.want, d.Status, d.Reason, c.source)
		}
	}
	t.Logf("golden corpus: %d cases, expected allows %d, evaluator allows %d, false allows %d", len(cases), expectedAllow, gotAllow, falseAllow)
	if falseAllow != 0 {
		t.Fatalf("%d false allows: the evaluator must never validate access that AWS would not grant", falseAllow)
	}
}
