package iamauth

import (
	"fmt"
	"sort"
	"testing"
)

// A generated corpus: every combination of principal type, account relation, resource-policy principal, identity,
// permissions boundary, session policy and SCP for s3:GetObject. The expected result is decided by flowOracle, written
// from the AWS evaluation-logic pages (not from the evaluator), so a disagreement is a finding either way:
//   - the evaluator allows what the oracle does not: a FALSE ALLOW, the one failure that is never acceptable;
//   - the evaluator denies/allows differently on an explicit deny: a bug;
//   - the evaluator withholds an allow the oracle gives: a SAFE MISS, counted and listed.
//
// Sources: docEval and docCross (same and cross account), docBound ("Resource-based policies" for users, roles and
// role sessions), docSCP.
type flowCase struct {
	principal string // user | role | session
	same      bool   // the resource is in the caller's account
	res       string // none | self | root_caller | star | other | root_other | deny
	ident     string // allow | none | deny
	bound     string // none | allow | noallow | deny
	sess      string // none | allow | noallow | deny (sessions only)
	scp       string // none | allow | noallow | deny
}

func (c flowCase) String() string {
	return fmt.Sprintf("%s same=%v res=%s ident=%s bound=%s sess=%s scp=%s", c.principal, c.same, c.res, c.ident, c.bound, c.sess, c.scp)
}

const (
	flowOutAllowed    = "allowed"
	flowOutDenied     = "denied"
	flowOutNotAllowed = "not_allowed"
	flowOutAmbiguous  = "ambiguous" // the AWS pages do not say; no assertion
)

func flowOracle(c flowCase) string {
	if c.ident == "deny" || c.res == "deny" || c.bound == "deny" || c.sess == "deny" || c.scp == "deny" {
		return flowOutDenied
	}
	scpOK := c.scp == "none" || c.scp == "allow"
	boundOK := c.bound == "none" || c.bound == "allow"
	sessOK := c.sess == "none" || c.sess == "allow"
	if !scpOK {
		return flowOutNotAllowed
	}
	identity := c.ident == "allow"
	if !c.same {
		// Both must allow; the boundary and session policy limit the caller.
		resource := c.res == "self" || c.res == "root_caller" || c.res == "star"
		if identity && resource && boundOK && sessOK {
			return flowOutAllowed
		}
		return flowOutNotAllowed
	}
	unlimited := c.res == "self" && (c.principal == "user" || c.principal == "session")
	limited := identity || (c.res == "self" && c.principal == "role")
	if unlimited || (limited && boundOK && sessOK) {
		return flowOutAllowed
	}
	if c.res == "star" {
		if boundOK && sessOK {
			return flowOutAllowed
		}
		return flowOutAmbiguous // whether a boundary limits a grant to everyone is not stated
	}
	return flowOutNotAllowed
}

func flowPrincipalARN(kind, account string) string {
	switch kind {
	case "user":
		return "arn:aws:iam::" + account + ":user/alice"
	case "session":
		return "arn:aws:sts::" + account + ":assumed-role/App/s1"
	}
	return "arn:aws:iam::" + account + ":role/App"
}

func flowPolicy(kind string) PolicySlot {
	switch kind {
	case "none":
		return PolicySlot{State: EvidenceAbsent, Evidence: "none attached"}
	case "allow":
		return statements("p", "A", "Allow", []string{"s3:*"}, []string{"*"}, nil)
	case "noallow":
		return statements("p", "A", "Allow", []string{"dynamodb:*"}, []string{"*"}, nil)
	}
	return slotOf(stmt("p", "A", "Allow", []string{"s3:*"}, []string{"*"}, nil), stmt("p", "D", "Deny", []string{"s3:GetObject"}, []string{"*"}, nil))
}

func flowSCP(kind, account string) PolicySlot {
	if kind == "none" {
		return PolicySlot{State: EvidenceAbsent, Evidence: "no SCP applies"}
	}
	stmts := []StatementView{stmt("scp", "A", "Allow", []string{"s3:*"}, []string{"*"}, nil)}
	switch kind {
	case "noallow":
		stmts = []StatementView{stmt("scp", "A", "Allow", []string{"dynamodb:*"}, []string{"*"}, nil)}
	case "deny":
		stmts = append(stmts, stmt("scp", "D", "Deny", []string{"s3:GetObject"}, []string{"*"}, nil))
	}
	return PolicySlot{State: EvidencePresent, HierarchyComplete: true, RequiredTargets: []string{account}, Documents: []PolicyDocument{{
		ID: "scp", PolicyType: "scp", AttachmentLevel: "account", AttachmentTarget: account, Statements: stmts}}}
}

func flowRequest(c flowCase) AuthorizationRequest {
	callerAcct, resAcct := "111111111111", "111111111111"
	if !c.same {
		callerAcct = "222222222222"
	}
	r := baseGet()
	r.PrincipalARN = flowPrincipalARN(c.principal, callerAcct)
	r.ResourceAccountID = resAcct
	r.Identity = flowPolicy(c.ident)
	r.PermissionsBoundary = flowPolicy(c.bound)
	r.SessionPolicies = flowPolicy(c.sess)
	r.SCPs = flowSCP(c.scp, callerAcct)
	switch c.res {
	case "none":
		r.ResourcePolicy = PolicySlot{State: EvidenceAbsent, Evidence: "no bucket policy"}
	case "self":
		r.ResourcePolicy = bucketPolicy("Allow", r.PrincipalARN, "s3:GetObject")
	case "root_caller":
		r.ResourcePolicy = bucketPolicy("Allow", "arn:aws:iam::"+callerAcct+":root", "s3:GetObject")
	case "star":
		r.ResourcePolicy = bucketPolicy("Allow", "*", "s3:GetObject")
	case "other":
		r.ResourcePolicy = bucketPolicy("Allow", "arn:aws:iam::"+callerAcct+":user/someone-else", "s3:GetObject")
	case "root_other":
		other := "333333333333"
		if !c.same {
			other = resAcct
		}
		r.ResourcePolicy = bucketPolicy("Allow", "arn:aws:iam::"+other+":root", "s3:GetObject")
	case "deny":
		r.ResourcePolicy = bucketPolicy("Deny", "*", "s3:GetObject")
	}
	return r
}

func flowCases() []flowCase {
	var out []flowCase
	for _, principal := range []string{"user", "role", "session"} {
		sessions := []string{"none"}
		if principal == "session" {
			sessions = []string{"none", "allow", "noallow", "deny"}
		}
		for _, same := range []bool{true, false} {
			for _, res := range []string{"none", "self", "root_caller", "star", "other", "root_other", "deny"} {
				for _, ident := range []string{"allow", "none", "deny"} {
					for _, bound := range []string{"none", "allow", "noallow", "deny"} {
						for _, sess := range sessions {
							for _, scp := range []string{"none", "allow", "noallow", "deny"} {
								out = append(out, flowCase{principal, same, res, ident, bound, sess, scp})
							}
						}
					}
				}
			}
		}
	}
	return out
}

func TestFlowCombinationCorpus(t *testing.T) {
	cases := flowCases()
	var falseAllows, deniedMismatch []string
	misses := map[string][]string{}
	counts := map[string]int{}
	for _, c := range cases {
		want := flowOracle(c)
		if want == flowOutAmbiguous {
			counts["ambiguous"]++
			if got := Evaluate(flowRequest(c)); got.Status == StatusAllowed {
				// Allowed where the pages are silent is acceptable only when nothing could limit the grant.
				counts["ambiguous_allowed"]++
			}
			continue
		}
		got := Evaluate(flowRequest(c))
		counts[want]++
		switch {
		case got.Status == StatusAllowed && want != flowOutAllowed:
			falseAllows = append(falseAllows, c.String())
		case want == flowOutDenied && got.Status != StatusDenied, want != flowOutDenied && got.Status == StatusDenied:
			deniedMismatch = append(deniedMismatch, c.String()+" -> "+got.Status+" "+got.Reason)
		case want == flowOutAllowed && got.Status != StatusAllowed:
			key := got.Status + " " + got.Reason
			misses[key] = append(misses[key], c.String())
		}
	}
	missTotal := 0
	var keys []string
	for k, v := range misses {
		missTotal += len(v)
		keys = append(keys, k)
	}
	sort.Strings(keys)
	t.Logf("flow corpus: %d cases; oracle allowed %d, denied %d, not allowed %d, ambiguous %d; false allows %d; deny mismatches %d; safe misses %d",
		len(cases), counts[flowOutAllowed], counts[flowOutDenied], counts[flowOutNotAllowed], counts["ambiguous"], len(falseAllows), len(deniedMismatch), missTotal)
	for _, k := range keys {
		t.Logf("  safe miss %-45s %4d, e.g. %s", k, len(misses[k]), misses[k][0])
	}
	for _, f := range falseAllows[:min(len(falseAllows), 10)] {
		t.Errorf("FALSE ALLOW: %s", f)
	}
	for _, f := range deniedMismatch[:min(len(deniedMismatch), 10)] {
		t.Errorf("explicit-deny mismatch: %s", f)
	}
	if len(falseAllows) > 0 || len(deniedMismatch) > 0 {
		t.Fatalf("%d false allows, %d deny mismatches", len(falseAllows), len(deniedMismatch))
	}
	// A safe miss is not unsafe, but it is a gap against what AWS documents. None exist today, so any new one is a
	// regression; if one is accepted on purpose, name its class here with the reason.
	for k, v := range misses {
		t.Errorf("safe miss: %d cases are allowed by AWS but not by the evaluator (%s), e.g. %s", len(v), k, v[0])
	}
}
