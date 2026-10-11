package graph

import (
	"strings"
	"testing"
	"time"

	"github.com/Zero0x00/cloudrift/internal/iamauth"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestAuthorizationDecisionProjection_IsolatesScans(t *testing.T) {
	req := iamauth.AuthorizationRequest{
		ScanID:              "scan-a",
		PrincipalARN:        "arn:aws:iam::111111111111:role/App",
		Action:              iamauth.ActionGetObject,
		ResourceARN:         "arn:aws:s3:::data/readme.txt",
		ResourceAccountID:   "111111111111",
		EvaluatedAt:         time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC),
		Identity:            presentAllow("scan-a"),
		ResourcePolicy:      iamauth.PolicySlot{State: iamauth.EvidenceAbsent},
		PermissionsBoundary: iamauth.PolicySlot{State: iamauth.EvidenceAbsent},
		SessionPolicies:     iamauth.PolicySlot{State: iamauth.EvidenceAbsent},
		SCPs:                iamauth.PolicySlot{State: iamauth.EvidenceAbsent},
		RCPs:                iamauth.PolicySlot{State: iamauth.EvidenceAbsent},
		S3ObjectACL:         iamauth.ConstraintNotApplicable,
		S3BlockPublicAccess: iamauth.ConstraintNotApplicable,
	}
	first, _ := iamauth.ProjectDecision(iamauth.Evaluate(req))
	again, _ := iamauth.ProjectDecision(iamauth.Evaluate(req))
	if first.ARN != again.ARN {
		t.Fatal("repeated ingestion changed the decision identity")
	}
	req.ScanID = "scan-b"
	second, rel := iamauth.ProjectDecision(iamauth.Evaluate(req))
	if first.ARN == second.ARN || first.ScanID == second.ScanID {
		t.Fatal("two scans collapsed onto one decision")
	}
	role := models.AssetNode{ARN: req.PrincipalARN, AssetType: models.AssetIAMRole, AccountID: "111111111111", ScanID: "scan-b"}
	proj := CompileScanProjection(models.ScanSnapshot{ScanID: "scan-b", Timestamp: time.Unix(2, 0).UTC()}, []models.AssetNode{role, second}, []models.Relationship{rel}, nil)
	var saw bool
	for _, stmt := range proj.Statements {
		if !strings.Contains(stmt.Cypher, "HAS_AUTHORIZATION_DECISION") {
			continue
		}
		saw = true
		if stmt.Params["scan_id"] != "scan-b" || strings.Contains(stmt.Cypher, "scan-a") {
			t.Fatalf("scan scope: %#v\n%s", stmt.Params["scan_id"], stmt.Cypher)
		}
		if !strings.Contains(stmt.Cypher, "rel.scan_id = $scan_id") {
			t.Fatal("decision relationship is not scan scoped")
		}
	}
	if !saw {
		t.Fatal("decision relationship was not projected")
	}
}

func presentAllow(scan string) iamauth.PolicySlot {
	_ = scan
	return iamauth.PolicySlot{State: iamauth.EvidencePresent, Documents: []iamauth.PolicyDocument{{
		ID: "id", PolicyType: "inline",
		Statements: []iamauth.StatementView{{
			PolicyID: "id", StatementID: "Allow", Effect: "Allow",
			Action: []string{"s3:GetObject"}, Resource: []string{"arn:aws:s3:::data/readme.txt"},
		}},
	}}}
}
