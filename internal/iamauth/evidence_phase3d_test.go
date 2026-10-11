package iamauth

import (
	"testing"
	"time"

	"github.com/Zero0x00/cloudrift/internal/models"
)

func TestSlotFromStatus_AbsenceRequiresEvidence(t *testing.T) {
	if got := SlotFromStatus("confirmed_absent", "", nil); got.State != EvidenceMissing {
		t.Fatalf("absence without evidence: %+v", got)
	}
	got := SlotFromStatus("confirmed_absent", "s3:GetBucketPolicy returned NoSuchBucketPolicy", nil)
	if got.State != EvidenceAbsent || got.Evidence == "" {
		t.Fatalf("confirmed absence: %+v", got)
	}
	named := SlotFromStatus("present", "iam:ListRoles returned a boundary ARN", nil)
	if named.State != EvidenceMissing {
		t.Fatalf("boundary ARN without a document: %+v", named)
	}
}

func TestEvidenceFingerprint_PolicyChangeInvalidatesDecision(t *testing.T) {
	first := baseGet()
	second := baseGet()
	second.Identity = statements("id", "Allow", "Allow", []string{"s3:GetObject"}, []string{"arn:aws:s3:::data/other"}, nil)
	if EvidenceFingerprint(first) == EvidenceFingerprint(second) {
		t.Fatal("policy change kept the same fingerprint")
	}
	stored := Evaluate(first)
	if DecisionCurrent(stored.EvidenceFingerprint, second) {
		t.Fatal("stale decision was still current")
	}
	if DecisionCurrent(stored.EvidenceFingerprint, first) == false {
		t.Fatal("matching evidence was treated as stale")
	}
	again := Evaluate(first)
	if stored.ID != again.ID {
		t.Fatal("same evidence changed the decision id")
	}
	if Evaluate(second).ID == stored.ID {
		t.Fatal("changed policy reused the old decision id")
	}
}

func TestProjectCapability_IdempotentAndSkipsUnresolved(t *testing.T) {
	d := Evaluate(baseGet())
	node, rels := ProjectCapability(d, true)
	again, againRels := ProjectCapability(d, true)
	if node.ARN != again.ARN || len(rels) != 2 || len(againRels) != 2 {
		t.Fatalf("projection was not idempotent: %s %d", node.ARN, len(rels))
	}
	if rels[1].RelType != models.RelAuthorizationTargets || rels[1].TargetARN != d.ResourceARN {
		t.Fatalf("target link: %+v", rels[1])
	}
	_, skipped := ProjectCapability(d, false)
	if len(skipped) != 1 || skipped[0].RelType != models.RelHasAuthorizationDecision {
		t.Fatal("uncollected target received a target link")
	}
	wild := d
	wild.ResourceARN = "arn:aws:s3:::data/*"
	_, wildRels := ProjectCapability(wild, true)
	if len(wildRels) != 1 {
		t.Fatal("wildcard target was linked")
	}
}

func TestKMSPrerequisiteStaysUnknown(t *testing.T) {
	req := baseGet()
	req.S3KMSKeyPolicy = "missing"
	d := Evaluate(req)
	if d.Status != StatusUnknown || d.Reason != ReasonMissingKMS {
		t.Fatalf("%+v", d)
	}
	req.S3KMSKeyPolicy = ConstraintNotApplicable
	if got := Evaluate(req); got.Status != StatusAllowed {
		t.Fatalf("SSE-S3 was treated as a KMS requirement: %+v", got)
	}
}

func TestMissingVersusAbsentSCP(t *testing.T) {
	missing := baseGet()
	missing.SCPs = SlotFromStatus("", "organizations SCP documents were not collected", nil)
	if d := Evaluate(missing); d.Status != StatusUnknown || d.Reason != ReasonMissingSCP {
		t.Fatalf("missing scp: %+v", d)
	}
	absent := baseGet()
	absent.SCPs = SlotFromStatus("confirmed_absent", "organizations:ListPoliciesForTarget returned no SCP for this account", nil)
	if d := Evaluate(absent); d.Status != StatusAllowed {
		t.Fatalf("confirmed absent scp: %+v", d)
	}
	inherited := baseGet()
	inherited.SCPs = SlotFromStatus("present", "inherited from OU /root/prod", []PolicyDocument{{
		ID: "ou-prod", PolicyType: "scp", Raw: `{"Statement":[{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}]}`,
	}})
	if d := Evaluate(inherited); d.Status != StatusDenied || len(d.ExplicitDeny) == 0 {
		t.Fatalf("inherited scp: %+v", d)
	}
}

func TestRestrictedSessionAndBoundaryDocument(t *testing.T) {
	req := baseGet()
	req.SessionPolicies = statements("session", "ReadOnly", "Allow", []string{"s3:ListBucket"}, []string{"*"}, nil)
	if d := Evaluate(req); d.Status != StatusUnknown || d.Reason != ReasonSessionNoAllow {
		t.Fatalf("session: %+v", d)
	}
	req = baseGet()
	req.EvaluatedAt = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	req.PermissionsBoundary = SlotFromStatus("present", "iam:ListRoles returned a boundary ARN", nil)
	if d := Evaluate(req); d.Status != StatusUnknown || d.Reason != ReasonMissingBoundary {
		t.Fatalf("boundary document missing: %+v", d)
	}
}
