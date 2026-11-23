package scorers

import (
	"strings"
	"testing"

	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/validators"
)

func cname(props map[string]any) models.AssetNode {
	base := map[string]any{"type": "CNAME", "value": "docs-site.s3-website-us-east-1.amazonaws.com", "zone_id": "Z1", "ttl": int64(300), "values": []string{"docs-site.s3-website-us-east-1.amazonaws.com"}}
	for k, v := range props {
		base[k] = v
	}
	return models.AssetNode{ARN: "arn:aws:route53:::Z1/docs.example.com", AssetType: models.AssetDNSRecord, Name: "docs.example.com", AccountID: "1", Properties: base}
}

func TestOrphanFindingNamesTheRecordAndGivesARunnableFix(t *testing.T) {
	f := ScoreRisk(cname(nil), validators.ValidationResult{DNSStatus: "resolved", ErrorFingerprint: "s3_bucket_deleted"}, map[string]bool{})
	if !strings.Contains(f.Title, "docs.example.com can be taken over") || !strings.Contains(f.Title, "docs-site.s3-website") {
		t.Fatalf("title should say what and where: %q", f.Title)
	}
	if f.Evidence["record_type"] != "CNAME" || f.Evidence["zone_id"] != "Z1" {
		t.Fatalf("record facts missing: %v", f.Evidence)
	}
	for _, want := range []string{`"Action": "DELETE"`, `"TTL": 300`, `"Value": "docs-site.s3-website-us-east-1.amazonaws.com"`, "--hosted-zone-id Z1"} {
		if !strings.Contains(f.RemediationCmd, want) {
			t.Fatalf("command lacks %s:\n%s", want, f.RemediationCmd)
		}
	}
}

func TestAliasRecordFixCarriesTheAliasTarget(t *testing.T) {
	n := cname(map[string]any{"type": "A", "value": "d1.cloudfront.net", "alias_hosted_zone_id": "Z2FDTNDATAQYW2", "alias_evaluate_target_health": false})
	cmd, _ := route53DeleteCommand(n)
	if !strings.Contains(cmd, `"HostedZoneId": "Z2FDTNDATAQYW2"`) || !strings.Contains(cmd, `"DNSName": "d1.cloudfront.net."`) || strings.Contains(cmd, "TTL") {
		t.Fatalf("alias change wrong:\n%s", cmd)
	}
}

func TestNoFixIsInventedWhenTheRecordIsNotFullyKnown(t *testing.T) {
	if cmd, _ := route53DeleteCommand(cname(map[string]any{"set_identifier": "blue"})); cmd != "" {
		t.Fatal("a routed record needs routing fields the scan does not store")
	}
	if cmd, _ := route53DeleteCommand(cname(map[string]any{"ttl": nil})); cmd != "" {
		t.Fatal("without a TTL the delete would be rejected")
	}
}

func TestDeletedTargetAndLameDelegationAreScoredAndNamed(t *testing.T) {
	bean := cname(map[string]any{"value": "old.us-east-1.elasticbeanstalk.com", "values": []string{"old.us-east-1.elasticbeanstalk.com"}, "target_service": "elasticbeanstalk"})
	f := ScoreRisk(bean, validators.ValidationResult{DNSStatus: "nxdomain", ErrorFingerprint: "target_deleted_elasticbeanstalk", Claimable: true}, nil)
	if f.Claimability != models.ClaimReclaimable || f.Severity != models.SeverityHigh || !strings.Contains(f.Title, "deleted elasticbeanstalk") {
		t.Fatalf("a deleted Beanstalk target is reclaimable: %s %s %q", f.Claimability, f.Severity, f.Title)
	}
	lb := ScoreRisk(bean, validators.ValidationResult{DNSStatus: "nxdomain", ErrorFingerprint: "target_deleted_alb"}, nil)
	if lb.Claimability != models.ClaimDangling {
		t.Fatalf("a deleted load balancer is dangling: %s", lb.Claimability)
	}
	ns := cname(map[string]any{"type": "NS", "value": "ns-1.awsdns-01.org", "values": []string{"ns-1.awsdns-01.org."}})
	f = ScoreRisk(ns, validators.ValidationResult{DNSStatus: "delegation_lame", ErrorFingerprint: "ns_delegation_lame", Claimable: true}, nil)
	if f.Claimability != models.ClaimReclaimable || !strings.Contains(f.Title, "name servers that do not serve it") || !strings.Contains(f.RemediationCmd, `"Type": "NS"`) {
		t.Fatalf("lame Route 53 delegation: %s %q\n%s", f.Claimability, f.Title, f.RemediationCmd)
	}
}

func TestDeleteCommandLooksSavesThenDeletesAndQuotesNames(t *testing.T) {
	cmd, _ := route53DeleteCommand(cname(map[string]any{}))
	look, save, del := strings.Index(cmd, "list-resource-record-sets"), strings.Index(cmd, `"Action": "CREATE"`), strings.Index(cmd, `"Action": "DELETE"`)
	if look < 0 || save < look || del < save || !strings.Contains(cmd, "file://'delete-docs.example.com.json'") || !strings.Contains(cmd, "# To undo:") {
		t.Fatalf("order must be look, save for undo, delete, with the file name quoted:\n%s", cmd)
	}
	hostile := cname(map[string]any{})
	hostile.Name = "a'$(touch x).example.com"
	cmd, _ = route53DeleteCommand(hostile)
	if strings.Contains(cmd, "touch x).example.com.json ") || !strings.Contains(cmd, `'\''`) {
		t.Fatalf("a quote in a name must not end the quoted word:\n%s", cmd)
	}
}

func TestMissingCommandSaysWhy(t *testing.T) {
	_, why := route53DeleteCommand(cname(map[string]any{"set_identifier": "blue"}))
	if !strings.Contains(why, "routing policy") {
		t.Fatalf("a routed record must explain itself: %q", why)
	}
	f := ScoreRisk(cname(map[string]any{"set_identifier": "blue"}), validators.ValidationResult{DNSStatus: "resolved", ErrorFingerprint: "s3_bucket_deleted"}, map[string]bool{})
	if f.RemediationCmd != "" || f.Evidence["remediation_note"] == nil {
		t.Fatalf("no command means a note in the evidence: %+v", f.Evidence)
	}
}

func TestInferredFindingsSayVerifyFirstAndVerifiedOnesDoNot(t *testing.T) {
	inferred := ScoreRisk(cname(nil), validators.ValidationResult{DNSStatus: "nxdomain", ErrorFingerprint: "dns_nxdomain"}, nil)
	if inferred.Evidence["evidence_level"] != "inferred" || !strings.HasPrefix(inferred.Recommendation, "Verify first:") {
		t.Fatalf("a failed lookup is an inference: %q", inferred.Recommendation)
	}
	verified := ScoreRisk(cname(nil), validators.ValidationResult{DNSStatus: "resolved", ErrorFingerprint: "s3_bucket_deleted"}, map[string]bool{})
	if verified.Evidence["evidence_level"] != "verified" || strings.HasPrefix(verified.Recommendation, "Verify first") {
		t.Fatalf("a deleted bucket seen by S3 is verified: %q", verified.Recommendation)
	}
	if !strings.Contains(verified.Recommendation, "Terraform, CloudFormation or external-dns") {
		t.Fatalf("a record with a delete command must say to check who manages it: %q", verified.Recommendation)
	}
}
