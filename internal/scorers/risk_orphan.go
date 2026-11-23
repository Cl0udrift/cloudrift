package scorers

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// orphanTitle says what is wrong in the finding's own words: the name, where it points, and the verdict.
func orphanTitle(node models.AssetNode, c models.Claimability, fingerprint string) string {
	target, _ := node.Properties["value"].(string)
	where := ""
	if target != "" {
		where = " (points at " + target + ")"
	}
	switch {
	case fingerprint == "ns_delegation_lame":
		return fmt.Sprintf("%s is delegated to name servers that do not serve it%s", node.Name, where)
	case strings.HasPrefix(fingerprint, "target_deleted_"):
		return fmt.Sprintf("%s points at a deleted %s%s", node.Name, strings.ReplaceAll(strings.TrimPrefix(fingerprint, "target_deleted_"), "_", " "), where)
	}
	switch c {
	case models.ClaimReclaimable:
		return fmt.Sprintf("%s can be taken over%s", node.Name, where)
	case models.ClaimDangling:
		return fmt.Sprintf("%s points at a resource that does not answer%s", node.Name, where)
	case models.ClaimEdgeObscured:
		return fmt.Sprintf("%s is not an alias of the distribution it points at%s", node.Name, where)
	case models.ClaimBroken:
		return fmt.Sprintf("%s does not resolve%s", node.Name, where)
	}
	return fmt.Sprintf("%s -> %s", node.Name, c)
}

// recordFacts is what the finding shows about the DNS record itself.
func recordFacts(node models.AssetNode) map[string]any {
	p := node.Properties
	out := map[string]any{"record_name": node.Name}
	for _, k := range []string{"type", "value", "zone_id", "ttl", "set_identifier"} {
		if v, ok := p[k]; ok && v != nil && v != "" {
			key := k
			switch k {
			case "type":
				key = "record_type"
			case "value":
				key = "record_target"
			}
			out[key] = v
		}
	}
	return out
}

// route53DeleteCommand returns the steps that remove a record safely: look at it now, save it so it can be put back,
// then delete it. Route 53 only deletes a record when every field matches, so it needs the full record set. When the
// scan did not store enough, the command is empty and why says what to do instead.
func route53DeleteCommand(node models.AssetNode) (cmd, why string) {
	p := node.Properties
	zone, _ := p["zone_id"].(string)
	typ, _ := p["type"].(string)
	if zone == "" || typ == "" || node.Name == "" {
		return "", "The scan did not store the zone or type of this record. Rescan, or delete it from the Route 53 console."
	}
	set := map[string]any{"Name": node.Name + ".", "Type": typ}
	if id, _ := p["set_identifier"].(string); id != "" {
		return "", "This record has a routing policy (weighted, latency, geolocation or failover), so deleting it can change how its siblings answer. Review the whole set in the Route 53 console."
	}
	if hz, _ := p["alias_hosted_zone_id"].(string); hz != "" {
		health, _ := p["alias_evaluate_target_health"].(bool)
		target, _ := p["value"].(string)
		set["AliasTarget"] = map[string]any{"HostedZoneId": hz, "DNSName": target + ".", "EvaluateTargetHealth": health}
	} else {
		var values []string
		switch v := p["values"].(type) {
		case []string:
			values = v
		case []any:
			for _, x := range v {
				if s, ok := x.(string); ok {
					values = append(values, s)
				}
			}
		}
		ttl, ok := toInt(p["ttl"])
		if len(values) == 0 || !ok {
			return "", "The scan did not store this record's TTL or values (it was made before they were collected). Rescan to get the command."
		}
		recs := make([]map[string]string, 0, len(values))
		for _, v := range values {
			recs = append(recs, map[string]string{"Value": v})
		}
		set["TTL"], set["ResourceRecords"] = ttl, recs
	}
	batch := func(action string) string {
		b, _ := json.MarshalIndent(map[string]any{
			"Comment": action + " record " + node.Name,
			"Changes": []any{map[string]any{"Action": action, "ResourceRecordSet": set}},
		}, "", "  ")
		return string(b)
	}
	safe := strings.NewReplacer("*", "wildcard", "/", "_", "\\", "_").Replace(node.Name)
	del, restore := shellQuote("delete-"+safe+".json"), shellQuote("restore-"+safe+".json")
	name := strings.ReplaceAll(node.Name, "'", "")
	return fmt.Sprintf(`# 1. Look at the record as it is now. Stop if it is not what the finding describes.
aws route53 list-resource-record-sets --hosted-zone-id %[1]s --query "ResourceRecordSets[?Name=='%[2]s.' && Type=='%[3]s']"

# 2. Save the record so it can be put back.
cat > %[4]s <<'EOF'
%[5]s
EOF

# 3. Delete it. This is live DNS: run it only after you have checked who manages the record.
cat > %[6]s <<'EOF'
%[7]s
EOF
aws route53 change-resource-record-sets --hosted-zone-id %[1]s --change-batch file://%[6]s

# To undo:
# aws route53 change-resource-record-sets --hosted-zone-id %[1]s --change-batch file://%[4]s`, zone, name, typ, restore, batch("CREATE"), del, batch("DELETE")), ""
}

// shellQuote wraps a word in single quotes so a record name can never be read as shell syntax.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func toInt(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case float64:
		return int64(n), true
	}
	return 0, false
}

// Evidence levels: "verified" means the scan saw the fact itself (the service said the bucket or target does not
// exist, IAM said the principal was deleted). Anything else is an inference and the finding says what to check.
const (
	levelVerified = "verified"
	levelInferred = "inferred"
)

func levelAndHint(fingerprint string, c models.Claimability) (level, hint string) {
	switch {
	case fingerprint == "s3_bucket_deleted" && c == models.ClaimReclaimable,
		strings.HasPrefix(fingerprint, "target_deleted_"), fingerprint == "s3_bucket_unowned_referenced", fingerprint == "deleted_principal":
		return levelVerified, ""
	case fingerprint == "ns_delegation_lame":
		return levelInferred, "run dig NS for the name against each of its name servers from another network. A server that answers means the zone is served."
	case fingerprint == "ec2_address_not_held":
		return levelInferred, "look for the address in every account and Region you use, including accounts outside this scan (aws ec2 describe-addresses)."
	case fingerprint == "api_gateway_domain_not_held", fingerprint == "cognito_domain_not_held":
		return levelInferred, "look for the domain in every other account and Region you use."
	case fingerprint == "acm_validation_record_orphaned":
		return levelInferred, "check that no certificate in another account or Region still uses this record."
	case fingerprint == "dns_nxdomain" || c == models.ClaimBroken:
		return levelInferred, "resolve the name again from another network. A failed lookup can be temporary."
	case c == models.ClaimEdgeObscured:
		return levelInferred, "confirm in CloudFront that the name is not an alias of a distribution you own."
	case c == models.ClaimReclaimable:
		return levelInferred, "open the name in a browser and confirm the page says the site is unclaimed, and that the account at that service is not yours."
	}
	return levelInferred, "confirm with the owner of the target that the resource is meant to be gone."
}

// annotateRemediation adds how sure the finding is, what to check when it is only inferred, and, for a DNS record,
// the reminder to look for whatever manages it. A missing command carries the reason instead.
func annotateRemediation(f *models.Finding, fingerprint string, isRecord bool, why string) {
	if f.Evidence == nil {
		f.Evidence = map[string]any{}
	}
	level, hint := levelAndHint(fingerprint, f.Claimability)
	f.Evidence["evidence_level"] = level
	if level == levelInferred {
		f.Evidence["verify_first"] = hint
		if r := f.Recommendation; r != "" {
			f.Recommendation = "Verify first: " + hint + " If that confirms it, " + strings.ToLower(r[:1]) + r[1:]
		}
	}
	if !isRecord {
		return
	}
	if f.RemediationCmd != "" {
		f.Recommendation += " Before deleting, check whether Terraform, CloudFormation or external-dns manages this record: a record they manage comes back on the next apply."
	} else if why != "" {
		f.Evidence["remediation_note"] = why
	}
}
