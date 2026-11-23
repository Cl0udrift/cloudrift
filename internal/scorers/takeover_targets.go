package scorers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// DNS records that point at something no scanned account holds: an EC2 address that was released, an API Gateway
// custom domain or Cognito domain that was deleted, a certificate validation record left behind. Each rests on
// absence, so it is raised only when coverage is complete and the collector behind it succeeded everywhere.

var (
	apiCustomDomainTarget = regexp.MustCompile(`^d-[a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com$`)
	cognitoDomainTarget   = regexp.MustCompile(`^[a-z0-9-]+\.auth\.[a-z0-9-]+\.amazoncognito\.com$`)
)

// EC2AddressProbe says whether an IPv4 address is in the EC2 public range.
type EC2AddressProbe func(ctx context.Context, ip string) bool

// collectorComplete is true when the collector ran in at least one account and Region and every run succeeded.
func collectorComplete(assets []models.AssetNode, name string) bool {
	seen := false
	for _, a := range assets {
		if a.AssetType != "collection_status" {
			continue
		}
		if c, _ := a.Properties["collector"].(string); c != name {
			continue
		}
		seen = true
		if s, _ := a.Properties["status"].(string); s != "succeeded" {
			return false
		}
	}
	return seen
}

func ScoreUnheldTargets(ctx context.Context, assets []models.AssetNode, coverageComplete bool, isEC2 EC2AddressProbe) []models.Finding {
	if !coverageComplete {
		return nil
	}
	ips, apiNames, cognito, validation := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, a := range assets {
		switch a.AssetType {
		case models.AssetPublicAddressSet:
			for _, ip := range stringList(a.Properties["addresses"]) {
				ips[ip] = true
			}
		case models.AssetEC2Instance:
			if ip, _ := a.Properties["public_ip"].(string); ip != "" {
				ips[ip] = true
			}
		case models.AssetAPIGatewayDomain:
			for _, n := range stringList(a.Properties["regional_domain_names"]) {
				apiNames[strings.ToLower(n)] = true
			}
		case models.AssetCognitoUserPool:
			if h, _ := a.Properties["hosted_ui_host"].(string); h != "" {
				cognito[strings.ToLower(h)] = true
			}
		case models.AssetACMCert:
			for _, n := range stringList(a.Properties["validation_records"]) {
				validation[n] = true
			}
		}
	}
	okAddr, okAPI := collectorComplete(assets, "public_addresses") && isEC2 != nil, collectorComplete(assets, "apigateway")
	okCog, okACM := collectorComplete(assets, "cognito"), collectorComplete(assets, "acm")

	var out []models.Finding
	for _, n := range assets {
		if n.AssetType != models.AssetDNSRecord {
			continue
		}
		if private, _ := n.Properties["private"].(bool); private {
			continue
		}
		target := strings.TrimSuffix(strings.ToLower(fmt.Sprint(n.Properties["value"])), ".")
		typ, _ := n.Properties["type"].(string)
		alias, _ := n.Properties["alias_hosted_zone_id"].(string)
		switch {
		case okAPI && apiCustomDomainTarget.MatchString(target) && !apiNames[target]:
			out = append(out, unheldFinding(n, "api_gateway_domain_not_held", models.SeverityHigh, models.ClaimDangling,
				fmt.Sprintf("%s points at an API Gateway custom domain no scanned account holds (%s)", n.Name, target),
				"The API Gateway custom domain this name points at is not in any scanned account. It was deleted or belongs to another account; either way the name hands traffic to whoever holds the domain."))
		case okCog && cognitoDomainTarget.MatchString(target) && !cognito[target]:
			out = append(out, unheldFinding(n, "cognito_domain_not_held", models.SeverityHigh, models.ClaimDangling,
				fmt.Sprintf("%s points at a Cognito domain no scanned account holds (%s)", n.Name, target),
				"Cognito domain prefixes are first come, first served. This one is not in any scanned account, so it was deleted or is held by someone else; whoever holds it serves the sign-in pages under your name."))
		case okACM && typ == "CNAME" && strings.HasPrefix(n.Name, "_") && strings.HasSuffix(target, ".acm-validations.aws") && !validation[strings.ToLower(n.Name)]:
			out = append(out, unheldFinding(n, "acm_validation_record_orphaned", models.SeverityLow, models.ClaimDangling,
				fmt.Sprintf("%s is a certificate validation record for a certificate no scanned account holds", n.Name),
				"ACM left this record when the certificate was requested. No scanned account has a certificate that uses it, so it is clutter. It is account-specific and cannot be reused by others, so this is not a takeover."))
		case okAddr && typ == "A" && alias == "":
			for _, ip := range stringList(n.Properties["values"]) {
				if addr := net.ParseIP(ip); addr == nil || addr.To4() == nil || addr.IsPrivate() || addr.IsLoopback() || ips[ip] {
					continue
				}
				if isEC2(ctx, ip) {
					out = append(out, unheldFinding(n, "ec2_address_not_held", models.SeverityHigh, models.ClaimDangling,
						fmt.Sprintf("%s points at EC2 address %s that no scanned account holds", n.Name, ip),
						"The address is in the EC2 public range but is not an Elastic IP, instance or network interface address in any scanned account and Region. It was released, and anyone who is handed it by EC2 serves traffic for your name."))
					break
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func unheldFinding(n models.AssetNode, fingerprint string, sev models.Severity, c models.Claimability, title, impact string) models.Finding {
	h := sha256.Sum256([]byte(string(models.ModuleOrphanedEdge) + "|" + fingerprint + "|" + n.ARN))
	cmd, why := route53DeleteCommand(n)
	f := models.Finding{
		ID: hex.EncodeToString(h[:])[:12], Title: title, Severity: sev, Module: models.ModuleOrphanedEdge, Claimability: c,
		AffectedARN: n.ARN, AccountID: n.AccountID, Hostname: n.Name, Impact: impact,
		Recommendation: "Delete the record, or point it at a resource in an account you own.",
		RemediationCmd: cmd,
		Evidence:       mergeFacts(map[string]any{"fingerprint": fingerprint, "claimable": false}, recordFacts(n)),
	}
	annotateRemediation(&f, fingerprint, true, why)
	return f
}
