package ciem

import (
	"strings"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// controlsNote says whether anything outside the role's own policies limits it.
func controlsNote(role models.AssetNode, cov schema.CIEMEvidenceCoverage, complete bool) string {
	if complete {
		if strings.Contains(strProp(role, "scp_evidence"), "not a member of an organization") {
			return "No permissions boundary, SCP or RCP limits this role (the account is not in an AWS Organization), so its policies are everything that applies."
		}
		return "The permissions boundary, SCPs and RCPs were checked, so the policies shown are what applies."
	}
	return "Not every limit was read (permissions boundary, SCP or RCP), so this role may be allowed less than its policies say."
}

// plainCoverageLines words the evidence coverage for a reader, without internal state names.
func plainCoverageLines(role models.AssetNode, cov schema.CIEMEvidenceCoverage, fromWorkload bool) []string {
	var out []string
	switch cov.PermissionsBoundary {
	case "NOT_APPLICABLE":
		out = append(out, "No permissions boundary is attached.")
	case "COMPLETE_FOR_SUPPORTED_SCOPE":
		out = append(out, "A permissions boundary is attached and was read.")
	default:
		out = append(out, "The permissions boundary was not collected, so the role may be allowed less than its policies say.")
	}
	switch {
	case cov.OrganizationsSCP == "NOT_APPLICABLE" && cov.OrganizationsRCP == "NOT_APPLICABLE" && strings.Contains(strProp(role, "scp_evidence"), "not a member of an organization"):
		out = append(out, "This account is not in an AWS Organization, so no SCP or RCP applies.")
	case cov.OrganizationsSCP == "NOT_APPLICABLE" && cov.OrganizationsRCP == "NOT_APPLICABLE":
		out = append(out, "No SCP or RCP applies to this role.")
	case cov.OrganizationsSCP == "COMPLETE_FOR_SUPPORTED_SCOPE" && cov.OrganizationsRCP == "COMPLETE_FOR_SUPPORTED_SCOPE":
		out = append(out, "Organization policies (SCP and RCP) were collected.")
	default:
		out = append(out, "Organization policies (SCP or RCP) were not fully collected, so they could limit this role further.")
	}
	if fromWorkload {
		out = append(out, "Credentials taken from a workload carry no session policy, so none is assumed.")
	} else {
		out = append(out, sessionLine(cov.SessionContext))
	}
	if cov.S3ObjectInventory == "COMPLETE_FOR_SUPPORTED_SCOPE" {
		out = append(out, "S3 objects were inventoried, so access to individual objects is checked.")
	} else {
		out = append(out, "S3 objects were not inventoried, so access to individual objects is not checked.")
	}
	return out
}

// workloadCards describes each workload that runs as the role.
func workloadCards(workloads []schema.WorkloadAttachment, assets []models.AssetNode) []schema.WorkloadCard {
	byARN := map[string]models.AssetNode{}
	for _, a := range assets {
		byARN[a.ARN] = a
	}
	var out []schema.WorkloadCard
	for _, w := range workloads {
		card := schema.WorkloadCard{ARN: w.WorkloadARN, Type: w.WorkloadType, Name: w.WorkloadName}
		if a, ok := byARN[w.WorkloadARN]; ok {
			if n := tagsOf(a)["Name"]; n != "" {
				card.Name = n
			}
			card.State = strProp(a, "instance_state")
			card.PublicIP = strProp(a, "public_ip")
			if p := strProp(a, "instance_profile_arn"); p != "" {
				card.Profile = p[strings.LastIndex(p, "/")+1:]
			}
		}
		out = append(out, card)
	}
	return out
}
