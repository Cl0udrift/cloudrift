package main

import (
	"github.com/Zero0x00/cloudrift/internal/collectors"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func identityScenarioIDs() []string {
	return []string{
		"id-narrow", "id-admin", "id-same-trust", "id-cross-trust", "id-trust-no-caller",
		"id-assume-ok", "id-trust-deny", "id-boundary", "id-scp", "id-rcp",
		"id-missing-org", "id-missing-session", "id-shared-policy", "id-mixed",
		"id-service", "id-slr", "id-wildcard", "id-multipath", "id-admin-no-path",
		"id-hist-a", "id-hist-b",
	}
}

func identityScenario(scanID, scenario string) ([]models.AssetNode, []models.Relationship) {
	principal := "arn:aws:iam::999999999999:root"
	switch scenario {
	case "id-narrow":
		return oneRole(scanID, "IDNarrow", demoAcctCore, allowGet(objectARN("id-narrow", "readme.txt")), "id-narrow", nil)
	case "id-admin":
		return oneRole(scanID, "IDAdmin", demoAcctCore, allowStar(), "id-admin", map[string]any{"attached_policy_names": []string{"AdministratorAccess"}})
	case "id-admin-no-path":
		role := secRole(scanID, demoAcctCore, "IDAdminIdle", map[string]any{"attached_policy_names": []string{"AdministratorAccess"}})
		assets := []models.AssetNode{role}
		nodes, edges := collectors.BuildIdentityPolicyEvidence(role, []collectors.IdentityPolicyInput{inline("IDAdminIdle", allowStar())})
		return stamp(append(assets, nodes...), edges)
	case "id-same-trust":
		return trustPair(scanID, demoAcctCore, demoAcctCore, "IDSameCaller", "IDSameTarget", "id-same", trustAllow(roleARN(demoAcctCore, "IDSameCaller")), allowAssume(roleARN(demoAcctCore, "IDSameTarget")), false)
	case "id-cross-trust":
		return trustPair(scanID, demoAcctCore, demoAcctData, "IDCrossCaller", "IDCrossTarget", "id-cross", trustAllow(roleARN(demoAcctCore, "IDCrossCaller")), "", true)
	case "id-trust-no-caller":
		return trustPair(scanID, demoAcctCore, demoAcctCore, "IDNoPermCaller", "IDNoPermTarget", "id-noperm", trustAllow(roleARN(demoAcctCore, "IDNoPermCaller")), allowGet(objectARN("id-noperm", "readme.txt")), false)
	case "id-assume-ok":
		return trustPair(scanID, demoAcctCore, demoAcctCore, "IDAssumeCaller", "IDAssumeTarget", "id-assume", trustAllow(roleARN(demoAcctCore, "IDAssumeCaller")), allowAssume(roleARN(demoAcctCore, "IDAssumeTarget")), false)
	case "id-trust-deny":
		return trustPair(scanID, demoAcctCore, demoAcctCore, "IDDenyCaller", "IDDenyTarget", "id-deny", trustDeny(roleARN(demoAcctCore, "IDDenyCaller")), allowAssume(roleARN(demoAcctCore, "IDDenyTarget")), false)
	case "id-boundary":
		object := objectARN("id-boundary", "readme.txt")
		return oneRole(scanID, "IDBoundary", demoAcctCore, allowGet(object), "id-boundary", map[string]any{
			"permissions_boundary_status": "present", "permissions_boundary_evidence": "demo observation: boundary document collected",
			"permissions_boundary_document": `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}}`,
		})
	case "id-scp":
		return oneRole(scanID, "IDSCP", demoAcctCore, allowGet(objectARN("id-scp", "readme.txt")), "id-scp", map[string]any{
			"scp_status": "present", "scp_evidence": "demo observation: account SCP denies the object read",
			"scp_hierarchy_complete": true,
			"scp_attachments": []map[string]any{
				orgAttachment("SERVICE_CONTROL_POLICY", "p-root", "root", "r-root", `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}}`),
			},
		})
	case "id-rcp":
		return rcpRole(scanID)
	case "id-missing-org":
		role := secRole(scanID, demoAcctCore, "IDMissingOrg", map[string]any{
			"scp_status": "missing", "scp_evidence": "demo observation: organizations policy collection was denied",
		})
		return withObject(scanID, role, "id-missing-org", allowGet(objectARN("id-missing-org", "readme.txt")))
	case "id-missing-session":
		role := secRole(scanID, demoAcctCore, "IDMissingSession", nil)
		delete(role.Properties, "session_policy_status")
		delete(role.Properties, "session_policy_evidence")
		return withObject(scanID, role, "id-missing-session", allowGet(objectARN("id-missing-session", "readme.txt")))
	case "id-shared-policy":
		return sharedPolicy(scanID)
	case "id-mixed":
		role := secRole(scanID, demoAcctCore, "IDMixed", map[string]any{"trust_policy_document": trustAllow(principal)})
		internal := secRole(scanID, demoAcctCore, "IDMixedPeer", nil)
		ext := externalNode(principal, "aws_account")
		assets := []models.AssetNode{role, internal, ext,
			{ARN: "org:" + demoAcctCore, AssetType: models.AssetOrganizationAccount, AccountID: demoAcctCore, Name: demoAcctCore, Properties: map[string]any{"scan_status": "scanned"}},
			{ARN: "org:" + demoAcctData, AssetType: models.AssetOrganizationAccount, AccountID: demoAcctData, Name: demoAcctData, Properties: map[string]any{"scan_status": "scanned"}},
		}
		nodes, edges := collectors.BuildIdentityPolicyEvidence(role, []collectors.IdentityPolicyInput{inline("IDMixed", allowGet(objectARN("id-mixed", "readme.txt")))})
		assets = append(assets, nodes...)
		bucket, object := completeObject(scanID, demoAcctCore, "id-mixed", "readme.txt", nil)
		assets = append(assets, bucket, object)
		rels := append(edges, models.Relationship{
			SourceARN: role.ARN, TargetARN: ext.ARN, RelType: models.RelTrusts, ScanID: scanID,
			Properties: map[string]any{"principal_type": "aws_account", "principal_value": principal},
		}, models.Relationship{
			SourceARN: role.ARN, TargetARN: internal.ARN, RelType: models.RelTrusts, ScanID: scanID,
			Properties: map[string]any{"principal_type": "iam_role", "principal_value": internal.ARN},
		})
		return stamp(assets, rels)
	case "id-service":
		role := secRole(scanID, demoAcctCore, "IDService", nil)
		service := externalNode("ec2.amazonaws.com", "service")
		assets := []models.AssetNode{role, service}
		rels := []models.Relationship{{
			SourceARN: role.ARN, TargetARN: service.ARN, RelType: models.RelTrusts, ScanID: scanID,
			Properties: map[string]any{"principal_type": "service", "principal_value": "ec2.amazonaws.com"},
		}}
		return stamp(assets, rels)
	case "id-slr":
		role := secRole(scanID, demoAcctCore, "IDSLR", map[string]any{"path": "/aws-service-role/s3.amazonaws.com/"})
		role.ARN = "arn:aws:iam::" + demoAcctCore + ":role/aws-service-role/s3.amazonaws.com/IDSLR"
		return stamp([]models.AssetNode{role}, nil)
	case "id-wildcard":
		role := secRole(scanID, demoAcctCore, "IDWildcard", map[string]any{
			"trust_policy_document": `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"demo"}}}}`,
		})
		star := externalNode("*", "wildcard")
		assets := []models.AssetNode{role, star}
		rels := []models.Relationship{{
			SourceARN: role.ARN, TargetARN: star.ARN, RelType: models.RelTrusts, ScanID: scanID,
			Properties: map[string]any{"principal_type": "wildcard", "principal_value": "*"},
		}}
		return stamp(assets, rels)
	case "id-multipath":
		return multiPath(scanID)
	case "id-hist-a":
		return oneRole(scanID, "IDHistory", demoAcctCore, allowGet(objectARN("id-history", "readme.txt")), "id-history", nil)
	case "id-hist-b":
		return oneRole(scanID, "IDHistory", demoAcctCore, allowStar(), "id-history", map[string]any{"attached_policy_names": []string{"AdministratorAccess"}})
	default:
		return nil, nil
	}
}

func oneRole(scanID, name, account, policy, bucket string, extra map[string]any) ([]models.AssetNode, []models.Relationship) {
	if extra == nil {
		extra = map[string]any{}
	}
	role := secRole(scanID, account, name, extra)
	return withObject(scanID, role, bucket, policy)
}

func withObject(scanID string, role models.AssetNode, bucket, policy string) ([]models.AssetNode, []models.Relationship) {
	b, object := completeObject(scanID, role.AccountID, bucket, "readme.txt", nil)
	accountPrincipal := "arn:aws:iam::" + role.AccountID + ":root"
	principal := externalNode(accountPrincipal, "aws_account")
	assets := []models.AssetNode{role, b, object, principal}
	nodes, edges := collectors.BuildIdentityPolicyEvidence(role, []collectors.IdentityPolicyInput{inline(role.Name, policy)})
	edges = append(edges, models.Relationship{
		SourceARN: role.ARN, TargetARN: principal.ARN, RelType: models.RelTrusts,
		Properties: map[string]any{"principal_type": "aws_account", "principal_value": accountPrincipal},
	})
	return stamp(append(assets, nodes...), edges)
}

func trustPair(scanID, callerAccount, targetAccount, callerName, targetName, bucket, trustDoc, callerPolicy string, trustOnly bool) ([]models.AssetNode, []models.Relationship) {
	caller := secRole(scanID, callerAccount, callerName, nil)
	target := secRole(scanID, targetAccount, targetName, map[string]any{"trust_policy_document": trustDoc})
	assets := []models.AssetNode{caller, target}
	rels := []models.Relationship{{
		SourceARN: target.ARN, TargetARN: caller.ARN, RelType: models.RelTrusts, ScanID: scanID,
		Properties: map[string]any{"principal_type": "iam_role", "principal_value": caller.ARN},
	}, ownedBy(scanID, target)}
	if !trustOnly && callerPolicy != "" {
		nodes, edges := collectors.BuildIdentityPolicyEvidence(caller, []collectors.IdentityPolicyInput{inline(callerName, callerPolicy)})
		assets = append(assets, nodes...)
		rels = append(rels, edges...)
	}
	if bucket != "" && !trustOnly {
		b, object := completeObject(scanID, callerAccount, bucket, "readme.txt", nil)
		assets = append(assets, b, object)
	}
	return stamp(assets, rels)
}

func rcpRole(scanID string) ([]models.AssetNode, []models.Relationship) {
	object := objectARN("id-rcp", "readme.txt")
	role := secRole(scanID, demoAcctCore, "IDRCP", map[string]any{
		"scp_status": "present", "scp_hierarchy_complete": true, "scp_evidence": "demo observation: caller SCP allows the read",
		"scp_attachments": []map[string]any{orgAttachment("SERVICE_CONTROL_POLICY", "p-root", "root", "r-root", allowStar())},
	})
	bucket, obj := completeObject(scanID, demoAcctData, "id-rcp", "readme.txt", map[string]any{
		"bucket_policy_status": "present", "bucket_policy_evidence": "demo observation: bucket policy allows the caller",
		"bucket_policy_document": bucketAllow(role.ARN, object),
		"rcp_status":             "present", "rcp_evidence": "demo observation: target account RCP denies the read",
		"rcp_hierarchy_complete": true,
		"rcp_attachments": []map[string]any{
			orgAttachment("RESOURCE_CONTROL_POLICY", "p-rcp", "account", demoAcctData, `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}}`),
		},
	})
	assets := []models.AssetNode{role, bucket, obj}
	nodes, edges := collectors.BuildIdentityPolicyEvidence(role, []collectors.IdentityPolicyInput{inline("IDRCP", allowGet(object))})
	return stamp(append(assets, nodes...), edges)
}

func sharedPolicy(scanID string) ([]models.AssetNode, []models.Relationship) {
	a := secRole(scanID, demoAcctCore, "IDSharedA", nil)
	b := secRole(scanID, demoAcctCore, "IDSharedB", nil)
	policy := managedAdmin(allowGet(objectARN("id-shared", "readme.txt")))
	assets := []models.AssetNode{a, b}
	var rels []models.Relationship
	for _, role := range []models.AssetNode{a, b} {
		nodes, edges := collectors.BuildIdentityPolicyEvidence(role, []collectors.IdentityPolicyInput{policy})
		assets = append(assets, nodes...)
		rels = append(rels, edges...)
	}
	bucket, object := completeObject(scanID, demoAcctCore, "id-shared", "readme.txt", nil)
	return stamp(append(assets, bucket, object), rels)
}

func multiPath(scanID string) ([]models.AssetNode, []models.Relationship) {
	object := objectARN("id-multi", "readme.txt")
	caller := secRole(scanID, demoAcctCore, "IDMultiCaller", nil)
	target := secRole(scanID, demoAcctCore, "IDMultiTarget", map[string]any{"trust_policy_document": trustAllow(caller.ARN)})
	bucket, obj := completeObject(scanID, demoAcctCore, "id-multi", "readme.txt", nil)
	assets := []models.AssetNode{caller, target, bucket, obj}
	callerNodes, callerEdges := collectors.BuildIdentityPolicyEvidence(caller, []collectors.IdentityPolicyInput{inline("IDMultiCaller", allowAssumeRaw(target.ARN))})
	targetNodes, targetEdges := collectors.BuildIdentityPolicyEvidence(target, []collectors.IdentityPolicyInput{inline("IDMultiTarget", allowGet(object))})
	rels := append(callerEdges, targetEdges...)
	rels = append(rels, models.Relationship{
		SourceARN: target.ARN, TargetARN: caller.ARN, RelType: models.RelTrusts, ScanID: scanID,
		Properties: map[string]any{"principal_type": "iam_role", "principal_value": caller.ARN},
	})
	return stamp(append(assets, append(callerNodes, targetNodes...)...), rels)
}

func allowAssumeRaw(target string) string {
	return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"` + objectARN("id-multi", "readme.txt") + `"},{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"` + target + `"}]}`
}

func stamp(assets []models.AssetNode, rels []models.Relationship) ([]models.AssetNode, []models.Relationship) {
	return assets, rels
}
