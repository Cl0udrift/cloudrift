package main

import (
	"github.com/Zero0x00/cloudrift/internal/collectors"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func workloadScenarioIDs() []string {
	return []string{
		"wl-ec2-map", "wl-ec2-none", "wl-ec2-names", "wl-ec2-denied", "wl-ec2-share",
		"wl-lambda-scoped", "wl-lambda-admin", "wl-lambda-missing", "wl-lambda-trust",
		"wl-missing-scp", "wl-deny", "wl-assume", "wl-shared-resource",
		"wl-hist-a", "wl-hist-b", "wl-attach-a", "wl-attach-b", "wl-org-gap", "wl-org-unknown",
	}
}

func workloadScenario(scanID, scenario string) ([]models.AssetNode, []models.Relationship) {
	switch scenario {
	case "wl-ec2-map":
		return ec2Mapped(scanID, "WLMap", "wl-map-profile", "WLMapRole", false)
	case "wl-ec2-none":
		role := secRole(scanID, demoAcctCore, "WLNoneRole", nil)
		instance := ec2Instance(demoAcctCore, "i-none", "us-east-1")
		instance.Properties["attachment_status"] = "none"
		return []models.AssetNode{role, instance}, nil
	case "wl-ec2-names":
		return ec2Mapped(scanID, "web-profile", "web-profile", "WLAppRole", false)
	case "wl-ec2-denied":
		role := secRole(scanID, demoAcctCore, "WLDeniedRole", nil)
		instance := ec2Instance(demoAcctCore, "i-denied", "us-east-1")
		profile := instanceProfile(demoAcctCore, "denied-profile")
		profile.Properties["retrieval_status"] = "denied"
		instance.Properties["instance_profile_arn"] = profile.ARN
		rels := []models.Relationship{{
			SourceARN: instance.ARN, TargetARN: profile.ARN, RelType: models.RelEC2UsesInstanceProfile,
			Properties: map[string]any{"kind": "UNRESOLVED_ROLE", "mechanism": "instance_profile", "relationship_id": "denied-assoc", "note": "iam:GetInstanceProfile was denied."},
		}}
		return []models.AssetNode{role, instance, profile}, rels
	case "wl-ec2-share":
		return sharedEC2(scanID)
	case "wl-lambda-scoped":
		return lambdaRole(scanID, "WLLambdaScoped", allowGet(objectARN("wl-lambda", "readme.txt")), "wl-lambda", false)
	case "wl-lambda-admin":
		return lambdaRole(scanID, "WLLambdaAdmin", allowStar(), "wl-lambda-admin", true)
	case "wl-lambda-missing":
		fn := lambdaFunction(demoAcctCore, "missing-fn", "us-east-1", roleARN(demoAcctCore, "MissingRole"))
		rels := []models.Relationship{{
			SourceARN: fn.ARN, TargetARN: roleARN(demoAcctCore, "MissingRole"), RelType: models.RelLambdaUsesExecutionRole,
			Properties: map[string]any{"kind": "UNRESOLVED_ROLE", "mechanism": "lambda_execution_role", "relationship_id": "lambda-missing", "note": "The referenced role was not in the collected role inventory."},
		}}
		return []models.AssetNode{fn}, rels
	case "wl-lambda-trust":
		role := secRole(scanID, demoAcctCore, "WLServiceOnly", nil)
		service := externalNode("lambda.amazonaws.com", "service")
		rels := []models.Relationship{{
			SourceARN: role.ARN, TargetARN: service.ARN, RelType: models.RelTrusts,
			Properties: map[string]any{"principal_type": "service", "principal_value": "lambda.amazonaws.com"},
		}}
		return []models.AssetNode{role, service}, rels
	case "wl-missing-scp":
		role := secRole(scanID, demoAcctCore, "WLMissingSCP", map[string]any{
			"scp_status": "missing", "scp_evidence": "organizations collection denied",
			"session_policy_status": "missing", "session_policy_evidence": "no session document was collected",
		})
		return lambdaAttached(scanID, role, "wl-missing-scp")
	case "wl-deny":
		object := objectARN("wl-deny", "readme.txt")
		role := secRole(scanID, demoAcctCore, "WLDeny", nil)
		nodes, edges := collectors.BuildIdentityPolicyEvidence(role, []collectors.IdentityPolicyInput{inline("WLDeny", allowAndDeny(object))})
		bucket, obj := completeObject(scanID, demoAcctCore, "wl-deny", "readme.txt", nil)
		fn := lambdaFunction(demoAcctCore, "WLDenyFn", "us-east-1", role.ARN)
		edges = append(edges, models.Relationship{
			SourceARN: fn.ARN, TargetARN: role.ARN, RelType: models.RelLambdaUsesExecutionRole,
			Properties: map[string]any{"kind": "CONFIGURED_ROLE_ATTACHMENT", "mechanism": "lambda_execution_role", "relationship_id": "lambda-WLDeny"},
		})
		return append([]models.AssetNode{role, fn, bucket, obj}, nodes...), edges
	case "wl-assume":
		return workloadAssume(scanID)
	case "wl-shared-resource":
		return sharedResource(scanID)
	case "wl-hist-a":
		return lambdaRole(scanID, "WLHistory", allowGet(objectARN("wl-history", "readme.txt")), "wl-history", false)
	case "wl-hist-b":
		return lambdaRole(scanID, "WLHistory", allowStar(), "wl-history", true)
	case "wl-attach-a":
		return ec2Mapped(scanID, "WLAttach", "wl-attach-profile", "WLAttachRole", false)
	case "wl-attach-b":
		assets, rels := ec2Mapped(scanID, "WLAttach", "wl-attach-profile", "WLAttachRole", false)
		second := ec2Instance(demoAcctCore, "i-WLAttach-2", "us-west-2")
		rels = append(rels, models.Relationship{SourceARN: second.ARN, TargetARN: "arn:aws:iam::" + demoAcctCore + ":instance-profile/wl-attach-profile", RelType: models.RelEC2UsesInstanceProfile, Properties: map[string]any{"kind": "CONFIGURED_ROLE_ATTACHMENT", "mechanism": "instance_profile", "relationship_id": "ec2-WLAttach-2"}})
		return append(assets, second), rels
	case "wl-org-gap":
		role := secRole(scanID, demoAcctCore, "WLOrgGap", nil)
		org := []models.AssetNode{
			{ARN: "org:" + demoAcctCore, AssetType: models.AssetOrganizationAccount, AccountID: demoAcctCore, Properties: map[string]any{"scan_status": "scanned"}},
			{ARN: "org:333333333333", AssetType: models.AssetOrganizationAccount, AccountID: "333333333333", Properties: map[string]any{"scan_status": "not_scanned"}},
		}
		rels := []models.Relationship{{
			SourceARN: role.ARN, TargetARN: "arn:aws:iam::333333333333:root", RelType: models.RelTrusts,
			Properties: map[string]any{"principal_type": "aws_account", "principal_value": "arn:aws:iam::333333333333:root"},
		}}
		return append([]models.AssetNode{role}, org...), rels
	case "wl-org-unknown":
		role := secRole(scanID, demoAcctCore, "WLOrgUnknown", nil)
		rels := []models.Relationship{{
			SourceARN: role.ARN, TargetARN: "arn:aws:iam::999999999999:root", RelType: models.RelTrusts,
			Properties: map[string]any{"principal_type": "aws_account", "principal_value": "arn:aws:iam::999999999999:root"},
		}}
		return []models.AssetNode{role}, rels
	default:
		return nil, nil
	}
}

func ec2Mapped(scanID, instanceName, profileName, roleName string, _ bool) ([]models.AssetNode, []models.Relationship) {
	role := secRole(scanID, demoAcctCore, roleName, nil)
	instance := ec2Instance(demoAcctCore, "i-"+instanceName, "us-east-1")
	profile := instanceProfile(demoAcctCore, profileName)
	profile.Properties["role_arn"] = role.ARN
	profile.Properties["role_name"] = roleName
	profile.Properties["retrieval_status"] = "ok"
	instance.Properties["instance_profile_arn"] = profile.ARN
	instance.Properties["association_state"] = "associated"
	rels := []models.Relationship{
		{SourceARN: instance.ARN, TargetARN: profile.ARN, RelType: models.RelEC2UsesInstanceProfile, Properties: map[string]any{"kind": "CONFIGURED_ROLE_ATTACHMENT", "mechanism": "instance_profile", "relationship_id": "ec2-" + instanceName, "source_api": "ec2:DescribeIamInstanceProfileAssociations", "note": "Configured instance profile association."}},
		{SourceARN: profile.ARN, TargetARN: role.ARN, RelType: models.RelInstanceProfileContains, Properties: map[string]any{"kind": "CONFIGURED_ROLE_ATTACHMENT", "mechanism": "instance_profile", "relationship_id": "profile-" + profileName, "source_api": "iam:GetInstanceProfile", "note": "Role resolved from the instance profile."}},
	}
	return []models.AssetNode{role, instance, profile}, rels
}

func sharedEC2(scanID string) ([]models.AssetNode, []models.Relationship) {
	role := secRole(scanID, demoAcctCore, "WLSharedRole", map[string]any{"attached_policy_names": []string{"AdministratorAccess"}})
	profile := instanceProfile(demoAcctCore, "shared-profile")
	a := ec2Instance(demoAcctCore, "i-share-a", "us-east-1")
	b := ec2Instance(demoAcctCore, "i-share-b", "us-west-2")
	var rels []models.Relationship
	rels = append(rels, models.Relationship{SourceARN: profile.ARN, TargetARN: role.ARN, RelType: models.RelInstanceProfileContains, Properties: map[string]any{"kind": "CONFIGURED_ROLE_ATTACHMENT", "mechanism": "instance_profile", "relationship_id": "shared-profile"}})
	for _, instance := range []models.AssetNode{a, b} {
		rels = append(rels, models.Relationship{SourceARN: instance.ARN, TargetARN: profile.ARN, RelType: models.RelEC2UsesInstanceProfile, Properties: map[string]any{"kind": "CONFIGURED_ROLE_ATTACHMENT", "mechanism": "instance_profile", "relationship_id": instance.Name}})
	}
	return []models.AssetNode{role, profile, a, b}, rels
}

func lambdaRole(scanID, roleName, policy, bucket string, admin bool) ([]models.AssetNode, []models.Relationship) {
	extra := map[string]any{}
	if admin {
		extra["attached_policy_names"] = []string{"AdministratorAccess"}
	}
	role := secRole(scanID, demoAcctCore, roleName, extra)
	nodes, edges := collectors.BuildIdentityPolicyEvidence(role, []collectors.IdentityPolicyInput{inline(roleName, policy)})
	b, object := completeObject(scanID, demoAcctCore, bucket, "readme.txt", nil)
	fn := lambdaFunction(demoAcctCore, roleName+"Fn", "us-east-1", role.ARN)
	edges = append(edges, models.Relationship{SourceARN: fn.ARN, TargetARN: role.ARN, RelType: models.RelLambdaUsesExecutionRole, Properties: map[string]any{"kind": "CONFIGURED_ROLE_ATTACHMENT", "mechanism": "lambda_execution_role", "relationship_id": "lambda-" + roleName, "note": "Function configuration names the execution role."}})
	return append([]models.AssetNode{role, fn, b, object}, nodes...), edges
}

func lambdaAttached(scanID string, role models.AssetNode, bucket string) ([]models.AssetNode, []models.Relationship) {
	fn := lambdaFunction(demoAcctCore, role.Name+"Fn", "us-east-1", role.ARN)
	rels := []models.Relationship{{SourceARN: fn.ARN, TargetARN: role.ARN, RelType: models.RelLambdaUsesExecutionRole, Properties: map[string]any{"kind": "CONFIGURED_ROLE_ATTACHMENT", "mechanism": "lambda_execution_role", "relationship_id": "lambda-" + role.Name}}}
	return []models.AssetNode{role, fn}, rels
}

func workloadAssume(scanID string) ([]models.AssetNode, []models.Relationship) {
	caller := secRole(scanID, demoAcctCore, "WLAssumeCaller", nil)
	target := secRole(scanID, demoAcctCore, "WLAssumeTarget", map[string]any{"trust_policy_document": trustAllow(caller.ARN)})
	nodes, edges := collectors.BuildIdentityPolicyEvidence(caller, []collectors.IdentityPolicyInput{inline("WLAssumeCaller", allowAssume(target.ARN))})
	fn := lambdaFunction(demoAcctCore, "assume-fn", "us-east-1", caller.ARN)
	edges = append(edges, models.Relationship{SourceARN: fn.ARN, TargetARN: caller.ARN, RelType: models.RelLambdaUsesExecutionRole, Properties: map[string]any{"kind": "CONFIGURED_ROLE_ATTACHMENT", "mechanism": "lambda_execution_role", "relationship_id": "lambda-assume"}},
		models.Relationship{SourceARN: target.ARN, TargetARN: caller.ARN, RelType: models.RelTrusts, Properties: map[string]any{"principal_type": "iam_role", "principal_value": caller.ARN}})
	return append([]models.AssetNode{caller, target, fn}, nodes...), edges
}

func sharedResource(scanID string) ([]models.AssetNode, []models.Relationship) {
	role := secRole(scanID, demoAcctCore, "WLBoth", nil)
	nodes, edges := collectors.BuildIdentityPolicyEvidence(role, []collectors.IdentityPolicyInput{inline("WLBoth", allowGet(objectARN("wl-both", "readme.txt")))})
	b, object := completeObject(scanID, demoAcctCore, "wl-both", "readme.txt", nil)
	fn := lambdaFunction(demoAcctCore, "both-fn", "us-east-1", role.ARN)
	instance := ec2Instance(demoAcctCore, "i-both", "us-east-1")
	profile := instanceProfile(demoAcctCore, "both-profile")
	edges = append(edges,
		models.Relationship{SourceARN: fn.ARN, TargetARN: role.ARN, RelType: models.RelLambdaUsesExecutionRole, Properties: map[string]any{"kind": "CONFIGURED_ROLE_ATTACHMENT", "mechanism": "lambda_execution_role", "relationship_id": "both-lambda"}},
		models.Relationship{SourceARN: instance.ARN, TargetARN: profile.ARN, RelType: models.RelEC2UsesInstanceProfile, Properties: map[string]any{"kind": "CONFIGURED_ROLE_ATTACHMENT", "mechanism": "instance_profile", "relationship_id": "both-ec2"}},
		models.Relationship{SourceARN: profile.ARN, TargetARN: role.ARN, RelType: models.RelInstanceProfileContains, Properties: map[string]any{"kind": "CONFIGURED_ROLE_ATTACHMENT", "mechanism": "instance_profile", "relationship_id": "both-profile"}},
	)
	return append([]models.AssetNode{role, fn, instance, profile, b, object}, nodes...), edges
}

func ec2Instance(account, id, region string) models.AssetNode {
	return models.AssetNode{ARN: "arn:aws:ec2:" + region + ":" + account + ":instance/" + id, AssetType: models.AssetEC2Instance, Name: id, AccountID: account, Region: region, Properties: map[string]any{}}
}

func instanceProfile(account, name string) models.AssetNode {
	return models.AssetNode{ARN: "arn:aws:iam::" + account + ":instance-profile/" + name, AssetType: models.AssetInstanceProfile, Name: name, AccountID: account, Region: "global", Properties: map[string]any{}}
}

func lambdaFunction(account, name, region, roleARN string) models.AssetNode {
	return models.AssetNode{
		ARN: "arn:aws:lambda:" + region + ":" + account + ":function:" + name, AssetType: models.AssetLambdaFunction,
		Name: name, AccountID: account, Region: region,
		Properties: map[string]any{"execution_role_arn": roleARN, "configuration_scope": "function"},
	}
}
