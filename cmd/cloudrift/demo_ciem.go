package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/collectors"
	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/scorers"
)

func ciemRoleScenario(scanID, scenario string) ([]models.AssetNode, []models.Relationship) {
	account := "999999999999"
	principalValue := "arn:aws:iam::" + account + ":root"
	roleName := "CIEMAdmin"
	policy := allowStar()
	extra := map[string]any{"attached_policy_names": []string{"AdministratorAccess"}}
	var policies []collectors.IdentityPolicyInput
	policies = []collectors.IdentityPolicyInput{managedAdmin(policy)}
	switch scenario {
	case "ciem-stale":
		roleName = "CIEMScoped"
		extra = nil
		policy = allowGet(objectARN("ciem-stale", "readme.txt"))
		policies = []collectors.IdentityPolicyInput{inline("CIEMScoped", policy)}
	case "ciem-chain":
		return ciemChain(scanID, principalValue)
	}
	role := secRole(scanID, demoAcctCore, roleName, extra)
	role.Properties["trust_policy_document"] = trustAllow(principalValue)
	bucketName := "ciem-admin"
	if scenario == "ciem-stale" {
		bucketName = "ciem-stale"
	}
	bucket, object := completeObject(scanID, demoAcctCore, bucketName, "readme.txt", nil)
	var assets []models.AssetNode
	var rels []models.Relationship
	assets = append(assets, role, bucket, object, externalNode(principalValue, "aws_account"))
	nodes, edges := collectors.BuildIdentityPolicyEvidence(role, policies)
	assets = append(assets, nodes...)
	rels = append(rels, edges...)
	rels = append(rels, ownedBy(scanID, role))
	rels = append(rels, models.Relationship{
		SourceARN: role.ARN, TargetARN: externalNode(principalValue, "aws_account").ARN,
		RelType: models.RelTrusts, ScanID: scanID,
		Properties: map[string]any{"principal_type": "aws_account", "principal_value": principalValue},
	})
	if scenario == "ciem-multi" {
		specific := "arn:aws:iam::" + account + ":user/partner"
		assets = append(assets, externalNode(specific, "iam_user"))
		rels = append(rels, models.Relationship{
			SourceARN: role.ARN, TargetARN: externalNode(specific, "iam_user").ARN,
			RelType: models.RelTrusts, ScanID: scanID,
			Properties: map[string]any{"principal_type": "iam_user", "principal_value": specific},
		})
	}
	for i := range assets {
		assets[i].ScanID = scanID
	}
	return assets, rels
}

func ciemChain(scanID, principalValue string) ([]models.AssetNode, []models.Relationship) {
	object := objectARN("ciem-chain", "readme.txt")
	caller := secRole(scanID, demoAcctCore, "CIEMChainCaller", nil)
	target := secRole(scanID, demoAcctCore, "CIEMChainTarget", map[string]any{
		"trust_policy_document": trustAllow(caller.ARN),
	})
	caller.Properties["trust_policy_document"] = trustAllow(principalValue)
	bucket, obj := completeObject(scanID, demoAcctCore, "ciem-chain", "readme.txt", nil)
	principal := externalNode(principalValue, "aws_account")
	var assets []models.AssetNode
	var rels []models.Relationship
	assets = append(assets, caller, target, bucket, obj, principal)
	callerNodes, callerEdges := collectors.BuildIdentityPolicyEvidence(caller, []collectors.IdentityPolicyInput{inline("CIEMChainCaller", allowAssume(target.ARN))})
	targetNodes, targetEdges := collectors.BuildIdentityPolicyEvidence(target, []collectors.IdentityPolicyInput{inline("CIEMChainTarget", allowGet(object))})
	assets = append(assets, callerNodes...)
	assets = append(assets, targetNodes...)
	rels = append(rels, callerEdges...)
	rels = append(rels, targetEdges...)
	rels = append(rels, ownedBy(scanID, caller), ownedBy(scanID, target))
	rels = append(rels, models.Relationship{
		SourceARN: caller.ARN, TargetARN: principal.ARN, RelType: models.RelTrusts, ScanID: scanID,
		Properties: map[string]any{"principal_type": "aws_account", "principal_value": principalValue},
	})
	for i := range assets {
		assets[i].ScanID = scanID
	}
	return assets, rels
}

func ciemBucketScenario(scanID string) ([]models.AssetNode, []models.Relationship) {
	bucket := completeBucket(scanID, demoAcctCore, "ciem-public", nil)
	principal := externalNode("*", "wildcard")
	bucket.ScanID = scanID
	principal.ScanID = scanID
	return []models.AssetNode{bucket, principal}, []models.Relationship{{
		SourceARN: bucket.ARN, TargetARN: principal.ARN, RelType: models.RelTrusts, ScanID: scanID,
		Properties: map[string]any{
			"source_kind": "s3_bucket_policy", "is_public": true, "principal_type": "wildcard",
			"principal_value": "*", "actions": []string{"s3:GetObject"},
		},
	}}
}

func ciemSCPScenario(scanID string) ([]models.AssetNode, []models.Relationship) {
	principalValue := "arn:aws:iam::999999999999:root"
	object := objectARN("ciem-scp", "readme.txt")
	role := secRole(scanID, demoAcctCore, "CIEMSCP", map[string]any{
		"trust_policy_document": trustAllow(principalValue),
		"scp_status":            "present",
		"scp_evidence":          "demo observation: SCP p-deny is attached to the account",
		"scp_documents":         []string{`{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}}`},
		"scp_coverage":          "COMPLETE_FOR_SUPPORTED_SCOPE",
	})
	bucket, obj := completeObject(scanID, demoAcctCore, "ciem-scp", "readme.txt", nil)
	principal := externalNode(principalValue, "aws_account")
	assets := []models.AssetNode{role, bucket, obj, principal}
	nodes, edges := collectors.BuildIdentityPolicyEvidence(role, []collectors.IdentityPolicyInput{inline("CIEMSCP", allowGet(object))})
	assets = append(assets, nodes...)
	rels := append(edges, ownedBy(scanID, role), models.Relationship{
		SourceARN: role.ARN, TargetARN: principal.ARN, RelType: models.RelTrusts, ScanID: scanID,
		Properties: map[string]any{"principal_type": "aws_account", "principal_value": principalValue},
	})
	for i := range assets {
		assets[i].ScanID = scanID
	}
	return assets, rels
}

func ciemOrgScenario(scanID, scenario string) ([]models.AssetNode, []models.Relationship) {
	principalValue := "arn:aws:iam::999999999999:root"
	name := strings.TrimPrefix(scenario, "ciem-")
	object := objectARN(name, "readme.txt")
	full := allowStar()
	s3 := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`
	ec2 := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"ec2:*","Resource":"*"}}`
	account := demoAcctCore
	ou := "ou-ciem"
	if scenario == "ciem-scp-moved" {
		ou = "ou-moved"
	}
	var attachments []map[string]any
	extra := map[string]any{
		"trust_policy_document": trustAllow(principalValue),
		"scp_coverage":          "COMPLETE_FOR_SUPPORTED_SCOPE",
	}
	switch scenario {
	case "ciem-scp-gap":
		extra["scp_status"] = "missing"
		extra["scp_evidence"] = "demo observation: the parent OU was not returned; the SCP hierarchy is incomplete"
		extra["scp_coverage"] = "NOT_COLLECTED"
	case "ciem-scp-ancestor":
		attachments = []map[string]any{
			orgAttachment("SERVICE_CONTROL_POLICY", "p-root", "root", "r-root", s3),
			orgAttachment("SERVICE_CONTROL_POLICY", "p-ou", "organizational_unit", ou, ec2),
			orgAttachment("SERVICE_CONTROL_POLICY", "p-acct", "account", account, full),
		}
	case "ciem-scp-deny":
		attachments = []map[string]any{
			orgAttachment("SERVICE_CONTROL_POLICY", "p-root", "root", "r-root", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}]}`),
			orgAttachment("SERVICE_CONTROL_POLICY", "p-ou", "organizational_unit", ou, full),
			orgAttachment("SERVICE_CONTROL_POLICY", "p-acct", "account", account, full),
		}
	case "ciem-scp-implicit":
		attachments = []map[string]any{
			orgAttachment("SERVICE_CONTROL_POLICY", "p-root", "root", "r-root", ec2),
			orgAttachment("SERVICE_CONTROL_POLICY", "p-ou", "organizational_unit", ou, ec2),
			orgAttachment("SERVICE_CONTROL_POLICY", "p-acct", "account", account, ec2),
		}
	default:
		attachments = []map[string]any{
			orgAttachment("SERVICE_CONTROL_POLICY", "p-root", "root", "r-root", full),
			orgAttachment("SERVICE_CONTROL_POLICY", "p-s3", "organizational_unit", ou, s3),
			orgAttachment("SERVICE_CONTROL_POLICY", "p-ec2", "organizational_unit", ou, ec2),
			orgAttachment("SERVICE_CONTROL_POLICY", "p-acct", "account", account, full),
		}
	}
	if scenario != "ciem-scp-gap" {
		extra["scp_status"] = "present"
		extra["scp_evidence"] = "demo observation: SCP attachments record the root, OU, and account"
		extra["scp_hierarchy_complete"] = true
		extra["scp_attachments"] = attachments
		extra["org_hierarchy_targets"] = []string{account, ou, "r-root"}
	}
	role := secRole(scanID, account, "CIEM"+name, extra)
	bucket, obj := completeObject(scanID, account, name, "readme.txt", nil)
	principal := externalNode(principalValue, "aws_account")
	assets := []models.AssetNode{role, bucket, obj, principal}
	nodes, edges := collectors.BuildIdentityPolicyEvidence(role, []collectors.IdentityPolicyInput{inline("CIEM"+name, allowGet(object))})
	assets = append(assets, nodes...)
	rels := append(edges, ownedBy(scanID, role), models.Relationship{
		SourceARN: role.ARN, TargetARN: principal.ARN, RelType: models.RelTrusts, ScanID: scanID,
		Properties: map[string]any{"principal_type": "aws_account", "principal_value": principalValue},
	})
	for i := range assets {
		assets[i].ScanID = scanID
	}
	return assets, rels
}

func ciemRCPScenario(scanID, scenario string) ([]models.AssetNode, []models.Relationship) {
	principalValue := "arn:aws:iam::999999999999:root"
	caller := secRole(scanID, demoAcctCore, "CIEMRCPCaller", map[string]any{
		"trust_policy_document":  trustAllow(principalValue),
		"scp_status":             "present",
		"scp_evidence":           "demo observation: the caller account SCP hierarchy allows the action",
		"scp_hierarchy_complete": true,
		"scp_attachments": []map[string]any{
			orgAttachment("SERVICE_CONTROL_POLICY", "p-root", "root", "r-root", allowStar()),
			orgAttachment("SERVICE_CONTROL_POLICY", "p-ou", "organizational_unit", "ou-caller", allowStar()),
			orgAttachment("SERVICE_CONTROL_POLICY", "p-acct", "account", demoAcctCore, allowStar()),
		},
		"rcp_status":   "confirmed_absent",
		"rcp_evidence": "demo observation: the caller account is not the resource owner used for RCP evaluation",
	})
	var target models.AssetNode
	var bucket, object models.AssetNode
	var policies string
	switch scenario {
	case "ciem-rcp-assume":
		target = secRole(scanID, demoAcctData, "CIEMRCPTarget", map[string]any{
			"trust_policy_document":  trustAllow(caller.ARN),
			"rcp_status":             "present",
			"rcp_evidence":           "demo observation: RCP attachments belong to the target role account",
			"rcp_hierarchy_complete": true,
			"rcp_attachments": []map[string]any{
				orgAttachment("RESOURCE_CONTROL_POLICY", "p-rcp", "root", "r-root", `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"sts:AssumeRole","Resource":"*"}}`),
			},
		})
		policies = allowAssume(target.ARN)
	case "ciem-mgmt":
		caller.Properties["org_management_account_id"] = demoAcctData
		caller.Properties["rcp_status"] = "present"
		caller.Properties["rcp_evidence"] = "demo observation: a restrictive RCP is attached to the caller account and must not be applied to the management account resource"
		caller.Properties["rcp_hierarchy_complete"] = true
		caller.Properties["rcp_attachments"] = []map[string]any{
			orgAttachment("RESOURCE_CONTROL_POLICY", "p-caller", "account", demoAcctCore, `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}}`),
		}
		bucket, object = completeObject(scanID, demoAcctData, "ciem-mgmt", "readme.txt", map[string]any{
			"bucket_policy_status":      "present",
			"bucket_policy_evidence":    "demo observation: s3:GetBucketPolicy returned a policy document",
			"bucket_policy_document":    bucketAllow(caller.ARN, objectARN("ciem-mgmt", "readme.txt")),
			"org_management_account_id": demoAcctData,
		})
		policies = allowGet(object.ARN)
	default:
		bucket, object = completeObject(scanID, demoAcctData, "ciem-rcp", "readme.txt", map[string]any{
			"bucket_policy_status":   "present",
			"bucket_policy_evidence": "demo observation: s3:GetBucketPolicy returned a policy document",
			"bucket_policy_document": bucketAllow(caller.ARN, objectARN("ciem-rcp", "readme.txt")),
			"rcp_status":             "present",
			"rcp_evidence":           "demo observation: RCP attachments belong to the bucket account",
			"rcp_hierarchy_complete": true,
			"rcp_attachments": []map[string]any{
				orgAttachment("RESOURCE_CONTROL_POLICY", "p-rcp", "account", demoAcctData, `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}}`),
			},
		})
		policies = allowGet(object.ARN)
	}
	principal := externalNode(principalValue, "aws_account")
	assets := []models.AssetNode{caller, principal}
	if target.ARN != "" {
		assets = append(assets, target)
	}
	if bucket.ARN != "" {
		assets = append(assets, bucket, object)
	}
	nodes, edges := collectors.BuildIdentityPolicyEvidence(caller, []collectors.IdentityPolicyInput{inline("CIEMRCPCaller", policies)})
	assets = append(assets, nodes...)
	rels := append(edges, ownedBy(scanID, caller), models.Relationship{
		SourceARN: caller.ARN, TargetARN: principal.ARN, RelType: models.RelTrusts, ScanID: scanID,
		Properties: map[string]any{"principal_type": "aws_account", "principal_value": principalValue},
	})
	if target.ARN != "" {
		rels = append(rels, ownedBy(scanID, target))
	}
	for i := range assets {
		assets[i].ScanID = scanID
	}
	return assets, rels
}

func ciemScopeScenario(scanID string) ([]models.AssetNode, []models.Relationship) {
	principalValue := "arn:aws:iam::999999999999:root"
	role := secRole(scanID, demoAcctCore, "CIEMScope", map[string]any{
		"trust_policy_document": trustAllow(principalValue),
	})
	bucket := completeBucket(scanID, demoAcctCore, "ciem-scope", nil)
	principal := externalNode(principalValue, "aws_account")
	assets := []models.AssetNode{role, bucket, principal}
	nodes, edges := collectors.BuildIdentityPolicyEvidence(role, []collectors.IdentityPolicyInput{inline("CIEMScope", allowGet("arn:aws:s3:::ciem-scope/*"))})
	assets = append(assets, nodes...)
	rels := append(edges, ownedBy(scanID, role), models.Relationship{
		SourceARN: role.ARN, TargetARN: principal.ARN, RelType: models.RelTrusts, ScanID: scanID,
		Properties: map[string]any{"principal_type": "aws_account", "principal_value": principalValue},
	})
	for i := range assets {
		assets[i].ScanID = scanID
	}
	return assets, rels
}

func externalNode(value, principalType string) models.AssetNode {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(value))
	node := models.AssetNode{
		ARN:       "arn:cloudrift:external-principal:::" + principalType + "/" + encoded,
		AssetType: models.AssetExternalPrincipal, Name: value, Region: "global",
		Properties: map[string]any{"principal_type": principalType, "principal_value": value},
	}
	node, _ = models.ResolvePrincipalOwnership(node)
	return node
}

func attachCIEMFindings(scanPath, scenario string) error {
	scanID := filepath.Base(scanPath)
	var assets []models.AssetNode
	b, err := os.ReadFile(filepath.Join(scanPath, "assets", "security_fixtures.json"))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &assets); err != nil {
		return err
	}
	var rels []models.Relationship
	b, err = os.ReadFile(filepath.Join(scanPath, "relationships.json"))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &rels); err != nil {
		return err
	}
	activity := map[string]collectors.RoleActivity{}
	if scenario == "ciem-stale" {
		for _, asset := range assets {
			if asset.AssetType == models.AssetIAMRole {
				activity[asset.ARN] = collectors.RoleActivity{RoleARN: asset.ARN, DaysSinceUsed: 400}
			}
		}
	}
	findings := scorers.ScoreTrust(assets, rels, activity, config.Default())
	findings = append(findings, scorers.ScoreResourceExposure(assets, rels, config.Default())...)
	if strings.HasPrefix(scenario, "id-") || strings.HasPrefix(scenario, "wl-") || strings.HasPrefix(scenario, "ecs-") || strings.HasPrefix(scenario, "eks-") || strings.HasPrefix(scenario, "irsa-") || strings.HasPrefix(scenario, "ct-") || scenario == "share-ecs-lambda" {
		findings = append(findings, scorers.ScoreEntitlements(assets, rels)...)
	}
	for i := range findings {
		findings[i].ScanID = scanID
	}
	return writeJSONFile(filepath.Join(scanPath, "findings.json"), findings)
}
