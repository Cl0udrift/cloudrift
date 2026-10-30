package main

import (
	"fmt"

	"github.com/Zero0x00/cloudrift/internal/collectors"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func containerScenarioIDs() []string {
	return []string{
		"ecs-task-role", "ecs-exec-role", "ecs-both", "ecs-running", "ecs-service-idle", "ecs-missing-role", "ecs-shared", "ecs-partial",
		"eks-pod-id", "eks-sa-absent", "eks-missing-role",
		"irsa-trust", "irsa-exact", "irsa-wildcard", "irsa-no-k8s",
		"share-ecs-lambda", "ct-deny", "ct-missing-scp", "ct-assume", "ct-shared-object", "ct-hist-a", "ct-hist-b",
		"inv-mixed", "inv-pages", "regions-coverage",
	}
}

func containerScenario(scanID, scenario string) ([]models.AssetNode, []models.Relationship, bool) {
	switch scenario {
	case "ecs-task-role":
		role := secRole(scanID, demoAcctCore, "ECSTask", nil)
		def := taskDef(demoAcctCore, "app", "1", role.ARN, "")
		return []models.AssetNode{role, def}, defRoleEdges(def, role.ARN, ""), true
	case "ecs-exec-role":
		role := secRole(scanID, demoAcctCore, "ECSExec", nil)
		def := taskDef(demoAcctCore, "app", "1", "", role.ARN)
		return []models.AssetNode{role, def}, defRoleEdges(def, "", role.ARN), true
	case "ecs-both":
		task := secRole(scanID, demoAcctCore, "ECSTask", nil)
		exec := secRole(scanID, demoAcctCore, "ECSExec", nil)
		def := taskDef(demoAcctCore, "app", "2", task.ARN, exec.ARN)
		return []models.AssetNode{task, exec, def}, defRoleEdges(def, task.ARN, exec.ARN), true
	case "ecs-running":
		oldRole := secRole(scanID, demoAcctCore, "ECSRev3", nil)
		newRole := secRole(scanID, demoAcctCore, "ECSRev4", nil)
		old := taskDef(demoAcctCore, "app", "3", oldRole.ARN, "")
		newer := taskDef(demoAcctCore, "app", "4", newRole.ARN, "")
		task := ecsTask(demoAcctCore, "task-1", old.ARN, "RUNNING")
		rels := append(defRoleEdges(old, oldRole.ARN, ""), defRoleEdges(newer, newRole.ARN, "")...)
		rels = append(rels, models.Relationship{SourceARN: task.ARN, TargetARN: old.ARN, RelType: models.RelECSTaskUsesTaskDef, Properties: map[string]any{
			"status": "OBSERVED_TASK_CONFIGURATION", "runtime_observed": "OBSERVED_RUNNING", "revision": "3", "relationship_id": "task-1",
		}})
		return []models.AssetNode{oldRole, newRole, old, newer, task}, rels, true
	case "ecs-service-idle":
		role := secRole(scanID, demoAcctCore, "ECSIdle", nil)
		def := taskDef(demoAcctCore, "idle", "1", role.ARN, "")
		svc := ecsService(demoAcctCore, "web", def.ARN, 0)
		rels := append(defRoleEdges(def, role.ARN, ""), serviceEdge(svc, def))
		return []models.AssetNode{role, def, svc}, rels, true
	case "ecs-missing-role":
		def := taskDef(demoAcctCore, "missing", "1", roleARN(demoAcctCore, "MissingECS"), "")
		rels := defRoleEdges(def, roleARN(demoAcctCore, "MissingECS"), "")
		collectors.MarkUnresolvedRoleReferences([]models.AssetNode{def}, rels)
		return []models.AssetNode{def}, rels, true
	case "ecs-shared":
		role := secRole(scanID, demoAcctCore, "ECSShared", map[string]any{"attached_policy_names": []string{"AdministratorAccess"}})
		a := taskDef(demoAcctCore, "one", "1", role.ARN, "")
		b := taskDef(demoAcctCore, "two", "1", role.ARN, "")
		return []models.AssetNode{role, a, b}, append(defRoleEdges(a, role.ARN, ""), defRoleEdges(b, role.ARN, "")...), true
	case "ecs-partial":
		return []models.AssetNode{{
			ARN: "arn:cloudrift:workload-collection:::" + demoAcctCore + ":us-east-1:ecs", AssetType: "workload_collection_status",
			AccountID: demoAcctCore, Region: "us-east-1", Properties: map[string]any{"status": "partial", "collector": "ecs", "error": "access denied"},
		}}, nil, true
	case "eks-pod-id":
		role := secRole(scanID, demoAcctCore, "PodRole", nil)
		assoc, ref, rels := podIdentity(demoAcctCore, "demo", "app", "api", role.ARN, false)
		return []models.AssetNode{role, assoc, ref}, rels, true
	case "eks-sa-absent":
		role := secRole(scanID, demoAcctCore, "PodRole", nil)
		assoc, ref, rels := podIdentity(demoAcctCore, "demo", "missing-ns", "missing-sa", role.ARN, false)
		return []models.AssetNode{role, assoc, ref}, rels, true
	case "eks-missing-role":
		assoc, ref, rels := podIdentity(demoAcctCore, "demo", "app", "api", roleARN(demoAcctCore, "MissingPod"), true)
		return []models.AssetNode{assoc, ref}, rels, true
	case "irsa-trust", "irsa-exact", "irsa-no-k8s":
		assets, rels := irsaScenario(scanID, "system:serviceaccount:app:api", "StringEquals")
		return assets, rels, true
	case "irsa-wildcard":
		assets, rels := irsaScenario(scanID, "system:serviceaccount:app:*", "StringLike")
		return assets, rels, true
	case "share-ecs-lambda":
		assets, rels := sharedECSLambda(scanID)
		return assets, rels, true
	case "ct-deny":
		object := objectARN("ct-deny", "readme.txt")
		role := secRole(scanID, demoAcctCore, "CTDeny", nil)
		nodes, edges := collectors.BuildIdentityPolicyEvidence(role, []collectors.IdentityPolicyInput{inline("CTDeny", allowAndDeny(object))})
		bucket, obj := completeObject(scanID, demoAcctCore, "ct-deny", "readme.txt", nil)
		def := taskDef(demoAcctCore, "deny", "1", role.ARN, "")
		edges = append(edges, defRoleEdges(def, role.ARN, "")...)
		return append([]models.AssetNode{role, def, bucket, obj}, nodes...), edges, true
	case "ct-missing-scp":
		role := secRole(scanID, demoAcctCore, "CTMissing", map[string]any{
			"scp_status": "missing", "scp_evidence": "organizations collection denied",
			"session_policy_status": "missing", "session_policy_evidence": "no session document was collected",
		})
		def := taskDef(demoAcctCore, "missing-scp", "1", role.ARN, "")
		return []models.AssetNode{role, def}, defRoleEdges(def, role.ARN, ""), true
	case "ct-assume":
		caller := secRole(scanID, demoAcctCore, "CTAssumeCaller", nil)
		target := secRole(scanID, demoAcctCore, "CTAssumeTarget", map[string]any{"trust_policy_document": trustAllow(caller.ARN)})
		nodes, edges := collectors.BuildIdentityPolicyEvidence(caller, []collectors.IdentityPolicyInput{inline("CTAssumeCaller", allowAssume(target.ARN))})
		def := taskDef(demoAcctCore, "assume", "1", caller.ARN, "")
		edges = append(edges, defRoleEdges(def, caller.ARN, "")...)
		edges = append(edges, models.Relationship{SourceARN: target.ARN, TargetARN: caller.ARN, RelType: models.RelTrusts, Properties: map[string]any{"principal_type": "iam_role", "principal_value": caller.ARN}})
		return append([]models.AssetNode{caller, target, def}, nodes...), edges, true
	case "ct-shared-object":
		role := secRole(scanID, demoAcctCore, "CTBoth", nil)
		nodes, edges := collectors.BuildIdentityPolicyEvidence(role, []collectors.IdentityPolicyInput{inline("CTBoth", allowGet(objectARN("ct-both", "readme.txt")))})
		bucket, obj := completeObject(scanID, demoAcctCore, "ct-both", "readme.txt", nil)
		def := taskDef(demoAcctCore, "both", "1", role.ARN, "")
		fn := lambdaFunction(demoAcctCore, "both-fn", "us-east-1", role.ARN)
		edges = append(edges, defRoleEdges(def, role.ARN, "")...)
		edges = append(edges, models.Relationship{SourceARN: fn.ARN, TargetARN: role.ARN, RelType: models.RelLambdaUsesExecutionRole, Properties: map[string]any{"kind": "CONFIGURED_ROLE_ATTACHMENT", "mechanism": "lambda_execution_role", "relationship_id": "both-lambda"}})
		return append([]models.AssetNode{role, def, fn, bucket, obj}, nodes...), edges, true
	case "ct-hist-a":
		assets, rels := lambdaRole(scanID, "CTHistory", allowGet(objectARN("ct-history", "readme.txt")), "ct-history", false)
		return assets, rels, true
	case "ct-hist-b":
		assets, rels := lambdaRole(scanID, "CTHistory", allowStar(), "ct-history", true)
		return assets, rels, true
	case "inv-mixed":
		return mixedInventory(scanID)
	case "inv-pages":
		return inventoryPages(scanID)
	case "regions-coverage":
		return regionCoverageScenario()
	default:
		return nil, nil, false
	}
}

func mixedInventory(scanID string) ([]models.AssetNode, []models.Relationship, bool) {
	ec2Assets, ec2Rels := ec2Mapped(scanID, "inv-profile", "inv-profile", "InvEC2Role", false)
	lambdaRoleNode := secRole(scanID, demoAcctCore, "InvLambdaRole", nil)
	fn := lambdaFunction(demoAcctCore, "inv-fn", "us-west-2", lambdaRoleNode.ARN)
	bucket, object := completeObject(scanID, demoAcctCore, "inv-bucket", "readme.txt", nil)
	taskRole := secRole(scanID, demoAcctCore, "InvTaskRole", nil)
	execRole := secRole(scanID, demoAcctCore, "InvExecRole", nil)
	def := taskDef(demoAcctCore, "inv", "3", taskRole.ARN, execRole.ARN)
	task := ecsTask(demoAcctCore, "inv-task", def.ARN, "RUNNING")
	svc := ecsService(demoAcctCore, "inv-svc", def.ARN, 1)
	podRole := secRole(scanID, demoAcctCore, "InvPodRole", nil)
	assoc, ref, podRels := podIdentity(demoAcctCore, "inv", "app", "api", podRole.ARN, false)
	cluster := models.AssetNode{ARN: "arn:aws:eks:us-east-1:" + demoAcctCore + ":cluster/inv", AssetType: models.AssetEKSCluster, Name: "inv", AccountID: demoAcctCore, Region: "us-east-1", Properties: map[string]any{"kubernetes_api": "NOT_COLLECTED"}}
	dns := models.AssetNode{ARN: "arn:aws:route53:::hostedzone/ZINV/inv.example.com", AssetType: models.AssetDNSRecord, Name: "inv.example.com", AccountID: demoAcctCore, Properties: map[string]any{"type": "A"}}
	dist := models.AssetNode{ARN: "arn:aws:cloudfront::" + demoAcctCore + ":distribution/EINV", AssetType: models.AssetCloudFrontDist, Name: "EINV", AccountID: demoAcctCore, Properties: map[string]any{"status": "Deployed"}}
	partial := models.AssetNode{ARN: "arn:cloudrift:workload-collection:::" + demoAcctCore + ":eu-west-1:eks", AssetType: "workload_collection_status", AccountID: demoAcctCore, Region: "eu-west-1", Properties: map[string]any{"status": "partial", "collector": "eks", "error": "AccessDenied", "scope": "regional"}}
	statuses := []models.AssetNode{
		collectors.CollectionStatus(demoAcctCore, "us-east-1", "ec2", "regional", "succeeded", ""),
		collectors.CollectionStatus(demoAcctCore, "ap-southeast-2", "ec2", "regional", "failed", "AccessDenied"),
		collectors.CollectionStatus(demoAcctCore, "us-west-2", "lambda", "regional", "succeeded", ""),
		collectors.CollectionStatus(demoAcctCore, "us-east-1", "ecs", "regional", "succeeded", ""),
		collectors.CollectionStatus(demoAcctCore, "us-east-1", "eks", "regional", "succeeded", ""),
		collectors.CollectionStatus(demoAcctCore, "", "s3", "global", "succeeded", ""),
		collectors.CollectionStatus(demoAcctCore, "", "iam", "global", "succeeded", ""),
		collectors.CollectionStatus(demoAcctCore, "", "route53", "global", "succeeded", ""),
		collectors.CollectionStatus(demoAcctCore, "", "cloudfront", "global", "succeeded", ""),
		collectors.CollectionStatus(demoAcctCore, "", "acm", "global", "succeeded", ""),
	}
	assets := append(ec2Assets, lambdaRoleNode, fn, bucket, object, taskRole, execRole, def, task, svc, podRole, assoc, ref, cluster, dns, dist, partial)
	assets = append(assets, statuses...)
	rels := append(ec2Rels, models.Relationship{SourceARN: fn.ARN, TargetARN: lambdaRoleNode.ARN, RelType: models.RelLambdaUsesExecutionRole, Properties: map[string]any{"kind": "CONFIGURED_ROLE_ATTACHMENT", "mechanism": "lambda_execution_role", "relationship_id": "inv-lambda"}})
	rels = append(rels, defRoleEdges(def, taskRole.ARN, execRole.ARN)...)
	rels = append(rels, models.Relationship{SourceARN: task.ARN, TargetARN: def.ARN, RelType: models.RelECSTaskUsesTaskDef, Properties: map[string]any{"status": "OBSERVED_TASK_CONFIGURATION", "runtime_observed": "OBSERVED_RUNNING", "revision": "3"}})
	rels = append(rels, serviceEdge(svc, def))
	rels = append(rels, podRels...)
	irsaAssets, irsaRels := irsaScenario(scanID, "system:serviceaccount:app:api", "StringEquals")
	return append(assets, irsaAssets...), append(rels, irsaRels...), true
}

func inventoryPages(scanID string) ([]models.AssetNode, []models.Relationship, bool) {
	assets := []models.AssetNode{collectors.CollectionStatus(demoAcctCore, "", "s3", "global", "succeeded", "")}
	for i := 0; i < 30; i++ {
		name := fmt.Sprintf("page-bucket-%02d", i)
		bucket, _ := completeObject(scanID, demoAcctCore, name, "readme.txt", nil)
		assets = append(assets, bucket)
	}
	return assets, nil, true
}

func taskDef(account, family, revision, taskRole, execRole string) models.AssetNode {
	arn := "arn:aws:ecs:us-east-1:" + account + ":task-definition/" + family + ":" + revision
	return models.AssetNode{
		ARN: arn, AssetType: models.AssetECSTaskDefinition, Name: family + ":" + revision, AccountID: account, Region: "us-east-1",
		Properties: map[string]any{"revision": revision, "task_role_arn": taskRole, "execution_role_arn": execRole, "retrieval_status": "ok"},
	}
}

func defRoleEdges(def models.AssetNode, taskRole, execRole string) []models.Relationship {
	var rels []models.Relationship
	if taskRole != "" {
		rels = append(rels, models.Relationship{SourceARN: def.ARN, TargetARN: taskRole, RelType: models.RelECSTaskDefUsesTaskRole, Properties: map[string]any{
			"kind": "CONFIGURED_ROLE_ATTACHMENT", "mechanism": "ecs_task_role", "status": "TASK_DEFINITION_CONFIGURATION",
			"runtime_observed": "NOT_COLLECTED", "revision": def.Properties["revision"], "relationship_id": "task-" + def.Name,
			"note": "The task definition names the application task role.",
		}})
	}
	if execRole != "" {
		rels = append(rels, models.Relationship{SourceARN: def.ARN, TargetARN: execRole, RelType: models.RelECSTaskDefUsesExecutionRole, Properties: map[string]any{
			"kind": "CONFIGURED_ROLE_ATTACHMENT", "mechanism": "ecs_execution_role", "status": "TASK_DEFINITION_CONFIGURATION",
			"runtime_observed": "NOT_COLLECTED", "revision": def.Properties["revision"], "relationship_id": "exec-" + def.Name,
			"note": "The execution role is ECS infrastructure, not the application task identity.",
		}})
	}
	return rels
}

func ecsTask(account, id, defARN, status string) models.AssetNode {
	arn := "arn:aws:ecs:us-east-1:" + account + ":task/demo/" + id
	return models.AssetNode{ARN: arn, AssetType: models.AssetECSTask, Name: id, AccountID: account, Region: "us-east-1", Properties: map[string]any{"task_definition_arn": defARN, "last_status": status}}
}

func ecsService(account, name, defARN string, running int) models.AssetNode {
	arn := "arn:aws:ecs:us-east-1:" + account + ":service/demo/" + name
	return models.AssetNode{ARN: arn, AssetType: models.AssetECSService, Name: name, AccountID: account, Region: "us-east-1", Properties: map[string]any{"running_count": running, "task_definition_arn": defARN}}
}

func serviceEdge(svc, def models.AssetNode) models.Relationship {
	runtime := "NOT_COLLECTED"
	return models.Relationship{SourceARN: svc.ARN, TargetARN: def.ARN, RelType: models.RelECSServiceRefsTaskDef, Properties: map[string]any{
		"kind": "CONFIGURED_ROLE_ATTACHMENT", "mechanism": "ecs_service", "status": "SERVICE_CONFIGURATION",
		"runtime_observed": runtime, "relationship_id": "svc-" + svc.Name,
		"note": "The service references this task definition. No running task was collected.",
	}}
}

func podIdentity(account, cluster, namespace, sa, roleARN string, unresolved bool) (models.AssetNode, models.AssetNode, []models.Relationship) {
	assocARN := "arn:aws:eks:us-east-1:" + account + ":podidentityassociation/" + cluster + "/" + namespace + "/" + sa
	refARN := "arn:cloudrift:eks-service-account:us-east-1:" + account + ":" + cluster + ":" + namespace + ":" + sa
	assoc := models.AssetNode{ARN: assocARN, AssetType: models.AssetEKSPodIdentity, Name: namespace + "/" + sa, AccountID: account, Region: "us-east-1", Properties: map[string]any{
		"namespace": namespace, "service_account": sa, "kubernetes_attachment": "NOT_COLLECTED", "kubernetes_service_account": "not_collected", "role_arn": roleARN,
	}}
	ref := models.AssetNode{ARN: refARN, AssetType: models.AssetEKSServiceAccountRef, Name: sa, AccountID: account, Region: "us-east-1", Properties: map[string]any{
		"namespace": namespace, "kubernetes_object": "not_collected",
	}}
	kind := "CONFIGURED_ROLE_ATTACHMENT"
	if unresolved {
		kind = "UNRESOLVED_ROLE"
	}
	rels := []models.Relationship{
		{SourceARN: assocARN, TargetARN: refARN, RelType: models.RelEKSPodIdentityRefsSA, Properties: map[string]any{"kind": "CONFIGURED_ROLE_ATTACHMENT", "mechanism": "eks_pod_identity", "status": "CONFIGURED", "runtime_observed": "NOT_COLLECTED", "namespace": namespace, "service_account": sa}},
		{SourceARN: assocARN, TargetARN: roleARN, RelType: models.RelEKSPodIdentityUsesRole, Properties: map[string]any{"kind": kind, "mechanism": "eks_pod_identity", "status": "CONFIGURED", "runtime_observed": "NOT_COLLECTED", "namespace": namespace, "service_account": sa, "role_arn": roleARN, "note": "Pod Identity configuration. A running Pod was not observed."}},
	}
	return assoc, ref, rels
}

func irsaScenario(scanID, subject, op string) ([]models.AssetNode, []models.Relationship) {
	issuer := "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"
	cluster := models.AssetNode{ARN: "arn:aws:eks:us-east-1:" + demoAcctCore + ":cluster/demo", AssetType: models.AssetEKSCluster, Name: "demo", AccountID: demoAcctCore, Region: "us-east-1", Properties: map[string]any{"oidc_issuer": issuer, "kubernetes_api": "NOT_COLLECTED"}}
	doc := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::` + demoAcctCore + `:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"` + op + `":{"oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:sub":"` + subject + `"}}}}`
	role := secRole(scanID, demoAcctCore, "IRSARole", map[string]any{"trust_policy_document": doc})
	extra, rels := collectors.DeriveIRSATrusts([]models.AssetNode{cluster, role})
	return append([]models.AssetNode{role, cluster}, extra...), rels
}

func sharedECSLambda(scanID string) ([]models.AssetNode, []models.Relationship) {
	role := secRole(scanID, demoAcctCore, "SharedContainer", nil)
	nodes, edges := collectors.BuildIdentityPolicyEvidence(role, []collectors.IdentityPolicyInput{inline("SharedContainer", allowGet(objectARN("shared-container", "readme.txt")))})
	bucket, obj := completeObject(scanID, demoAcctCore, "shared-container", "readme.txt", nil)
	def := taskDef(demoAcctCore, "shared", "1", role.ARN, "")
	fn := lambdaFunction(demoAcctCore, "shared-fn", "us-east-1", role.ARN)
	edges = append(edges, defRoleEdges(def, role.ARN, "")...)
	edges = append(edges, models.Relationship{SourceARN: fn.ARN, TargetARN: role.ARN, RelType: models.RelLambdaUsesExecutionRole, Properties: map[string]any{"kind": "CONFIGURED_ROLE_ATTACHMENT", "mechanism": "lambda_execution_role", "relationship_id": "shared-lambda"}})
	return append([]models.AssetNode{role, def, fn, bucket, obj}, nodes...), edges
}

func regionCoverageScenario() ([]models.AssetNode, []models.Relationship, bool) {
	core := collectors.CollectionStatus(demoAcctCore, "", "region_discovery", "account", "succeeded", "auto")
	core.Properties["partition"] = "aws"
	core.Properties["region_mode"] = "auto"
	core.Properties["selected_regions"] = "us-east-1,us-west-2"
	core.Properties["not_enabled"] = "af-south-1"
	core.Properties["evidence_origin"] = "ec2:DescribeRegions"
	var assets []models.AssetNode
	assets = append(assets, core)
	for _, region := range []string{"us-east-1", "us-west-2"} {
		for _, svc := range []string{"ec2", "lambda", "ecs", "eks"} {
			status := "succeeded"
			if region == "us-west-2" && svc == "lambda" {
				status = "failed"
			}
			assets = append(assets, collectors.CollectionStatus(demoAcctCore, region, svc, "regional", status, ""))
		}
	}
	failed := collectors.CollectionStatus(demoAcctData, "", "region_discovery", "account", "failed", "access_denied")
	failed.Properties["partition"] = "aws"
	failed.Properties["region_mode"] = "auto"
	failed.Properties["error_category"] = "access_denied"
	failed.Properties["evidence_origin"] = "ec2:DescribeRegions"
	assets = append(assets, failed)
	return assets, nil, true
}
