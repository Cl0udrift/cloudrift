package collectors

import (
	"context"
	"strings"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// ECSAPI and EKSAPI are the read-only calls used to map container workload identities.
type ECSAPI interface {
	ListClusters(context.Context, *ecs.ListClustersInput, ...func(*ecs.Options)) (*ecs.ListClustersOutput, error)
	ListServices(context.Context, *ecs.ListServicesInput, ...func(*ecs.Options)) (*ecs.ListServicesOutput, error)
	DescribeServices(context.Context, *ecs.DescribeServicesInput, ...func(*ecs.Options)) (*ecs.DescribeServicesOutput, error)
	ListTasks(context.Context, *ecs.ListTasksInput, ...func(*ecs.Options)) (*ecs.ListTasksOutput, error)
	DescribeTasks(context.Context, *ecs.DescribeTasksInput, ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error)
	DescribeTaskDefinition(context.Context, *ecs.DescribeTaskDefinitionInput, ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error)
}

type EKSAPI interface {
	ListClusters(context.Context, *eks.ListClustersInput, ...func(*eks.Options)) (*eks.ListClustersOutput, error)
	DescribeCluster(context.Context, *eks.DescribeClusterInput, ...func(*eks.Options)) (*eks.DescribeClusterOutput, error)
	ListPodIdentityAssociations(context.Context, *eks.ListPodIdentityAssociationsInput, ...func(*eks.Options)) (*eks.ListPodIdentityAssociationsOutput, error)
	DescribePodIdentityAssociation(context.Context, *eks.DescribePodIdentityAssociationInput, ...func(*eks.Options)) (*eks.DescribePodIdentityAssociationOutput, error)
}

func collectContainers(ctx context.Context, accountID, region string, ecsAPI ECSAPI, eksAPI EKSAPI, collectedAt time.Time) ([]models.AssetNode, []models.Relationship, error) {
	var assets []models.AssetNode
	var rels []models.Relationship
	if ecsAPI != nil {
		nodes, edges, err := collectECS(ctx, accountID, region, ecsAPI, collectedAt)
		if err != nil {
			assets = append(assets, partialContainer(accountID, region, "ecs", err))
		} else {
			assets = append(assets, nodes...)
			assets = append(assets, CollectionStatus(accountID, region, "ecs", "regional", "succeeded", ""))
			rels = append(rels, edges...)
		}
	}
	if eksAPI != nil {
		nodes, edges, err := collectEKS(ctx, accountID, region, eksAPI, collectedAt)
		if err != nil {
			assets = append(assets, partialContainer(accountID, region, "eks", err))
		} else {
			assets = append(assets, nodes...)
			assets = append(assets, CollectionStatus(accountID, region, "eks", "regional", "succeeded", ""))
			rels = append(rels, edges...)
		}
	}
	return assets, rels, nil
}

func partialContainer(accountID, region, collector string, err error) models.AssetNode {
	return models.AssetNode{
		ARN:       "arn:cloudrift:workload-collection:::" + accountID + ":" + region + ":" + collector,
		AssetType: "workload_collection_status", AccountID: accountID, Region: region,
		Properties: map[string]any{"status": "partial", "collector": collector, "error": err.Error()},
	}
}

func collectECS(ctx context.Context, accountID, region string, api ECSAPI, collectedAt time.Time) ([]models.AssetNode, []models.Relationship, error) {
	clusters, err := listAll(func(token *string) ([]string, *string, error) {
		out, err := api.ListClusters(ctx, &ecs.ListClustersInput{NextToken: token})
		if err != nil {
			return nil, nil, err
		}
		return out.ClusterArns, out.NextToken, nil
	})
	if err != nil {
		return nil, nil, err
	}
	var assets []models.AssetNode
	var rels []models.Relationship
	defs := map[string]struct{}{}
	type taskRef struct{ taskARN, defARN, cluster, status string }
	var tasks []taskRef
	type serviceRef struct {
		serviceARN, cluster string
		defs                []string
		running             int32
	}
	var services []serviceRef
	for _, cluster := range clusters {
		assets = append(assets, models.AssetNode{
			ARN: cluster, AssetType: models.AssetECSCluster, Name: arnName(cluster), AccountID: accountID, Region: region,
			Properties: map[string]any{"source_api": "ecs:ListClusters", "collected_at": collectedAt.Format(time.RFC3339)},
		})
		serviceARNs, err := listAll(func(token *string) ([]string, *string, error) {
			out, err := api.ListServices(ctx, &ecs.ListServicesInput{Cluster: &cluster, NextToken: token})
			if err != nil {
				return nil, nil, err
			}
			return out.ServiceArns, out.NextToken, nil
		})
		if err != nil {
			assets = append(assets, partialContainer(accountID, region, "ecs-services:"+arnName(cluster), err))
			continue
		}
		for _, batch := range chunks(serviceARNs, 10) {
			out, err := api.DescribeServices(ctx, &ecs.DescribeServicesInput{Cluster: &cluster, Services: batch})
			if err != nil {
				assets = append(assets, partialContainer(accountID, region, "ecs-describe-services", err))
				continue
			}
			for _, svc := range out.Services {
				ref := serviceRef{serviceARN: awsv2.ToString(svc.ServiceArn), cluster: cluster, running: svc.RunningCount}
				seen := map[string]struct{}{}
				addDef := func(arn string) {
					if arn == "" {
						return
					}
					if _, ok := seen[arn]; ok {
						return
					}
					seen[arn] = struct{}{}
					ref.defs = append(ref.defs, arn)
					defs[arn] = struct{}{}
				}
				addDef(awsv2.ToString(svc.TaskDefinition))
				for _, dep := range svc.Deployments {
					addDef(awsv2.ToString(dep.TaskDefinition))
				}
				services = append(services, ref)
				assets = append(assets, models.AssetNode{
					ARN: ref.serviceARN, AssetType: models.AssetECSService, Name: awsv2.ToString(svc.ServiceName),
					AccountID: accountID, Region: region,
					Properties: map[string]any{
						"cluster_arn": cluster, "running_count": svc.RunningCount, "desired_count": svc.DesiredCount,
						"service_status": awsv2.ToString(svc.Status), "source_api": "ecs:DescribeServices",
						"collected_at": collectedAt.Format(time.RFC3339),
					},
				})
			}
		}
		taskARNs, err := listAll(func(token *string) ([]string, *string, error) {
			out, err := api.ListTasks(ctx, &ecs.ListTasksInput{Cluster: &cluster, NextToken: token})
			if err != nil {
				return nil, nil, err
			}
			return out.TaskArns, out.NextToken, nil
		})
		if err != nil {
			assets = append(assets, partialContainer(accountID, region, "ecs-tasks:"+arnName(cluster), err))
			continue
		}
		for _, batch := range chunks(taskARNs, 100) {
			out, err := api.DescribeTasks(ctx, &ecs.DescribeTasksInput{Cluster: &cluster, Tasks: batch})
			if err != nil {
				assets = append(assets, partialContainer(accountID, region, "ecs-describe-tasks", err))
				continue
			}
			for _, task := range out.Tasks {
				defARN := awsv2.ToString(task.TaskDefinitionArn)
				status := awsv2.ToString(task.LastStatus)
				tasks = append(tasks, taskRef{taskARN: awsv2.ToString(task.TaskArn), defARN: defARN, cluster: cluster, status: status})
				if defARN != "" {
					defs[defARN] = struct{}{}
				}
				assets = append(assets, models.AssetNode{
					ARN: awsv2.ToString(task.TaskArn), AssetType: models.AssetECSTask, Name: arnName(awsv2.ToString(task.TaskArn)),
					AccountID: accountID, Region: region,
					Properties: map[string]any{
						"cluster_arn": cluster, "task_definition_arn": defARN, "last_status": status,
						"revision": revisionOf(defARN), "source_api": "ecs:DescribeTasks",
						"collected_at": collectedAt.Format(time.RFC3339),
					},
				})
			}
		}
	}
	defNodes, defRels := describeTaskDefinitions(ctx, accountID, region, api, defs, collectedAt)
	assets = append(assets, defNodes...)
	rels = append(rels, defRels...)
	for _, task := range tasks {
		if task.defARN == "" {
			continue
		}
		runtime := "NOT_COLLECTED"
		if strings.EqualFold(task.status, "RUNNING") {
			runtime = "OBSERVED_RUNNING"
		}
		rels = append(rels, models.Relationship{
			SourceARN: task.taskARN, TargetARN: task.defARN, RelType: models.RelECSTaskUsesTaskDef,
			Properties: attachmentProps(task.taskARN, string(models.RelECSTaskUsesTaskDef), task.defARN, "CONFIGURED_ROLE_ATTACHMENT", "ecs_task_definition", "ecs:DescribeTasks", collectedAt,
				"The task reports task definition revision "+revisionOf(task.defARN)+". A newer revision is not substituted."),
		})
		rels[len(rels)-1].Properties["status"] = "OBSERVED_TASK_CONFIGURATION"
		rels[len(rels)-1].Properties["runtime_observed"] = runtime
		rels[len(rels)-1].Properties["cluster"] = task.cluster
		rels[len(rels)-1].Properties["revision"] = revisionOf(task.defARN)
	}
	for _, svc := range services {
		for _, defARN := range svc.defs {
			runtime := "NOT_COLLECTED"
			if svc.running > 0 {
				runtime = "OBSERVED_RUNNING"
			}
			props := attachmentProps(svc.serviceARN, string(models.RelECSServiceRefsTaskDef), defARN, "CONFIGURED_ROLE_ATTACHMENT", "ecs_service", "ecs:DescribeServices", collectedAt,
				"The service references this task definition revision. A reference does not prove a task is running.")
			props["status"] = "SERVICE_CONFIGURATION"
			props["runtime_observed"] = runtime
			props["cluster"] = svc.cluster
			props["revision"] = revisionOf(defARN)
			rels = append(rels, models.Relationship{SourceARN: svc.serviceARN, TargetARN: defARN, RelType: models.RelECSServiceRefsTaskDef, Properties: props})
		}
	}
	return assets, rels, nil
}

func describeTaskDefinitions(ctx context.Context, accountID, region string, api ECSAPI, defs map[string]struct{}, collectedAt time.Time) ([]models.AssetNode, []models.Relationship) {
	var assets []models.AssetNode
	var rels []models.Relationship
	for defARN := range defs {
		out, err := api.DescribeTaskDefinition(ctx, &ecs.DescribeTaskDefinitionInput{TaskDefinition: &defARN})
		node := models.AssetNode{
			ARN: defARN, AssetType: models.AssetECSTaskDefinition, Name: arnName(defARN), AccountID: accountID, Region: region,
			Properties: map[string]any{
				"revision": revisionOf(defARN), "source_api": "ecs:DescribeTaskDefinition",
				"collected_at": collectedAt.Format(time.RFC3339),
			},
		}
		if err != nil || out.TaskDefinition == nil {
			node.Properties["retrieval_status"] = "denied"
			assets = append(assets, node)
			continue
		}
		td := out.TaskDefinition
		node.Properties["retrieval_status"] = "ok"
		node.Properties["family"] = awsv2.ToString(td.Family)
		if td.Revision != 0 {
			node.Properties["revision"] = td.Revision
		}
		taskRole := awsv2.ToString(td.TaskRoleArn)
		execRole := awsv2.ToString(td.ExecutionRoleArn)
		node.Properties["task_role_arn"] = taskRole
		node.Properties["execution_role_arn"] = execRole
		assets = append(assets, node)
		if taskRole != "" {
			props := attachmentProps(defARN, string(models.RelECSTaskDefUsesTaskRole), taskRole, "CONFIGURED_ROLE_ATTACHMENT", "ecs_task_role", "ecs:DescribeTaskDefinition", collectedAt,
				"The task definition names the application task role. This revision is not proof a task is running.")
			props["status"] = "TASK_DEFINITION_CONFIGURATION"
			props["runtime_observed"] = "NOT_COLLECTED"
			props["revision"] = revisionOf(defARN)
			rels = append(rels, models.Relationship{SourceARN: defARN, TargetARN: taskRole, RelType: models.RelECSTaskDefUsesTaskRole, Properties: props})
		}
		if execRole != "" {
			props := attachmentProps(defARN, string(models.RelECSTaskDefUsesExecutionRole), execRole, "CONFIGURED_ROLE_ATTACHMENT", "ecs_execution_role", "ecs:DescribeTaskDefinition", collectedAt,
				"The task definition names the ECS execution role. These permissions are not attributed to application containers.")
			props["status"] = "TASK_DEFINITION_CONFIGURATION"
			props["runtime_observed"] = "NOT_COLLECTED"
			props["revision"] = revisionOf(defARN)
			rels = append(rels, models.Relationship{SourceARN: defARN, TargetARN: execRole, RelType: models.RelECSTaskDefUsesExecutionRole, Properties: props})
		}
	}
	return assets, rels
}

func collectEKS(ctx context.Context, accountID, region string, api EKSAPI, collectedAt time.Time) ([]models.AssetNode, []models.Relationship, error) {
	names, err := listAll(func(token *string) ([]string, *string, error) {
		out, err := api.ListClusters(ctx, &eks.ListClustersInput{NextToken: token})
		if err != nil {
			return nil, nil, err
		}
		return out.Clusters, out.NextToken, nil
	})
	if err != nil {
		return nil, nil, err
	}
	var assets []models.AssetNode
	var rels []models.Relationship
	for _, name := range names {
		desc, err := api.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: &name})
		if err != nil || desc.Cluster == nil {
			assets = append(assets, partialContainer(accountID, region, "eks-cluster:"+name, errOrMissing(err)))
			continue
		}
		cluster := desc.Cluster
		issuer := ""
		if cluster.Identity != nil && cluster.Identity.Oidc != nil {
			issuer = awsv2.ToString(cluster.Identity.Oidc.Issuer)
		}
		clusterARN := awsv2.ToString(cluster.Arn)
		assets = append(assets, models.AssetNode{
			ARN: clusterARN, AssetType: models.AssetEKSCluster, Name: name, AccountID: accountID, Region: region,
			Properties: map[string]any{
				"oidc_issuer": issuer, "source_api": "eks:DescribeCluster",
				"collected_at": collectedAt.Format(time.RFC3339), "kubernetes_api": "NOT_COLLECTED",
			},
		})
		summaries, err := listPodAssociations(ctx, api, name)
		if err != nil {
			assets = append(assets, partialContainer(accountID, region, "eks-pod-identity:"+name, err))
			continue
		}
		for _, summary := range summaries {
			assoc, edges := describePodAssociation(ctx, accountID, region, clusterARN, name, api, summary, collectedAt)
			assets = append(assets, assoc...)
			rels = append(rels, edges...)
		}
	}
	return assets, rels, nil
}

func listPodAssociations(ctx context.Context, api EKSAPI, cluster string) ([]ekstypes.PodIdentityAssociationSummary, error) {
	var out []ekstypes.PodIdentityAssociationSummary
	var token *string
	for {
		page, err := api.ListPodIdentityAssociations(ctx, &eks.ListPodIdentityAssociationsInput{ClusterName: &cluster, NextToken: token})
		if err != nil {
			return nil, err
		}
		out = append(out, page.Associations...)
		if page.NextToken == nil || *page.NextToken == "" {
			return out, nil
		}
		token = page.NextToken
	}
}

func describePodAssociation(ctx context.Context, accountID, region, clusterARN, clusterName string, api EKSAPI, summary ekstypes.PodIdentityAssociationSummary, collectedAt time.Time) ([]models.AssetNode, []models.Relationship) {
	ns := awsv2.ToString(summary.Namespace)
	sa := awsv2.ToString(summary.ServiceAccount)
	assocARN := awsv2.ToString(summary.AssociationArn)
	if assocARN == "" {
		assocARN = "arn:aws:eks:" + region + ":" + accountID + ":podidentityassociation/" + clusterName + "/" + awsv2.ToString(summary.AssociationId)
	}
	saARN := "arn:cloudrift:eks-service-account:" + region + ":" + accountID + ":" + clusterName + ":" + ns + ":" + sa
	assoc := models.AssetNode{
		ARN: assocARN, AssetType: models.AssetEKSPodIdentity, Name: ns + "/" + sa, AccountID: accountID, Region: region,
		Properties: map[string]any{
			"cluster_arn": clusterARN, "namespace": ns, "service_account": sa,
			"association_id":        awsv2.ToString(summary.AssociationId),
			"kubernetes_attachment": "NOT_COLLECTED", "kubernetes_service_account": "not_collected",
			"source_api": "eks:ListPodIdentityAssociations", "collected_at": collectedAt.Format(time.RFC3339),
		},
	}
	ref := models.AssetNode{
		ARN: saARN, AssetType: models.AssetEKSServiceAccountRef, Name: sa, AccountID: accountID, Region: region,
		Properties: map[string]any{
			"cluster_arn": clusterARN, "namespace": ns, "service_account": sa,
			"kubernetes_object": "not_collected", "note": "Named by an EKS Pod Identity association. This is not a collected Kubernetes service account or Pod.",
		},
	}
	refProps := attachmentProps(assocARN, string(models.RelEKSPodIdentityRefsSA), saARN, "CONFIGURED_ROLE_ATTACHMENT", "eks_pod_identity", "eks:ListPodIdentityAssociations", collectedAt,
		"The association names this namespace and service account. No Pod was invented, and Kubernetes attachment was not collected.")
	refProps["status"] = "CONFIGURED"
	refProps["runtime_observed"] = "NOT_COLLECTED"
	refProps["cluster"] = clusterARN
	refProps["namespace"] = ns
	refProps["service_account"] = sa
	rels := []models.Relationship{{SourceARN: assocARN, TargetARN: saARN, RelType: models.RelEKSPodIdentityRefsSA, Properties: refProps}}
	desc, err := api.DescribePodIdentityAssociation(ctx, &eks.DescribePodIdentityAssociationInput{ClusterName: &clusterName, AssociationId: summary.AssociationId})
	if err != nil || desc.Association == nil || awsv2.ToString(desc.Association.RoleArn) == "" {
		assoc.Properties["retrieval_status"] = "denied"
		return []models.AssetNode{assoc, ref}, rels
	}
	roleARN := awsv2.ToString(desc.Association.RoleArn)
	assoc.Properties["role_arn"] = roleARN
	assoc.Properties["retrieval_status"] = "ok"
	assoc.Properties["source_api"] = "eks:DescribePodIdentityAssociation"
	roleProps := attachmentProps(assocARN, string(models.RelEKSPodIdentityUsesRole), roleARN, "CONFIGURED_ROLE_ATTACHMENT", "eks_pod_identity", "eks:DescribePodIdentityAssociation", collectedAt,
		"Pod Identity configuration names this role. A running Pod using the service account was not observed.")
	roleProps["status"] = "CONFIGURED"
	roleProps["runtime_observed"] = "NOT_COLLECTED"
	roleProps["cluster"] = clusterARN
	roleProps["namespace"] = ns
	roleProps["service_account"] = sa
	rels = append(rels, models.Relationship{SourceARN: assocARN, TargetARN: roleARN, RelType: models.RelEKSPodIdentityUsesRole, Properties: roleProps})
	return []models.AssetNode{assoc, ref}, rels
}

func listAll(page func(*string) ([]string, *string, error)) ([]string, error) {
	var out []string
	var token *string
	for {
		items, next, err := page(token)
		if err != nil {
			return nil, err
		}
		out = append(out, items...)
		if next == nil || *next == "" {
			return out, nil
		}
		token = next
	}
}

func chunks(values []string, size int) [][]string {
	if len(values) == 0 {
		return nil
	}
	var out [][]string
	for len(values) > 0 {
		n := size
		if n > len(values) {
			n = len(values)
		}
		out = append(out, values[:n])
		values = values[n:]
	}
	return out
}

func arnName(arn string) string {
	if i := strings.LastIndex(arn, "/"); i >= 0 && i < len(arn)-1 {
		return arn[i+1:]
	}
	return arn
}

func revisionOf(defARN string) string {
	name := arnName(defARN)
	if i := strings.LastIndex(name, ":"); i >= 0 {
		return name[i+1:]
	}
	return ""
}

func errOrMissing(err error) error {
	if err != nil {
		return err
	}
	return errMissingCluster
}

type missingClusterError struct{}

func (missingClusterError) Error() string { return "eks:DescribeCluster returned no cluster" }

var errMissingCluster = missingClusterError{}
