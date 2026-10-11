package collectors

import (
	"context"
	"errors"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"

	"github.com/Zero0x00/cloudrift/internal/models"
)

type fakeECS struct {
	clusters []string
	services []ecstypes.Service
	tasks    []ecstypes.Task
	defs     map[string]ecstypes.TaskDefinition
	failList bool
}

func (f fakeECS) ListClusters(_ context.Context, in *ecs.ListClustersInput, _ ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
	if f.failList {
		return nil, errors.New("access denied")
	}
	if in.NextToken == nil && len(f.clusters) > 1 {
		return &ecs.ListClustersOutput{ClusterArns: f.clusters[:1], NextToken: awsv2.String("next")}, nil
	}
	rest := f.clusters
	if in.NextToken != nil {
		rest = f.clusters[1:]
	}
	return &ecs.ListClustersOutput{ClusterArns: rest}, nil
}

func (f fakeECS) ListServices(context.Context, *ecs.ListServicesInput, ...func(*ecs.Options)) (*ecs.ListServicesOutput, error) {
	var arns []string
	for _, svc := range f.services {
		arns = append(arns, awsv2.ToString(svc.ServiceArn))
	}
	return &ecs.ListServicesOutput{ServiceArns: arns}, nil
}

func (f fakeECS) DescribeServices(_ context.Context, in *ecs.DescribeServicesInput, _ ...func(*ecs.Options)) (*ecs.DescribeServicesOutput, error) {
	return &ecs.DescribeServicesOutput{Services: f.services}, nil
}

func (f fakeECS) ListTasks(context.Context, *ecs.ListTasksInput, ...func(*ecs.Options)) (*ecs.ListTasksOutput, error) {
	var arns []string
	for _, task := range f.tasks {
		arns = append(arns, awsv2.ToString(task.TaskArn))
	}
	return &ecs.ListTasksOutput{TaskArns: arns}, nil
}

func (f fakeECS) DescribeTasks(context.Context, *ecs.DescribeTasksInput, ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
	return &ecs.DescribeTasksOutput{Tasks: f.tasks}, nil
}

func (f fakeECS) DescribeTaskDefinition(_ context.Context, in *ecs.DescribeTaskDefinitionInput, _ ...func(*ecs.Options)) (*ecs.DescribeTaskDefinitionOutput, error) {
	def, ok := f.defs[awsv2.ToString(in.TaskDefinition)]
	if !ok {
		return nil, errors.New("access denied")
	}
	return &ecs.DescribeTaskDefinitionOutput{TaskDefinition: &def}, nil
}

type fakeEKS struct {
	names []string
	assoc ekstypes.PodIdentityAssociation
	fail  bool
}

func (f fakeEKS) ListClusters(_ context.Context, in *eks.ListClustersInput, _ ...func(*eks.Options)) (*eks.ListClustersOutput, error) {
	if f.fail {
		return nil, errors.New("access denied")
	}
	if in.NextToken == nil && len(f.names) > 1 {
		return &eks.ListClustersOutput{Clusters: f.names[:1], NextToken: awsv2.String("next")}, nil
	}
	rest := f.names
	if in.NextToken != nil {
		rest = f.names[1:]
	}
	return &eks.ListClustersOutput{Clusters: rest}, nil
}

func (f fakeEKS) DescribeCluster(context.Context, *eks.DescribeClusterInput, ...func(*eks.Options)) (*eks.DescribeClusterOutput, error) {
	return &eks.DescribeClusterOutput{Cluster: &ekstypes.Cluster{
		Name: awsv2.String("demo"), Arn: awsv2.String("arn:aws:eks:us-east-1:111111111111:cluster/demo"),
		Identity: &ekstypes.Identity{Oidc: &ekstypes.OIDC{Issuer: awsv2.String("https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE")}},
	}}, nil
}

func (f fakeEKS) ListPodIdentityAssociations(_ context.Context, in *eks.ListPodIdentityAssociationsInput, _ ...func(*eks.Options)) (*eks.ListPodIdentityAssociationsOutput, error) {
	if in.NextToken == nil {
		return &eks.ListPodIdentityAssociationsOutput{
			Associations: []ekstypes.PodIdentityAssociationSummary{{
				AssociationArn: awsv2.String("arn:aws:eks:us-east-1:111111111111:podidentityassociation/demo/a-1"),
				AssociationId:  awsv2.String("a-1"), Namespace: awsv2.String("app"), ServiceAccount: awsv2.String("api"),
			}},
			NextToken: awsv2.String("next"),
		}, nil
	}
	return &eks.ListPodIdentityAssociationsOutput{}, nil
}

func (f fakeEKS) DescribePodIdentityAssociation(context.Context, *eks.DescribePodIdentityAssociationInput, ...func(*eks.Options)) (*eks.DescribePodIdentityAssociationOutput, error) {
	return &eks.DescribePodIdentityAssociationOutput{Association: &f.assoc}, nil
}

func TestCollectContainers_TaskRevisionAndPodIdentity(t *testing.T) {
	rev3 := "arn:aws:ecs:us-east-1:111111111111:task-definition/app:3"
	rev4 := "arn:aws:ecs:us-east-1:111111111111:task-definition/app:4"
	assets, rels, err := collectContainers(context.Background(), "111111111111", "us-east-1", fakeECS{
		clusters: []string{"arn:aws:ecs:us-east-1:111111111111:cluster/a", "arn:aws:ecs:us-east-1:111111111111:cluster/b"},
		services: []ecstypes.Service{{
			ServiceArn: awsv2.String("arn:aws:ecs:us-east-1:111111111111:service/a/web"), ServiceName: awsv2.String("web"),
			TaskDefinition: &rev4, RunningCount: 0,
		}},
		tasks: []ecstypes.Task{{
			TaskArn: awsv2.String("arn:aws:ecs:us-east-1:111111111111:task/a/task-1"), TaskDefinitionArn: &rev3, LastStatus: awsv2.String("RUNNING"),
		}},
		defs: map[string]ecstypes.TaskDefinition{
			rev3: {Family: awsv2.String("app"), Revision: 3, TaskRoleArn: awsv2.String("arn:aws:iam::111111111111:role/Task"), ExecutionRoleArn: awsv2.String("arn:aws:iam::111111111111:role/Exec")},
			rev4: {Family: awsv2.String("app"), Revision: 4, TaskRoleArn: awsv2.String("arn:aws:iam::111111111111:role/Newer")},
		},
	}, fakeEKS{names: []string{"demo", "other"}, assoc: ekstypes.PodIdentityAssociation{RoleArn: awsv2.String("arn:aws:iam::111111111111:role/Pod")}}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var taskDef string
	var sawPod bool
	for _, rel := range rels {
		if rel.RelType == models.RelECSTaskUsesTaskDef {
			taskDef = rel.TargetARN
		}
		if rel.RelType == models.RelEKSPodIdentityUsesRole && rel.TargetARN != "arn:aws:iam::111111111111:role/Pod" {
			t.Fatal(rel.TargetARN)
		}
		if rel.RelType == models.RelEKSPodIdentityUsesRole {
			sawPod = true
		}
	}
	if taskDef != rev3 {
		t.Fatalf("running task was attributed to %s", taskDef)
	}
	if !sawPod {
		t.Fatal("pod identity role was not recorded")
	}
	for _, asset := range assets {
		if asset.AssetType == "eks_pod" {
			t.Fatal("a pod was invented")
		}
	}
}

func TestCollectContainers_PartialFailure(t *testing.T) {
	assets, rels, err := collectContainers(context.Background(), "111111111111", "us-west-2", fakeECS{failList: true}, fakeEKS{fail: true}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(rels) != 0 || len(assets) != 2 {
		t.Fatalf("assets=%d rels=%d", len(assets), len(rels))
	}
}

func TestDeriveIRSATrusts_DoesNotInventPods(t *testing.T) {
	issuer := "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"
	cluster := models.AssetNode{ARN: "arn:aws:eks:us-east-1:111111111111:cluster/demo", AssetType: models.AssetEKSCluster, Name: "demo", Region: "us-east-1", Properties: map[string]any{"oidc_issuer": issuer}}
	role := models.AssetNode{ARN: "arn:aws:iam::111111111111:role/IRSA", AssetType: models.AssetIAMRole, AccountID: "111111111111", Properties: map[string]any{"trust_policy_document": `{
		"Statement":{"Effect":"Allow","Principal":{"Federated":"arn:aws:iam::111111111111:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"},
		"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE:sub":"system:serviceaccount:app:api"}}}}`}}
	assets, rels := DeriveIRSATrusts([]models.AssetNode{cluster, role})
	if len(rels) != 1 || rels[0].RelType != models.RelIRSATrustConfiguration || rels[0].Properties["status"] != "TRUST_ONLY" {
		t.Fatal(rels)
	}
	if assets[0].Properties["kubernetes_attachment"] != "NOT_COLLECTED" {
		t.Fatal(assets[0].Properties)
	}
}
