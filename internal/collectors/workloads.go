package collectors

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// EC2API and the companion interfaces are the read-only calls used to map
// instance profiles and Lambda execution roles. Tests supply fakes.
type EC2API interface {
	DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	DescribeIamInstanceProfileAssociations(context.Context, *ec2.DescribeIamInstanceProfileAssociationsInput, ...func(*ec2.Options)) (*ec2.DescribeIamInstanceProfileAssociationsOutput, error)
}

type InstanceProfileAPI interface {
	GetInstanceProfile(context.Context, *iam.GetInstanceProfileInput, ...func(*iam.Options)) (*iam.GetInstanceProfileOutput, error)
}

type LambdaAPI interface {
	ListFunctions(context.Context, *lambda.ListFunctionsInput, ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error)
}

// WorkloadClients builds regional clients for one account. Nil sessions are skipped.
type WorkloadClients struct {
	EC2    EC2API
	IAM    InstanceProfileAPI
	Lambda LambdaAPI
	ECS    ECSAPI
	EKS    EKSAPI
}

// OrganizationAccountNodes records discovered organization membership.
// Accounts that could not be assumed stay internal and not_scanned.
func OrganizationAccountNodes(cov Coverage) []models.AssetNode {
	if !cov.OrgMembershipKnown {
		return nil
	}
	scanned := map[string]struct{}{}
	for _, id := range cov.Scanned {
		scanned[id] = struct{}{}
	}
	var out []models.AssetNode
	for _, id := range cov.KnownOrgAccountIDs {
		status := "not_scanned"
		if _, ok := scanned[id]; ok {
			status = "scanned"
		}
		out = append(out, models.AssetNode{
			ARN: "arn:cloudrift:organization-account:::" + id, AssetType: models.AssetOrganizationAccount,
			Name: id, AccountID: id,
			Properties: map[string]any{"scan_status": status, "membership": "internal"},
		})
	}
	return out
}

// CollectWorkloads maps EC2 instance profiles and Lambda execution roles.
// A regional failure is recorded and does not discard other regions.
func CollectWorkloads(ctx context.Context, cfg *config.Config, accounts []Account) ([]models.AssetNode, []models.Relationship, error) {
	regions := cfg.AWS.Regions
	if len(regions) == 0 {
		regions = []string{"us-east-1"}
	}
	var assets []models.AssetNode
	var rels []models.Relationship
	for _, account := range accounts {
		if account.Session == nil {
			continue
		}
		for _, region := range regions {
			regional := account.Session.Copy()
			regional.Region = region
			nodes, edges, err := CollectRegionalWorkloads(ctx, account.ID, region, WorkloadClients{
				EC2: ec2.NewFromConfig(regional), IAM: iam.NewFromConfig(regional), Lambda: lambda.NewFromConfig(regional),
				ECS: ecs.NewFromConfig(regional), EKS: eks.NewFromConfig(regional),
			}, time.Now().UTC())
			if err != nil {
				warnPartial(ctx, "workloads", err)
				assets = append(assets, models.AssetNode{
					ARN:       "arn:cloudrift:workload-collection:::" + account.ID + ":" + region,
					AssetType: "workload_collection_status", AccountID: account.ID, Region: region,
					Properties: map[string]any{"status": "partial", "error": err.Error()},
				})
				continue
			}
			assets = append(assets, nodes...)
			rels = append(rels, edges...)
		}
	}
	return assets, rels, nil
}

// CollectRegionalWorkloads reads one account and region through the supplied clients.
func CollectRegionalWorkloads(ctx context.Context, accountID, region string, clients WorkloadClients, collectedAt time.Time) ([]models.AssetNode, []models.Relationship, error) {
	var assets []models.AssetNode
	var rels []models.Relationship
	if clients.EC2 != nil && clients.IAM != nil {
		nodes, edges, err := collectEC2(ctx, accountID, region, clients.EC2, clients.IAM, collectedAt)
		if err != nil {
			return nil, nil, err
		}
		assets = append(assets, nodes...)
		assets = append(assets, CollectionStatus(accountID, region, "ec2", "regional", "succeeded", ""))
		rels = append(rels, edges...)
	}
	if clients.Lambda != nil {
		nodes, edges, err := collectLambda(ctx, accountID, region, clients.Lambda, collectedAt)
		if err != nil {
			return assets, rels, err
		}
		assets = append(assets, nodes...)
		assets = append(assets, CollectionStatus(accountID, region, "lambda", "regional", "succeeded", ""))
		rels = append(rels, edges...)
	}
	if clients.ECS != nil || clients.EKS != nil {
		nodes, edges, err := collectContainers(ctx, accountID, region, clients.ECS, clients.EKS, collectedAt)
		if err != nil {
			assets = append(assets, models.AssetNode{
				ARN:       "arn:cloudrift:workload-collection:::" + accountID + ":" + region + ":containers",
				AssetType: "workload_collection_status", AccountID: accountID, Region: region,
				Properties: map[string]any{"status": "partial", "collector": "ecs_eks", "error": err.Error()},
			})
		} else {
			assets = append(assets, nodes...)
			rels = append(rels, edges...)
		}
	}
	return assets, rels, nil
}

func collectEC2(ctx context.Context, accountID, region string, api EC2API, profiles InstanceProfileAPI, collectedAt time.Time) ([]models.AssetNode, []models.Relationship, error) {
	var instances []ec2types.Instance
	var token *string
	for {
		out, err := api.DescribeInstances(ctx, &ec2.DescribeInstancesInput{NextToken: token})
		if err != nil {
			return nil, nil, err
		}
		for _, reservation := range out.Reservations {
			instances = append(instances, reservation.Instances...)
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	assocByInstance := map[string]ec2types.IamInstanceProfileAssociation{}
	token = nil
	for {
		out, err := api.DescribeIamInstanceProfileAssociations(ctx, &ec2.DescribeIamInstanceProfileAssociationsInput{NextToken: token})
		if err != nil {
			return nil, nil, err
		}
		for _, assoc := range out.IamInstanceProfileAssociations {
			assocByInstance[awsv2.ToString(assoc.InstanceId)] = assoc
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	var assets []models.AssetNode
	var rels []models.Relationship
	seenProfile := map[string]struct{}{}
	for _, instance := range instances {
		id := awsv2.ToString(instance.InstanceId)
		arn := "arn:aws:ec2:" + region + ":" + accountID + ":instance/" + id
		state := ""
		if instance.State != nil {
			state = string(instance.State.Name)
		}
		node := models.AssetNode{
			ARN: arn, AssetType: models.AssetEC2Instance, Name: id, AccountID: accountID, Region: region,
			Properties: map[string]any{
				"instance_state": state, "collected_at": collectedAt.Format(time.RFC3339),
				"source_api": "ec2:DescribeInstances",
			},
		}
		assoc, ok := assocByInstance[id]
		if !ok || assoc.IamInstanceProfile == nil || awsv2.ToString(assoc.IamInstanceProfile.Arn) == "" {
			node.Properties["attachment_status"] = "none"
			assets = append(assets, node)
			continue
		}
		profileARN := awsv2.ToString(assoc.IamInstanceProfile.Arn)
		assocState := string(assoc.State)
		node.Properties["association_state"] = assocState
		node.Properties["instance_profile_arn"] = profileARN
		assets = append(assets, node)
		if _, seen := seenProfile[profileARN]; !seen {
			seenProfile[profileARN] = struct{}{}
			profileNode, profileRels := resolveProfile(ctx, accountID, profileARN, profiles, collectedAt)
			assets = append(assets, profileNode)
			rels = append(rels, profileRels...)
		}
		kind := "CONFIGURED_ROLE_ATTACHMENT"
		note := "EC2 association identifies the instance profile. The role comes from iam:GetInstanceProfile, not from the profile name."
		if assocState != string(ec2types.IamInstanceProfileAssociationStateAssociated) {
			kind = "UNRESOLVED_ROLE"
			note = "The instance profile association is " + assocState + ". The role is not treated as attached."
		}
		rels = append(rels, models.Relationship{
			SourceARN: arn, TargetARN: profileARN, RelType: models.RelEC2UsesInstanceProfile,
			Properties: attachmentProps(arn, string(models.RelEC2UsesInstanceProfile), profileARN, kind, "instance_profile", "ec2:DescribeIamInstanceProfileAssociations", collectedAt, note),
		})
	}
	return assets, rels, nil
}

func resolveProfile(ctx context.Context, accountID, profileARN string, api InstanceProfileAPI, collectedAt time.Time) (models.AssetNode, []models.Relationship) {
	name := profileARN
	if i := strings.LastIndex(profileARN, "/"); i >= 0 {
		name = profileARN[i+1:]
	}
	node := models.AssetNode{
		ARN: profileARN, AssetType: models.AssetInstanceProfile, Name: name, AccountID: accountID, Region: "global",
		Properties: map[string]any{"source_api": "iam:GetInstanceProfile", "collected_at": collectedAt.Format(time.RFC3339)},
	}
	out, err := api.GetInstanceProfile(ctx, &iam.GetInstanceProfileInput{InstanceProfileName: &name})
	if err != nil || out.InstanceProfile == nil {
		node.Properties["retrieval_status"] = "denied"
		return node, nil
	}
	node.Properties["retrieval_status"] = "ok"
	var rels []models.Relationship
	for _, role := range out.InstanceProfile.Roles {
		roleARN := awsv2.ToString(role.Arn)
		if roleARN == "" {
			continue
		}
		node.Properties["role_arn"] = roleARN
		node.Properties["role_name"] = awsv2.ToString(role.RoleName)
		rels = append(rels, models.Relationship{
			SourceARN: profileARN, TargetARN: roleARN, RelType: models.RelInstanceProfileContains,
			Properties: attachmentProps(profileARN, string(models.RelInstanceProfileContains), roleARN, "CONFIGURED_ROLE_ATTACHMENT", "instance_profile", "iam:GetInstanceProfile", collectedAt,
				"Instance profile "+name+" contains role "+awsv2.ToString(role.RoleName)+"."),
		})
	}
	if len(rels) == 0 {
		node.Properties["retrieval_status"] = "no_role"
	}
	return node, rels
}

func collectLambda(ctx context.Context, accountID, region string, api LambdaAPI, collectedAt time.Time) ([]models.AssetNode, []models.Relationship, error) {
	var functions []lambdatypes.FunctionConfiguration
	var token *string
	for {
		out, err := api.ListFunctions(ctx, &lambda.ListFunctionsInput{Marker: token})
		if err != nil {
			return nil, nil, err
		}
		functions = append(functions, out.Functions...)
		if out.NextMarker == nil || *out.NextMarker == "" {
			break
		}
		token = out.NextMarker
	}
	var assets []models.AssetNode
	var rels []models.Relationship
	for _, fn := range functions {
		arn := awsv2.ToString(fn.FunctionArn)
		roleARN := awsv2.ToString(fn.Role)
		node := models.AssetNode{
			ARN: arn, AssetType: models.AssetLambdaFunction, Name: awsv2.ToString(fn.FunctionName),
			AccountID: accountID, Region: region,
			Properties: map[string]any{
				"function_state": string(fn.State), "last_update_status": string(fn.LastUpdateStatus),
				"execution_role_arn": roleARN, "source_api": "lambda:ListFunctions",
				"collected_at":        collectedAt.Format(time.RFC3339),
				"configuration_scope": "function",
			},
		}
		assets = append(assets, node)
		if roleARN == "" {
			node.Properties["attachment_status"] = "none"
			assets[len(assets)-1] = node
			continue
		}
		kind := "CONFIGURED_ROLE_ATTACHMENT"
		note := "The function configuration names this execution role. Service trust alone is not this attachment."
		rels = append(rels, models.Relationship{
			SourceARN: arn, TargetARN: roleARN, RelType: models.RelLambdaUsesExecutionRole,
			Properties: attachmentProps(arn, string(models.RelLambdaUsesExecutionRole), roleARN, kind, "lambda_execution_role", "lambda:ListFunctions", collectedAt, note),
		})
	}
	return assets, rels, nil
}

func attachmentProps(source, relType, target, kind, mechanism, sourceAPI string, collectedAt time.Time, note string) map[string]any {
	return map[string]any{
		"kind": kind, "mechanism": mechanism, "source_api": sourceAPI, "role_arn": target,
		"collected_at": collectedAt.Format(time.RFC3339), "note": note,
		"relationship_id": relationshipID(source, relType, target),
		"status":          "collected",
	}
}

// MarkUnresolvedRoleReferences marks attachments whose role is absent from the role inventory.
func MarkUnresolvedRoleReferences(assets []models.AssetNode, rels []models.Relationship) {
	roles := map[string]struct{}{}
	for _, asset := range assets {
		if asset.AssetType == models.AssetIAMRole {
			roles[asset.ARN] = struct{}{}
		}
	}
	unresolvedProfiles := map[string]struct{}{}
	for i, rel := range rels {
		if rel.RelType != models.RelLambdaUsesExecutionRole && rel.RelType != models.RelInstanceProfileContains && !roleAttachment(rel.RelType) {
			continue
		}
		if _, ok := roles[rel.TargetARN]; ok {
			continue
		}
		if rel.Properties == nil {
			rel.Properties = map[string]any{}
		}
		rel.Properties["kind"] = "UNRESOLVED_ROLE"
		rel.Properties["note"] = "The referenced role was not in the collected role inventory."
		rels[i] = rel
		if rel.RelType == models.RelInstanceProfileContains {
			unresolvedProfiles[rel.SourceARN] = struct{}{}
		}
	}
	for i, rel := range rels {
		if rel.RelType != models.RelEC2UsesInstanceProfile {
			continue
		}
		if _, ok := unresolvedProfiles[rel.TargetARN]; !ok {
			continue
		}
		if rel.Properties == nil {
			rel.Properties = map[string]any{}
		}
		rel.Properties["kind"] = "UNRESOLVED_ROLE"
		rels[i] = rel
	}
}

func roleAttachment(relType models.RelType) bool {
	switch relType {
	case models.RelECSTaskDefUsesTaskRole, models.RelECSTaskDefUsesExecutionRole, models.RelEKSPodIdentityUsesRole, models.RelIRSATrustConfiguration:
		return true
	default:
		return false
	}
}

func relationshipID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:8])
}
