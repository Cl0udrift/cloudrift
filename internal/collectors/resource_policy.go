package collectors

import (
	"context"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// SecretsAPI is the read-only Secrets Manager surface. GetSecretValue is deliberately absent.
type SecretsAPI interface {
	ListSecrets(ctx context.Context, params *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error)
	GetResourcePolicy(ctx context.Context, params *secretsmanager.GetResourcePolicyInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetResourcePolicyOutput, error)
}

// KMSAPI is the read-only KMS surface. No key material, grant or crypto operation is exposed.
type KMSAPI interface {
	ListKeys(ctx context.Context, params *kms.ListKeysInput, optFns ...func(*kms.Options)) (*kms.ListKeysOutput, error)
	DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
	GetKeyPolicy(ctx context.Context, params *kms.GetKeyPolicyInput, optFns ...func(*kms.Options)) (*kms.GetKeyPolicyOutput, error)
	ListAliases(ctx context.Context, params *kms.ListAliasesInput, optFns ...func(*kms.Options)) (*kms.ListAliasesOutput, error)
	ListGrants(ctx context.Context, params *kms.ListGrantsInput, optFns ...func(*kms.Options)) (*kms.ListGrantsOutput, error)
}

// RDSAPI is the read-only RDS surface used to inventory DB instances.
type RDSAPI interface {
	DescribeDBInstances(ctx context.Context, params *rds.DescribeDBInstancesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
}

// LambdaPolicyAPI reads a function's resource policy.
type LambdaPolicyAPI interface {
	GetPolicy(ctx context.Context, params *lambda.GetPolicyInput, optFns ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error)
}

// EndpointAPI reads VPC endpoints and the policy attached to each.
type EndpointAPI interface {
	DescribeVpcEndpoints(ctx context.Context, params *ec2.DescribeVpcEndpointsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVpcEndpointsOutput, error)
}

// ResourcePolicyClients are the regional clients used by CollectRegionalResourcePolicies.
type ResourcePolicyClients struct {
	Secrets SecretsAPI
	KMS     KMSAPI
	RDS     RDSAPI
	EC2     EndpointAPI
}

var regionalResourcePolicyClients = func(cfg awsv2.Config) ResourcePolicyClients {
	return ResourcePolicyClients{Secrets: secretsmanager.NewFromConfig(cfg), KMS: kms.NewFromConfig(cfg), RDS: rds.NewFromConfig(cfg), EC2: ec2.NewFromConfig(cfg)}
}

// Secret key modes. aws_managed is aws/secretsmanager; customer_managed needs the key policy;
// unknown means the key could not be resolved and must not be treated as aws_managed.
const (
	SecretKMSAWSManaged      = "aws_managed"
	SecretKMSCustomerManaged = "customer_managed"
	SecretKMSUnknown         = "unknown"
)

// CollectResourcePolicies reads secret metadata and resource policies plus customer-managed KMS key
// policies in each account's selected Regions. Region selection matches CollectWorkloads.
func CollectResourcePolicies(ctx context.Context, cfg *config.Config, accounts []Account) ([]models.AssetNode, error) {
	mode, explicit, err := config.ResolveRegionMode(cfg)
	if err != nil {
		return nil, err
	}
	var assets []models.AssetNode
	var jobs []regionJob
	for _, account := range accounts {
		if account.Session == nil {
			continue
		}
		var plan RegionDiscoveryResult
		if mode == config.RegionModeAuto {
			plan = describeAccountRegions(ctx, account)
		} else {
			plan = explicitRegionPlan(account.ID, mode, explicit)
		}
		if plan.Status != "succeeded" {
			continue
		}
		for _, region := range plan.Selected {
			jobs = append(jobs, regionJob{account: account, region: region})
		}
	}
	workers := 1
	if cfg != nil && cfg.Scan.RoleAssumptionConcurrency > 0 {
		workers = cfg.Scan.RoleAssumptionConcurrency
	}
	var mu sync.Mutex
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, job := range jobs {
		wg.Add(1)
		go func(job regionJob) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
				defer func() { <-sem }()
			}
			regional := job.account.Session.Copy()
			regional.Region = job.region
			nodes := CollectRegionalResourcePolicies(ctx, job.account.ID, job.region, regionalResourcePolicyClients(regional), time.Now().UTC())
			mu.Lock()
			assets = append(assets, nodes...)
			mu.Unlock()
		}(job)
	}
	wg.Wait()
	sort.Slice(assets, func(i, j int) bool { return assets[i].ARN < assets[j].ARN })
	return assets, nil
}

// CollectRegionalResourcePolicies reads one account and Region. Every API failure stays on the
// thing it affected as a "missing" status, never as confirmed absence.
func CollectRegionalResourcePolicies(ctx context.Context, accountID, region string, c ResourcePolicyClients, at time.Time) []models.AssetNode {
	var out []models.AssetNode
	retrieved := at.UTC().Format(time.RFC3339)
	aliases, aliasErr := keyAliases(ctx, c.KMS)
	keyARNs := map[string]struct{}{}

	secrets, err := listSecrets(ctx, c.Secrets)
	if err != nil {
		out = append(out, CollectionStatus(accountID, region, "secrets", "regional", "failed", apiErrorCode(err)))
	}
	for _, s := range secrets {
		arn := awsv2.ToString(s.ARN)
		mode, keyARN, evidence := resolveSecretKey(awsv2.ToString(s.KmsKeyId), accountID, region, aliases, aliasErr)
		props := map[string]any{
			"secret_kms_mode":     mode,
			"secret_kms_key_arn":  keyARN,
			"secret_kms_evidence": evidence,
			"retrieved_at":        retrieved,
		}
		status, ev, doc := readSecretPolicy(ctx, c.Secrets, arn)
		props["secret_policy_status"], props["secret_policy_evidence"], props["secret_policy_document"] = status, ev, doc
		if keyARN != "" {
			keyARNs[keyARN] = struct{}{}
		}
		out = append(out, models.AssetNode{ARN: arn, AssetType: models.AssetSecret, Name: awsv2.ToString(s.Name), AccountID: accountID, Region: region, Properties: props})
	}

	keys, err := listKeys(ctx, c.KMS)
	if err != nil {
		out = append(out, CollectionStatus(accountID, region, "kms", "regional", "failed", apiErrorCode(err)))
	}
	for _, k := range keys {
		arn := awsv2.ToString(k.KeyArn)
		desc, err := c.KMS.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: k.KeyId})
		if err != nil || desc.KeyMetadata == nil {
			continue
		}
		meta := desc.KeyMetadata
		if meta.KeyManager != kmstypes.KeyManagerTypeCustomer {
			continue // AWS managed key policies are not editable and carry RCP exceptions
		}
		props := map[string]any{"key_state": string(meta.KeyState), "retrieved_at": retrieved}
		status, ev, doc := readKeyPolicy(ctx, c.KMS, awsv2.ToString(k.KeyId))
		props["key_policy_status"], props["key_policy_evidence"], props["key_policy_document"] = status, ev, doc
		grants, grantStatus := readKeyGrants(ctx, c.KMS, awsv2.ToString(k.KeyId))
		props["key_grants"], props["key_grants_status"] = grants, grantStatus
		out = append(out, models.AssetNode{ARN: arn, AssetType: models.AssetKMSKey, Name: awsv2.ToString(k.KeyId), AccountID: accountID, Region: region, Properties: props})
	}
	if c.RDS != nil {
		out = append(out, collectRDSInstances(ctx, accountID, region, c.RDS, retrieved)...)
	}
	if c.EC2 != nil {
		out = append(out, collectVPCEndpoints(ctx, accountID, region, c.EC2, retrieved)...)
	}
	return out
}

// collectVPCEndpoints records each endpoint with its policy document. An endpoint policy only
// applies to requests that travel through that endpoint, which a scan cannot see, so the
// evaluator does not use these documents; they are evidence for review.
func collectVPCEndpoints(ctx context.Context, accountID, region string, api EndpointAPI, retrieved string) []models.AssetNode {
	var out []models.AssetNode
	var token *string
	for {
		page, err := api.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{NextToken: token})
		if err != nil {
			return append(out, CollectionStatus(accountID, region, "vpc_endpoints", "regional", "failed", apiErrorCode(err)))
		}
		for _, e := range page.VpcEndpoints {
			id := awsv2.ToString(e.VpcEndpointId)
			if id == "" {
				continue
			}
			doc := awsv2.ToString(e.PolicyDocument)
			status := "collected"
			if doc == "" {
				status = "not_returned" // the API gave no document; do not read this as full access
			}
			out = append(out, models.AssetNode{
				ARN: "arn:aws:ec2:" + region + ":" + accountID + ":vpc-endpoint/" + id, AssetType: models.AssetVPCEndpoint,
				Name: id, AccountID: accountID, Region: region,
				Properties: map[string]any{
					"service_name":           awsv2.ToString(e.ServiceName),
					"endpoint_type":          string(e.VpcEndpointType),
					"vpc_id":                 awsv2.ToString(e.VpcId),
					"endpoint_state":         string(e.State),
					"endpoint_policy":        doc,
					"endpoint_policy_status": status,
					"retrieved_at":           retrieved,
					"source_api":             "ec2:DescribeVpcEndpoints",
				}})
		}
		if page.NextToken == nil || *page.NextToken == "" {
			return out
		}
		token = page.NextToken
	}
}

func collectRDSInstances(ctx context.Context, accountID, region string, api RDSAPI, retrieved string) []models.AssetNode {
	var out []models.AssetNode
	var marker *string
	for {
		page, err := api.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{Marker: marker})
		if err != nil {
			return append(out, CollectionStatus(accountID, region, "rds", "regional", "failed", apiErrorCode(err)))
		}
		for _, db := range page.DBInstances {
			arn := awsv2.ToString(db.DBInstanceArn)
			if arn == "" {
				continue
			}
			out = append(out, models.AssetNode{ARN: arn, AssetType: models.AssetRDSInstance, Name: awsv2.ToString(db.DBInstanceIdentifier), AccountID: accountID, Region: region,
				Properties: map[string]any{
					"db_status":           awsv2.ToString(db.DBInstanceStatus),
					"deletion_protection": awsv2.ToBool(db.DeletionProtection),
					"engine":              awsv2.ToString(db.Engine),
					"retrieved_at":        retrieved,
					"source_api":          "rds:DescribeDBInstances",
				}})
		}
		if page.Marker == nil || *page.Marker == "" {
			return out
		}
		marker = page.Marker
	}
}

var lambdaPolicyClient = func(cfg awsv2.Config) LambdaPolicyAPI { return lambda.NewFromConfig(cfg) }

// CollectLambdaPolicies reads the resource policy of every collected Lambda function and records
// it on the function asset in place. NoSuchPolicy (ResourceNotFoundException) is confirmed absence;
// every other failure is "missing".
func CollectLambdaPolicies(ctx context.Context, cfg *config.Config, accounts []Account, assets []models.AssetNode) {
	sessions := map[string]*awsv2.Config{}
	for _, a := range accounts {
		if a.Session != nil {
			sessions[a.ID] = a.Session
		}
	}
	workers := 1
	if cfg != nil && cfg.Scan.RoleAssumptionConcurrency > 0 {
		workers = cfg.Scan.RoleAssumptionConcurrency
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i := range assets {
		if assets[i].AssetType != models.AssetLambdaFunction || sessions[assets[i].AccountID] == nil {
			continue
		}
		if assets[i].Properties == nil {
			assets[i].Properties = map[string]any{}
		}
		wg.Add(1)
		go func(node *models.AssetNode) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case sem <- struct{}{}:
				defer func() { <-sem }()
			}
			regional := sessions[node.AccountID].Copy()
			regional.Region = node.Region
			status, evidence, doc := readLambdaPolicy(ctx, lambdaPolicyClient(regional), node.ARN)
			node.Properties["function_policy_status"], node.Properties["function_policy_evidence"], node.Properties["function_policy_document"] = status, evidence, doc
		}(&assets[i])
	}
	wg.Wait()
}

func readLambdaPolicy(ctx context.Context, api LambdaPolicyAPI, arn string) (status, evidence, doc string) {
	out, err := api.GetPolicy(ctx, &lambda.GetPolicyInput{FunctionName: awsv2.String(arn)})
	if err != nil {
		if apiErrorCode(err) == "ResourceNotFoundException" {
			return "confirmed_absent", "lambda:GetPolicy returned ResourceNotFoundException (no resource policy)", ""
		}
		return "missing", "lambda:GetPolicy failed: " + apiErrorCode(err), ""
	}
	policy := strings.TrimSpace(awsv2.ToString(out.Policy))
	if policy == "" {
		return "missing", "lambda:GetPolicy returned an empty policy", ""
	}
	return "present", "lambda:GetPolicy returned a function resource policy", policy
}

func listSecrets(ctx context.Context, api SecretsAPI) ([]secretListEntry, error) {
	var out []secretListEntry
	var token *string
	for {
		page, err := api.ListSecrets(ctx, &secretsmanager.ListSecretsInput{NextToken: token})
		if err != nil {
			return out, err
		}
		for _, s := range page.SecretList {
			out = append(out, secretListEntry{ARN: s.ARN, Name: s.Name, KmsKeyId: s.KmsKeyId})
		}
		if page.NextToken == nil {
			return out, nil
		}
		token = page.NextToken
	}
}

type secretListEntry struct{ ARN, Name, KmsKeyId *string }

func listKeys(ctx context.Context, api KMSAPI) ([]kmstypes.KeyListEntry, error) {
	var out []kmstypes.KeyListEntry
	var marker *string
	for {
		page, err := api.ListKeys(ctx, &kms.ListKeysInput{Marker: marker})
		if err != nil {
			return out, err
		}
		out = append(out, page.Keys...)
		if !page.Truncated {
			return out, nil
		}
		marker = page.NextMarker
	}
}

// keyAliases maps "alias/name" to the target key ID. A failure leaves aliases unresolved.
func keyAliases(ctx context.Context, api KMSAPI) (map[string]string, error) {
	aliases := map[string]string{}
	var marker *string
	for {
		page, err := api.ListAliases(ctx, &kms.ListAliasesInput{Marker: marker})
		if err != nil {
			return aliases, err
		}
		for _, a := range page.Aliases {
			if a.AliasName != nil && a.TargetKeyId != nil {
				aliases[*a.AliasName] = *a.TargetKeyId
			}
		}
		if !page.Truncated {
			return aliases, nil
		}
		marker = page.NextMarker
	}
}

// resolveSecretKey classifies the key protecting a secret. An empty KmsKeyId or the default
// alias means aws/secretsmanager. Anything unresolvable is unknown, never aws_managed.
func resolveSecretKey(keyID, accountID, region string, aliases map[string]string, aliasErr error) (mode, keyARN, evidence string) {
	keyID = strings.TrimSpace(keyID)
	switch {
	case keyID == "" || keyID == "alias/aws/secretsmanager" || strings.HasSuffix(keyID, ":alias/aws/secretsmanager"):
		return SecretKMSAWSManaged, "", "secret uses the AWS managed key aws/secretsmanager"
	case strings.HasPrefix(keyID, "arn:") && strings.Contains(keyID, ":key/"):
		return SecretKMSCustomerManaged, keyID, "secret names a customer managed key ARN"
	case strings.HasPrefix(keyID, "arn:") && strings.Contains(keyID, ":alias/"):
		keyID = keyID[strings.Index(keyID, ":alias/")+1:]
	}
	if strings.HasPrefix(keyID, "alias/") {
		if target, ok := aliases[keyID]; ok {
			return SecretKMSCustomerManaged, "arn:aws:kms:" + region + ":" + accountID + ":key/" + target, "secret key alias " + keyID + " resolved with kms:ListAliases"
		}
		if aliasErr != nil {
			return SecretKMSUnknown, "", "kms:ListAliases failed (" + apiErrorCode(aliasErr) + "); alias " + keyID + " is unresolved"
		}
		return SecretKMSUnknown, "", "alias " + keyID + " was not found in this Region"
	}
	return SecretKMSCustomerManaged, "arn:aws:kms:" + region + ":" + accountID + ":key/" + keyID, "secret names key ID " + keyID
}

func readSecretPolicy(ctx context.Context, api SecretsAPI, arn string) (status, evidence, doc string) {
	out, err := api.GetResourcePolicy(ctx, &secretsmanager.GetResourcePolicyInput{SecretId: awsv2.String(arn)})
	if err != nil {
		return "missing", "secretsmanager:GetResourcePolicy failed: " + apiErrorCode(err), ""
	}
	policy := strings.TrimSpace(awsv2.ToString(out.ResourcePolicy))
	if policy == "" {
		return "confirmed_absent", "secretsmanager:GetResourcePolicy returned no resource policy", ""
	}
	return "present", "secretsmanager:GetResourcePolicy returned a resource policy", policy
}

func readKeyPolicy(ctx context.Context, api KMSAPI, keyID string) (status, evidence, doc string) {
	out, err := api.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{KeyId: awsv2.String(keyID), PolicyName: awsv2.String("default")})
	if err != nil {
		return "missing", "kms:GetKeyPolicy failed: " + apiErrorCode(err), ""
	}
	policy := strings.TrimSpace(awsv2.ToString(out.Policy))
	if decoded, derr := url.QueryUnescape(policy); derr == nil && strings.HasPrefix(strings.TrimSpace(decoded), "{") {
		policy = strings.TrimSpace(decoded)
	}
	if policy == "" {
		// A key always has a key policy, so an empty answer is not absence.
		return "missing", "kms:GetKeyPolicy returned an empty policy", ""
	}
	return "present", "kms:GetKeyPolicy returned the default key policy", policy
}

// grantConstraint keeps the encryption-context condition a grant carries, so it can be shown.
func grantConstraint(c *kmstypes.GrantConstraints) map[string]any {
	if c == nil {
		return nil
	}
	out := map[string]any{}
	if len(c.EncryptionContextEquals) > 0 {
		out["encryption_context_equals"] = c.EncryptionContextEquals
	}
	if len(c.EncryptionContextSubset) > 0 {
		out["encryption_context_subset"] = c.EncryptionContextSubset
	}
	return out
}

// readKeyGrants returns the key's grants. A failed call leaves status "missing": grants only add
// access, so missing grants can withhold an Allow but never create one.
func readKeyGrants(ctx context.Context, api KMSAPI, keyID string) ([]map[string]any, string) {
	grants := []map[string]any{}
	var marker *string
	for {
		page, err := api.ListGrants(ctx, &kms.ListGrantsInput{KeyId: awsv2.String(keyID), Marker: marker})
		if err != nil {
			return nil, "missing"
		}
		for _, g := range page.Grants {
			ops := make([]string, 0, len(g.Operations))
			for _, op := range g.Operations {
				ops = append(ops, string(op))
			}
			grants = append(grants, map[string]any{
				"grantee_principal": awsv2.ToString(g.GranteePrincipal),
				"operations":        ops,
				"constrained":       g.Constraints != nil,
				"constraint":        grantConstraint(g.Constraints),
			})
		}
		if !page.Truncated {
			return grants, "collected"
		}
		marker = page.NextMarker
	}
}
