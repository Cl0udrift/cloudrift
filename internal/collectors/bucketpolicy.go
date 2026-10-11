package collectors

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"sync"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"

	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// CollectBucketPolicies inspects S3 bucket resource policies for cross-account or public
// grants — exposure that IAM role-trust scanning (CollectTrust) misses entirely. For each
// bucket it reads the bucket policy and, for every Allow statement granting access to an
// external account or to "*", emits an external-principal node plus a bucket->principal
// relationship (RelTrusts, tagged source_kind=s3_bucket_policy) carrying the granted
// actions. Returns the external-principal nodes, the relationships, and the IDs of accounts
// whose policy read was denied (folded into scan coverage by the caller).
//
// It is given the already-collected bucket assets (from CollectStorage) to avoid a second
// ListBuckets pass; it only needs each owning account's session for GetBucketPolicy.
func CollectBucketPolicies(ctx context.Context, accounts []Account, buckets []models.AssetNode) ([]models.AssetNode, []models.Relationship, []BucketPolicyEvidence, []string, error) {
	return CollectBucketPoliciesWithConfig(ctx, config.Default(), accounts, buckets)
}

func CollectBucketPoliciesWithConfig(ctx context.Context, cfg *config.Config, accounts []Account, buckets []models.AssetNode) ([]models.AssetNode, []models.Relationship, []BucketPolicyEvidence, []string, error) {
	sessionByAccount := make(map[string]*awsv2.Config, len(accounts))
	for i := range accounts {
		if accounts[i].Session != nil {
			sessionByAccount[accounts[i].ID] = accounts[i].Session
		}
	}

	var (
		mu         sync.Mutex
		principals []models.AssetNode
		rels       []models.Relationship
		evidence   []BucketPolicyEvidence
		failed     []string
		firstErr   error
		seenPrin   = map[string]bool{}
	)
	sem := make(chan struct{}, max(1, cfg.Scan.RoleAssumptionConcurrency))
	var wg sync.WaitGroup

	for _, b := range buckets {
		if b.AssetType != models.AssetS3Bucket {
			continue
		}
		sess := sessionByAccount[b.AccountID]
		if sess == nil {
			continue
		}
		b := b
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			c := s3.NewFromConfig(*sess)
			fact := readBucketEvidence(ctx, c, b)
			out, err := c.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: awsv2.String(b.Name)})
			policyStatus, policyEvidence, document := ClassifyBucketPolicyRead(apiErrorCode(err), "")
			if err == nil && out != nil {
				policyStatus, policyEvidence, document = ClassifyBucketPolicyRead("", decodeBucketPolicy(awsv2.ToString(out.Policy)))
			}
			fact.PolicyStatus = policyStatus
			fact.PolicyEvidence = policyEvidence
			fact.PolicyDocument = document
			if err != nil && isAccessDeniedErr(err) {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				failed = append(failed, b.AccountID)
				evidence = append(evidence, fact)
				mu.Unlock()
				return
			}
			mu.Lock()
			evidence = append(evidence, fact)
			if document == "" {
				mu.Unlock()
				return
			}
			grants := externalGrantsFromBucketPolicy(b.AccountID, document)
			for _, g := range grants {
				if !seenPrin[g.principalARN] {
					seenPrin[g.principalARN] = true
					principalNode := models.AssetNode{
						ARN:       g.principalARN,
						AssetType: models.AssetExternalPrincipal,
						Name:      g.principalValue,
						AccountID: b.AccountID,
						Properties: map[string]any{
							"principal_type":      g.principalType,
							"principal_value":     g.principalValue,
							"external_account_id": g.externalAccountID,
						},
					}
					principalNode, _ = models.ResolvePrincipalOwnership(principalNode)
					principals = append(principals, principalNode)
				}
				rels = append(rels, models.Relationship{
					SourceARN: b.ARN,
					TargetARN: g.principalARN,
					RelType:   models.RelTrusts,
					Properties: map[string]any{
						"source_kind":         "s3_bucket_policy",
						"principal_type":      g.principalType,
						"external_account_id": g.externalAccountID,
						"is_public":           g.isPublic,
						"write_access":        g.write,
						"actions":             g.actions,
					},
				})
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	warnPartial(ctx, "bucket_policy", firstErr)
	return principals, rels, evidence, failed, nil
}

type bucketGrant struct {
	principalType     string // aws_account | public
	principalValue    string
	principalARN      string
	externalAccountID string
	isPublic          bool
	actions           []string
	write             bool
}

// resourceStatement keeps Principal as `any` (unlike the assume-role parser) so the
// string form `"Principal": "*"` used for public buckets is not lost.
type resourceStatement struct {
	Effect    string `json:"Effect"`
	Action    any    `json:"Action"`
	Principal any    `json:"Principal"`
}

func externalGrantsFromBucketPolicy(ownerAccountID, rawPolicy string) []bucketGrant {
	stmts := parseResourceStatements(rawPolicy)
	var grants []bucketGrant
	for _, stmt := range stmts {
		if !strings.EqualFold(strings.TrimSpace(stmt.Effect), "allow") {
			continue
		}
		actions := lowerAll(principalValues(stmt.Action))
		write := actionsImplyWrite(actions)

		// Principal: "*" (string) → public.
		if s, ok := stmt.Principal.(string); ok && strings.TrimSpace(s) == "*" {
			grants = append(grants, publicGrant(actions, write))
			continue
		}
		pm, ok := stmt.Principal.(map[string]any)
		if !ok {
			continue
		}
		for _, p := range principalValues(pm["AWS"]) {
			if strings.TrimSpace(p) == "*" {
				grants = append(grants, publicGrant(actions, write))
				continue
			}
			normalized, keep := normalizeExternalAWSPrincipal(ownerAccountID, p)
			if !keep {
				continue
			}
			grants = append(grants, bucketGrant{
				principalType:     "aws_account",
				principalValue:    normalized,
				principalARN:      externalPrincipalARN("aws_account", normalized),
				externalAccountID: accountIDFromARN(normalized),
				actions:           actions,
				write:             write,
			})
		}
	}
	return grants
}

func publicGrant(actions []string, write bool) bucketGrant {
	return bucketGrant{
		principalType:  "public",
		principalValue: "*",
		principalARN:   externalPrincipalARN("public", "*"),
		isPublic:       true,
		actions:        actions,
		write:          write,
	}
}

func parseResourceStatements(raw string) []resourceStatement {
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		decoded = raw
	}
	var doc struct {
		Statement any `json:"Statement"`
	}
	if json.Unmarshal([]byte(decoded), &doc) != nil {
		return nil
	}
	switch s := doc.Statement.(type) {
	case []any:
		out := make([]resourceStatement, 0, len(s))
		for _, item := range s {
			if rs, ok := toResourceStatement(item); ok {
				out = append(out, rs)
			}
		}
		return out
	case map[string]any:
		if rs, ok := toResourceStatement(s); ok {
			return []resourceStatement{rs}
		}
	}
	return nil
}

func toResourceStatement(item any) (resourceStatement, bool) {
	b, err := json.Marshal(item)
	if err != nil {
		return resourceStatement{}, false
	}
	var rs resourceStatement
	if json.Unmarshal(b, &rs) != nil {
		return resourceStatement{}, false
	}
	return rs, true
}

func actionsImplyWrite(actions []string) bool {
	for _, a := range actions {
		a = strings.TrimSpace(a)
		if a == "*" || a == "s3:*" {
			return true
		}
		if strings.HasPrefix(a, "s3:put") ||
			strings.HasPrefix(a, "s3:delete") ||
			strings.HasPrefix(a, "s3:restore") ||
			strings.HasPrefix(a, "s3:replicate") ||
			strings.HasPrefix(a, "s3:create") {
			return true
		}
	}
	return false
}

func lowerAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, strings.ToLower(strings.TrimSpace(s)))
	}
	return out
}

func accountIDFromARN(arn string) string {
	if m := accountIDInIAMArn.FindStringSubmatch(arn); len(m) == 2 {
		return m[1]
	}
	return ""
}

// BucketPolicyEvidence is the bucket-policy and related S3 configuration observed
// for one bucket. A missing read is not recorded as confirmed absence.
type BucketPolicyEvidence struct {
	BucketARN                 string
	PolicyStatus              string
	PolicyEvidence            string
	PolicyDocument            string
	ObjectOwnership           string
	ObjectOwnershipEvidence   string
	Encryption                string
	EncryptionEvidence        string
	KMSKeyARN                 string
	PublicAccessBlockStatus   string
	PublicAccessBlockEvidence string
}

// ClassifyBucketPolicyRead maps one GetBucketPolicy result to an evidence state.
// The document is retained whole, including Deny, NotAction, NotResource, and Condition.
func ClassifyBucketPolicyRead(apiCode, policy string) (status, evidence, document string) {
	switch apiCode {
	case "":
		if strings.TrimSpace(policy) == "" {
			return "confirmed_absent", "s3:GetBucketPolicy returned no policy document", ""
		}
		return "present", "s3:GetBucketPolicy returned a bucket policy document", policy
	case "NoSuchBucketPolicy":
		return "confirmed_absent", "s3:GetBucketPolicy returned NoSuchBucketPolicy", ""
	case "AccessDenied", "Forbidden":
		return "missing", "s3:GetBucketPolicy was denied", ""
	default:
		if apiCode == "" {
			apiCode = "unknown"
		}
		return "missing", "s3:GetBucketPolicy failed: " + apiCode, ""
	}
}

func readBucketEvidence(ctx context.Context, c *s3.Client, bucket models.AssetNode) BucketPolicyEvidence {
	fact := BucketPolicyEvidence{BucketARN: bucket.ARN}
	name := awsv2.String(bucket.Name)
	if out, err := c.GetBucketOwnershipControls(ctx, &s3.GetBucketOwnershipControlsInput{Bucket: name}); err != nil {
		fact.ObjectOwnershipEvidence = "s3:GetBucketOwnershipControls " + apiErrorCode(err)
	} else if out != nil && out.OwnershipControls != nil && len(out.OwnershipControls.Rules) > 0 {
		fact.ObjectOwnership = string(out.OwnershipControls.Rules[0].ObjectOwnership)
		fact.ObjectOwnershipEvidence = "s3:GetBucketOwnershipControls returned " + fact.ObjectOwnership
	}
	if out, err := c.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: name}); err != nil {
		code := apiErrorCode(err)
		if code == "ServerSideEncryptionConfigurationNotFoundError" {
			fact.Encryption = "confirmed_absent"
			fact.EncryptionEvidence = "s3:GetBucketEncryption returned ServerSideEncryptionConfigurationNotFoundError"
		} else {
			fact.Encryption = "missing"
			fact.EncryptionEvidence = "s3:GetBucketEncryption " + code
		}
	} else if out != nil && out.ServerSideEncryptionConfiguration != nil && len(out.ServerSideEncryptionConfiguration.Rules) > 0 {
		rule := out.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault
		if rule != nil {
			fact.Encryption = string(rule.SSEAlgorithm)
			fact.KMSKeyARN = awsv2.ToString(rule.KMSMasterKeyID)
			fact.EncryptionEvidence = "s3:GetBucketEncryption returned " + fact.Encryption
		}
	}
	if _, err := c.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: name}); err != nil {
		code := apiErrorCode(err)
		if code == "NoSuchPublicAccessBlockConfiguration" {
			fact.PublicAccessBlockStatus = "confirmed_absent"
			fact.PublicAccessBlockEvidence = "s3:GetPublicAccessBlock returned NoSuchPublicAccessBlockConfiguration; account-level Block Public Access was not read"
		} else {
			fact.PublicAccessBlockStatus = "missing"
			fact.PublicAccessBlockEvidence = "s3:GetPublicAccessBlock " + code
		}
	} else {
		fact.PublicAccessBlockStatus = "present"
		fact.PublicAccessBlockEvidence = "s3:GetPublicAccessBlock returned a bucket configuration; account-level Block Public Access was not read"
	}
	return fact
}

func decodeBucketPolicy(raw string) string {
	decoded, err := url.QueryUnescape(raw)
	if err != nil || strings.TrimSpace(decoded) == "" {
		return raw
	}
	return decoded
}

func apiErrorCode(err error) string {
	if err == nil {
		return ""
	}
	var api smithy.APIError
	if errors.As(err, &api) && api.ErrorCode() != "" {
		return api.ErrorCode()
	}
	if isAccessDeniedErr(err) {
		return "AccessDenied"
	}
	return "Error"
}

func isAccessDeniedErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "accessdenied") || strings.Contains(msg, "forbidden") || strings.Contains(msg, "not authorized")
}
