package scorers

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	cetypes "github.com/aws/aws-sdk-go-v2/service/costexplorer/types"

	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/models"
)

type CostExplorerAPI interface {
	GetCostAndUsage(ctx context.Context, params *costexplorer.GetCostAndUsageInput, optFns ...func(*costexplorer.Options)) (*costexplorer.GetCostAndUsageOutput, error)
}

var newCostExplorerClient = func(cfg awsv2.Config) CostExplorerAPI {
	return costexplorer.NewFromConfig(cfg)
}

var loadAWSCfgForCE = func(ctx context.Context, cfg config.Config) (awsv2.Config, error) {
	var opts []func(*awscfg.LoadOptions) error
	if cfg.AWS.ManagementProfile != "" {
		opts = append(opts, awscfg.WithSharedConfigProfile(cfg.AWS.ManagementProfile))
	}
	c, err := awscfg.LoadDefaultConfig(ctx, opts...)
	// Cost Explorer is one global endpoint, served from us-east-1. A profile with no Region would otherwise fail with
	// "Missing Region" and the whole cost feature would silently do nothing.
	c.Region = "us-east-1"
	return c, err
}

var ceNowUTC = func() time.Time {
	return time.Now().UTC()
}

// estimatedListPrice is what holding one asset of each kind costs per month at AWS list price, from the AWS pricing pages
// (read 2026-11-22). Every kind is $0, which is the finding: none of them has a standing per-asset fee, so the price of an
// orphaned asset says nothing about the harm of leaving it exposed.
//   - Route 53: $0.50 per hosted zone per month; a record has no charge (a zone includes up to 10,000).
//   - S3: no fixed fee per bucket and no minimum charge; storage and requests are billed by use.
//   - CloudFront: pay-as-you-go has no stated per-distribution fee. Flat-rate plans ($0, $15, $200, $1,000 per month) exist,
//     but the plan of a distribution is not collected.
//   - ACM: a public certificate for ACM-integrated services is free. An exportable one is $7 at issuance and renewal, and the
//     scan does not say which kind a certificate is.
var estimatedListPrice = map[models.AssetType]float64{
	models.AssetDNSRecord:      0,
	models.AssetS3Bucket:       0,
	models.AssetCloudFrontDist: 0,
	models.AssetACMCert:        0,
}

// Modeled factors for how easy an orphaned asset is to take over. They scale the list price above; they are not a loss
// estimate and are not configurable.
const (
	riskFactorReclaimable = 5.0
	riskFactorDangling    = 3.0
)

func ScoreCost(node models.AssetNode, finding *models.Finding) (directCost, riskCost float64) {
	directCost = estimatedListPrice[node.AssetType]
	return directCost, directCost * multiplierForFinding(models.ModuleOrphanedEdge, finding.Claimability)
}

func EnrichCostFromCE(ctx context.Context, findings []models.Finding, cfg config.Config) ([]models.Finding, error) {
	if !cfg.Cost.UseCUR {
		return findings, nil
	}
	if len(findings) == 0 {
		return findings, nil
	}

	awsCfg, err := loadAWSCfgForCE(ctx, cfg)
	if err != nil {
		warnCE("failed to load AWS config for cost enrichment", err)
		return findings, nil
	}
	client := newCostExplorerClient(awsCfg)

	end := ceNowUTC().Format("2006-01-02")
	start := ceNowUTC().AddDate(0, 0, -30).Format("2006-01-02")
	out, err := client.GetCostAndUsage(ctx, &costexplorer.GetCostAndUsageInput{
		TimePeriod: &cetypes.DateInterval{
			Start: &start,
			End:   &end,
		},
		Granularity: cetypes.GranularityMonthly,
		Metrics:     []string{"UnblendedCost"},
		GroupBy: []cetypes.GroupDefinition{
			{Type: cetypes.GroupDefinitionTypeDimension, Key: awsv2.String("LINKED_ACCOUNT")},
			{Type: cetypes.GroupDefinitionTypeDimension, Key: awsv2.String("SERVICE")},
		},
	})
	if err != nil {
		warnCE("Cost Explorer request failed; keeping static pricing", err)
		return findings, nil
	}

	costMap := buildCECostMap(out)
	if len(costMap) == 0 {
		return findings, nil
	}

	// Cost Explorer reports spend per account and service, not per resource, so it cannot price one finding. Dividing the
	// service's whole bill among the findings made each look like it cost hundreds of dollars. It is attached as context
	// instead, labelled as the whole service's spend, and the finding's own cost is left alone.
	enriched := make([]models.Finding, len(findings))
	copy(enriched, findings)
	for i := range enriched {
		service := serviceForFinding(enriched[i])
		if service == "" {
			continue
		}
		spend, ok := costMap[ceKey(enriched[i].AccountID, service)]
		if !ok {
			continue
		}
		evidence := make(map[string]any, len(enriched[i].Evidence)+2)
		for k, v := range enriched[i].Evidence {
			evidence[k] = v
		}
		evidence["account_service_name"] = service
		evidence["account_service_spend_usd_30d"] = spend
		enriched[i].Evidence = evidence
	}
	return enriched, nil
}

func buildCECostMap(out *costexplorer.GetCostAndUsageOutput) map[string]float64 {
	result := map[string]float64{}
	if out == nil {
		return result
	}
	for _, period := range out.ResultsByTime {
		for _, group := range period.Groups {
			if len(group.Keys) < 2 {
				continue
			}
			accountID := strings.TrimSpace(group.Keys[0])
			service := strings.TrimSpace(group.Keys[1])
			if accountID == "" || service == "" {
				continue
			}
			metric, ok := group.Metrics["UnblendedCost"]
			if !ok || metric.Amount == nil {
				continue
			}
			amount, err := parseAmount(*metric.Amount)
			if err != nil {
				continue
			}
			result[ceKey(accountID, service)] += amount
		}
	}
	return result
}

func parseAmount(raw string) (float64, error) {
	var value float64
	_, err := fmt.Sscanf(strings.TrimSpace(raw), "%f", &value)
	return value, err
}

func ceKey(accountID, service string) string {
	return accountID + "|" + service
}

func serviceForFinding(f models.Finding) string {
	// Restrict CE-derived service mapping to orphaned-edge findings.
	// External-access/trust findings should not inherit inferred service costs by default.
	if f.Module == models.ModuleExternalAccess {
		return ""
	}
	arn := strings.ToLower(f.AffectedARN)
	switch {
	case strings.Contains(arn, ":s3:::"):
		return "Amazon Simple Storage Service"
	case strings.Contains(arn, ":cloudfront:"):
		return "Amazon CloudFront"
	case strings.Contains(arn, ":route53:::"):
		return "Amazon Route 53"
	case strings.Contains(arn, ":apigateway:"):
		return "Amazon API Gateway"
	case strings.Contains(arn, ":acm:"):
		return "AWS Certificate Manager"
	case strings.Contains(arn, ":iam:"):
		return "AWS Identity and Access Management"
	default:
		return ""
	}
}

func multiplierForClaimability(c models.Claimability) float64 {
	return multiplierForFinding(models.ModuleOrphanedEdge, c)
}

func multiplierForFinding(module models.Module, c models.Claimability) float64 {
	if module != models.ModuleOrphanedEdge {
		return 1.0
	}
	switch c {
	case models.ClaimReclaimable:
		return riskFactorReclaimable
	case models.ClaimDangling:
		return riskFactorDangling
	default:
		return 1.0
	}
}

func warnCE(message string, err error) {
	if err != nil {
		slog.Warn(message, "error", err)
	}
}
