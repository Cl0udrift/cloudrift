package collectors

import (
	"context"
	"strings"
	"sync"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"

	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func CollectDNS(ctx context.Context, accounts []Account) ([]models.AssetNode, error) {
	return CollectDNSWithConfig(ctx, config.Default(), accounts)
}

func CollectDNSWithConfig(ctx context.Context, cfg *config.Config, accounts []Account) ([]models.AssetNode, error) {
	var out []models.AssetNode
	sem := make(chan struct{}, max(1, cfg.Scan.RoleAssumptionConcurrency))
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error

	for _, account := range accounts {
		account := account
		if account.Session == nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			client := route53.NewFromConfig(*account.Session)
			zp := route53.NewListHostedZonesPaginator(client, &route53.ListHostedZonesInput{})
			var local []models.AssetNode
			for zp.HasMorePages() {
				zonePage, err := zp.NextPage(ctx)
				if err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					out = append(out, CollectionStatus(account.ID, "", "route53", "global", "failed", err.Error()))
					mu.Unlock()
					return
				}
				for _, zone := range zonePage.HostedZones {
					rp := route53.NewListResourceRecordSetsPaginator(client, &route53.ListResourceRecordSetsInput{
						HostedZoneId: zone.Id,
					})
					for rp.HasMorePages() {
						records, err := rp.NextPage(ctx)
						if err != nil {
							mu.Lock()
							if firstErr == nil {
								firstErr = err
							}
							out = append(out, CollectionStatus(account.ID, "", "route53", "global", "failed", err.Error()))
							mu.Unlock()
							return
						}
						for _, rr := range records.ResourceRecordSets {
							if rr.Type == types.RRTypeSoa || rr.Type == types.RRTypeNs {
								continue
							}
							name := strings.TrimSuffix(awsv2.ToString(rr.Name), ".")
							target := recordTarget(rr)
							local = append(local, models.AssetNode{
								ARN:       "arn:aws:route53:::" + strings.TrimPrefix(awsv2.ToString(zone.Id), "/hostedzone/") + "/" + name,
								AssetType: models.AssetDNSRecord,
								Name:      name,
								AccountID: account.ID,
								Region:    "global",
								Properties: map[string]any{
									"type":           string(rr.Type),
									"value":          target,
									"zone_id":        strings.TrimPrefix(awsv2.ToString(zone.Id), "/hostedzone/"),
									"private":        zone.Config != nil && zone.Config.PrivateZone,
									"target_service": classifyTargetService(target),
									"dns_status":     "unknown",
								},
							})
						}
					}
				}
			}
			mu.Lock()
			out = append(out, local...)
			out = append(out, CollectionStatus(account.ID, "", "route53", "global", "succeeded", ""))
			mu.Unlock()
		}()
	}
	wg.Wait()
	warnPartial(ctx, "dns", firstErr)
	return out, nil
}

func recordTarget(rr types.ResourceRecordSet) string {
	if rr.AliasTarget != nil && rr.AliasTarget.DNSName != nil {
		return strings.TrimSuffix(*rr.AliasTarget.DNSName, ".")
	}
	if len(rr.ResourceRecords) > 0 && rr.ResourceRecords[0].Value != nil {
		v := strings.Trim(*rr.ResourceRecords[0].Value, "\"")
		return strings.TrimSuffix(v, ".")
	}
	return ""
}

func classifyTargetService(target string) string {
	t := strings.ToLower(target)
	switch {
	case strings.Contains(t, ".s3-website-") || strings.Contains(t, ".s3-website."):
		return "s3_website"
	case strings.HasSuffix(t, ".cloudfront.net"):
		return "cloudfront"
	case strings.Contains(t, ".execute-api.") && strings.Contains(t, ".amazonaws.com"):
		return "apigateway"
	case strings.HasSuffix(t, ".elb.amazonaws.com"):
		return "alb"
	case strings.HasSuffix(t, ".elasticbeanstalk.com"):
		return "elasticbeanstalk"
	case strings.Contains(t, "."):
		return "third_party"
	default:
		return "unknown"
	}
}
