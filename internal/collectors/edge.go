package collectors

import (
	"context"
	"strings"
	"sync"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"

	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func CollectEdge(ctx context.Context, accounts []Account) ([]models.AssetNode, []models.Relationship, error) {
	return CollectEdgeWithConfig(ctx, config.Default(), accounts)
}

func CollectEdgeWithConfig(ctx context.Context, cfg *config.Config, accounts []Account) ([]models.AssetNode, []models.Relationship, error) {
	var nodes []models.AssetNode
	var rels []models.Relationship
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
			c := cloudfront.NewFromConfig(*account.Session)
			p := cloudfront.NewListDistributionsPaginator(c, &cloudfront.ListDistributionsInput{})
			var localNodes []models.AssetNode
			var localRels []models.Relationship
			for p.HasMorePages() {
				page, err := p.NextPage(ctx)
				if err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					nodes = append(nodes, CollectionStatus(account.ID, "", "cloudfront", "global", "failed", err.Error()))
					mu.Unlock()
					return
				}
				if page.DistributionList == nil {
					continue
				}
				for _, d := range page.DistributionList.Items {
					arn := awsv2.ToString(d.ARN)
					name := awsv2.ToString(d.DomainName)
					var alt []string
					if d.Aliases.Items != nil {
						alt = d.Aliases.Items
					}
					node := models.AssetNode{
						ARN:       arn,
						AssetType: models.AssetCloudFrontDist,
						Name:      name,
						AccountID: account.ID,
						Region:    "global",
						Properties: map[string]any{
							"domain":            name,
							"enabled":           awsv2.ToBool(d.Enabled),
							"price_class":       string(d.PriceClass),
							"alternate_domains": alt,
							"origin":            firstOrigin(d),
						},
					}
					localNodes = append(localNodes, node)

					if d.ViewerCertificate != nil && d.ViewerCertificate.ACMCertificateArn != nil {
						localRels = append(localRels, models.Relationship{
							SourceARN: arn, TargetARN: *d.ViewerCertificate.ACMCertificateArn, RelType: models.RelUsesCert,
						})
					}
					origin := firstOrigin(d)
					if strings.Contains(origin, ".s3.") || strings.Contains(origin, ".s3-") {
						localRels = append(localRels, models.Relationship{
							SourceARN: arn, TargetARN: "arn:aws:s3:::" + bucketFromOrigin(origin), RelType: models.RelFronts,
						})
					}
				}
			}
			mu.Lock()
			nodes = append(nodes, localNodes...)
			nodes = append(nodes, CollectionStatus(account.ID, "", "cloudfront", "global", "succeeded", ""))
			rels = append(rels, localRels...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	warnPartial(ctx, "edge", firstErr)
	return nodes, rels, nil
}

func firstOrigin(d cftypes.DistributionSummary) string {
	if len(d.Origins.Items) > 0 {
		return awsv2.ToString(d.Origins.Items[0].DomainName)
	}
	return ""
}

func bucketFromOrigin(origin string) string {
	parts := strings.Split(origin, ".")
	if len(parts) > 0 {
		return parts[0]
	}
	return origin
}
