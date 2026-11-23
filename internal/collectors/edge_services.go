package collectors

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// Names that someone can register again, and the addresses and certificates tied to them. Every call is a
// read-only List or Describe. They exist so a DNS record that points at one can be checked against what the
// scanned accounts really hold.

type AddressAPI interface {
	DescribeAddresses(context.Context, *ec2.DescribeAddressesInput, ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error)
	DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error)
}

type ACMAPI interface {
	ListCertificates(context.Context, *acm.ListCertificatesInput, ...func(*acm.Options)) (*acm.ListCertificatesOutput, error)
	DescribeCertificate(context.Context, *acm.DescribeCertificateInput, ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error)
}

type APIGatewayAPI interface {
	GetDomainNames(context.Context, *apigateway.GetDomainNamesInput, ...func(*apigateway.Options)) (*apigateway.GetDomainNamesOutput, error)
}

type APIGatewayV2API interface {
	GetDomainNames(context.Context, *apigatewayv2.GetDomainNamesInput, ...func(*apigatewayv2.Options)) (*apigatewayv2.GetDomainNamesOutput, error)
}

type CognitoAPI interface {
	ListUserPools(context.Context, *cognitoidentityprovider.ListUserPoolsInput, ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ListUserPoolsOutput, error)
	DescribeUserPool(context.Context, *cognitoidentityprovider.DescribeUserPoolInput, ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.DescribeUserPoolOutput, error)
}

const (
	maxCertificates = 500
	maxUserPools    = 200
)

// Collector names recorded in collection_status. A takeover finding that rests on absence is raised only when every
// one of these succeeded.
const (
	CollectorPublicAddresses = "public_addresses"
	CollectorACM             = "acm"
	CollectorAPIGateway      = "apigateway"
	CollectorCognito         = "cognito"
)

func collectEdgeServices(ctx context.Context, accountID, region string, c WorkloadClients, at time.Time) ([]models.AssetNode, []models.Relationship) {
	var assets []models.AssetNode
	run := func(name string, fn func() ([]models.AssetNode, error)) {
		nodes, err := fn()
		if err != nil {
			status, detail := serviceStatus(err)
			assets = append(assets, CollectionStatus(accountID, region, name, "regional", status, detail))
			return
		}
		assets = append(assets, nodes...)
		assets = append(assets, CollectionStatus(accountID, region, name, "regional", "succeeded", ""))
	}
	if c.Addresses != nil {
		run(CollectorPublicAddresses, func() ([]models.AssetNode, error) {
			return collectPublicAddresses(ctx, accountID, region, c.Addresses, at)
		})
	}
	if c.ACM != nil {
		run(CollectorACM, func() ([]models.AssetNode, error) { return collectCertificates(ctx, accountID, region, c.ACM, at) })
	}
	if c.APIGateway != nil || c.APIGatewayV2 != nil {
		run(CollectorAPIGateway, func() ([]models.AssetNode, error) {
			return collectAPIDomains(ctx, accountID, region, c.APIGateway, c.APIGatewayV2, at)
		})
	}
	if c.Cognito != nil {
		run(CollectorCognito, func() ([]models.AssetNode, error) {
			return collectUserPoolDomains(ctx, accountID, region, c.Cognito, at)
		})
	}
	return assets, nil
}

// collectPublicAddresses records every public IPv4 address the account holds in the Region: Elastic IPs, and the
// addresses on network interfaces (which also covers NAT gateways and load balancers). One evidence asset per
// Region keeps the inventory free of an entry per address.
func collectPublicAddresses(ctx context.Context, accountID, region string, api AddressAPI, at time.Time) ([]models.AssetNode, error) {
	ips := map[string]bool{}
	addrs, err := api.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err != nil {
		return nil, err
	}
	for _, a := range addrs.Addresses {
		if ip := awsv2.ToString(a.PublicIp); ip != "" {
			ips[ip] = true
		}
	}
	var token *string
	for {
		out, err := api.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{NextToken: token})
		if err != nil {
			return nil, err
		}
		for _, ni := range out.NetworkInterfaces {
			if ni.Association != nil {
				if ip := awsv2.ToString(ni.Association.PublicIp); ip != "" {
					ips[ip] = true
				}
			}
			for _, p := range ni.PrivateIpAddresses {
				if p.Association != nil {
					if ip := awsv2.ToString(p.Association.PublicIp); ip != "" {
						ips[ip] = true
					}
				}
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	list := make([]string, 0, len(ips))
	for ip := range ips {
		list = append(list, ip)
	}
	sort.Strings(list)
	return []models.AssetNode{{
		ARN: "arn:cloudrift:public-addresses:::" + accountID + ":" + region, AssetType: models.AssetPublicAddressSet, Name: "public addresses " + region,
		AccountID: accountID, Region: region, Properties: map[string]any{"addresses": list, "collected_at": at.Format(time.RFC3339), "source_api": "ec2:DescribeAddresses,DescribeNetworkInterfaces"},
	}}, nil
}

func collectCertificates(ctx context.Context, accountID, region string, api ACMAPI, at time.Time) ([]models.AssetNode, error) {
	var arns []string
	var token *string
	for {
		out, err := api.ListCertificates(ctx, &acm.ListCertificatesInput{NextToken: token})
		if err != nil {
			return nil, err
		}
		for _, c := range out.CertificateSummaryList {
			arns = append(arns, awsv2.ToString(c.CertificateArn))
		}
		if out.NextToken == nil || *out.NextToken == "" || len(arns) >= maxCertificates {
			break
		}
		token = out.NextToken
	}
	var nodes []models.AssetNode
	for _, arn := range arns {
		d, err := api.DescribeCertificate(ctx, &acm.DescribeCertificateInput{CertificateArn: awsv2.String(arn)})
		if err != nil {
			return nil, err
		}
		c := d.Certificate
		if c == nil {
			continue
		}
		var validation []string
		for _, o := range c.DomainValidationOptions {
			if o.ResourceRecord != nil {
				validation = append(validation, strings.TrimSuffix(strings.ToLower(awsv2.ToString(o.ResourceRecord.Name)), "."))
			}
		}
		props := map[string]any{
			"domain": awsv2.ToString(c.DomainName), "status": string(c.Status), "type": string(c.Type), "in_use_by": c.InUseBy,
			"alternative_names": c.SubjectAlternativeNames, "validation_records": validation, "renewal_eligibility": string(c.RenewalEligibility),
			"collected_at": at.Format(time.RFC3339), "source_api": "acm:DescribeCertificate",
		}
		if c.NotAfter != nil {
			props["not_after"] = c.NotAfter.UTC().Format(time.RFC3339)
		}
		nodes = append(nodes, models.AssetNode{ARN: arn, AssetType: models.AssetACMCert, Name: awsv2.ToString(c.DomainName), AccountID: accountID, Region: region, Properties: props})
	}
	return nodes, nil
}

func collectAPIDomains(ctx context.Context, accountID, region string, v1 APIGatewayAPI, v2 APIGatewayV2API, at time.Time) ([]models.AssetNode, error) {
	var nodes []models.AssetNode
	add := func(name string, regional []string, api string) {
		nodes = append(nodes, models.AssetNode{
			ARN: fmt.Sprintf("arn:aws:apigateway:%s::/domainnames/%s", region, name), AssetType: models.AssetAPIGatewayDomain, Name: name, AccountID: accountID, Region: region,
			Properties: map[string]any{"regional_domain_names": regional, "api_version": api, "collected_at": at.Format(time.RFC3339)},
		})
	}
	if v1 != nil {
		var pos *string
		for {
			out, err := v1.GetDomainNames(ctx, &apigateway.GetDomainNamesInput{Position: pos})
			if err != nil {
				return nil, err
			}
			for _, d := range out.Items {
				add(awsv2.ToString(d.DomainName), nonEmpty(awsv2.ToString(d.RegionalDomainName), awsv2.ToString(d.DistributionDomainName)), "rest")
			}
			if out.Position == nil || *out.Position == "" {
				break
			}
			pos = out.Position
		}
	}
	if v2 != nil {
		var tok *string
		for {
			out, err := v2.GetDomainNames(ctx, &apigatewayv2.GetDomainNamesInput{NextToken: tok})
			if err != nil {
				return nil, err
			}
			for _, d := range out.Items {
				var names []string
				for _, cfg := range d.DomainNameConfigurations {
					names = append(names, nonEmpty(awsv2.ToString(cfg.ApiGatewayDomainName))...)
				}
				add(awsv2.ToString(d.DomainName), names, "http")
			}
			if out.NextToken == nil || *out.NextToken == "" {
				break
			}
			tok = out.NextToken
		}
	}
	return nodes, nil
}

func collectUserPoolDomains(ctx context.Context, accountID, region string, api CognitoAPI, at time.Time) ([]models.AssetNode, error) {
	var ids []string
	var token *string
	for {
		out, err := api.ListUserPools(ctx, &cognitoidentityprovider.ListUserPoolsInput{MaxResults: awsv2.Int32(60), NextToken: token})
		if err != nil {
			return nil, err
		}
		for _, p := range out.UserPools {
			ids = append(ids, awsv2.ToString(p.Id))
		}
		if out.NextToken == nil || *out.NextToken == "" || len(ids) >= maxUserPools {
			break
		}
		token = out.NextToken
	}
	var nodes []models.AssetNode
	for _, id := range ids {
		d, err := api.DescribeUserPool(ctx, &cognitoidentityprovider.DescribeUserPoolInput{UserPoolId: awsv2.String(id)})
		if err != nil {
			return nil, err
		}
		p := d.UserPool
		if p == nil {
			continue
		}
		prefix, custom := awsv2.ToString(p.Domain), awsv2.ToString(p.CustomDomain)
		if prefix == "" && custom == "" {
			continue
		}
		props := map[string]any{"user_pool_id": id, "domain_prefix": prefix, "custom_domain": custom, "collected_at": at.Format(time.RFC3339), "source_api": "cognito-idp:DescribeUserPool"}
		if prefix != "" {
			props["hosted_ui_host"] = prefix + ".auth." + region + ".amazoncognito.com"
		}
		nodes = append(nodes, models.AssetNode{ARN: fmt.Sprintf("arn:aws:cognito-idp:%s:%s:userpool/%s", region, accountID, id), AssetType: models.AssetCognitoUserPool, Name: awsv2.ToString(p.Name), AccountID: accountID, Region: region, Properties: props})
	}
	return nodes, nil
}

func nonEmpty(vals ...string) []string {
	var out []string
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
