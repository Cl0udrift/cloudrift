package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/pricing"
	pricingtypes "github.com/aws/aws-sdk-go-v2/service/pricing/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/config"
)

// Before a scan runs: can the credentials do what the scan will ask? Each check makes the smallest read-only call
// the scan makes, so a missing permission shows now and not after a long scan. It tests the profile itself, in one
// Region; in an organization scan the member accounts are read by the audit role, which this does not test.

const preflightRegion = "us-east-1"

type check struct {
	ID, Group, Label, Permission string
	Run                          func(ctx context.Context) error
	// Untested says why a check is not run, for the ones that cost money to call.
	Untested string
}

var deniedCodes = map[string]bool{
	"AccessDenied": true, "AccessDeniedException": true, "UnauthorizedOperation": true, "UnauthorizedAccess": true,
	"AuthorizationError": true, "AccessDeniedFault": true, "NotAuthorizedException": true,
}

// classifyCheckError turns an AWS error into ok, denied or error, with a sentence for the person reading it.
func classifyCheckError(err error) (status, detail string) {
	if err == nil {
		return "ok", ""
	}
	var api smithy.APIError
	if errors.As(err, &api) {
		code := api.ErrorCode()
		switch {
		case deniedCodes[code] || strings.Contains(strings.ToLower(api.ErrorMessage()), "not authorized"):
			return "denied", "The credentials are not allowed to make this call."
		case code == "ReportNotPresent" || code == "ReportInProgress" || code == "AWSOrganizationsNotInUseException":
			return "ok", ""
		case code == "OptInRequired" || code == "SubscriptionRequiredException" || strings.Contains(strings.ToLower(api.ErrorMessage()), "not supported"):
			return "unavailable", "The service is not available to this account or Region."
		case code == "UnrecognizedClientException" || code == "ExpiredToken" || code == "InvalidClientTokenId" || code == "InvalidSignatureException":
			return "error", "The credentials were rejected. Check the profile or sign in again."
		}
		return "error", code + ": " + api.ErrorMessage()
	}
	return "error", err.Error()
}

func runChecks(ctx context.Context, cfg aws.Config) ([]schema.PreflightCheck, string) {
	cfg.Region = preflightRegion
	ec2c, elb, rdsc := ec2.NewFromConfig(cfg), elbv2.NewFromConfig(cfg), rds.NewFromConfig(cfg)
	iamc, r53, cf, s3c := iam.NewFromConfig(cfg), route53.NewFromConfig(cfg), cloudfront.NewFromConfig(cfg), s3.NewFromConfig(cfg)
	acmc, apig, cog := acm.NewFromConfig(cfg), apigateway.NewFromConfig(cfg), cognitoidentityprovider.NewFromConfig(cfg)
	org, pr := organizations.NewFromConfig(cfg), pricing.NewFromConfig(cfg)

	checks := []check{
		{ID: "iam_roles", Group: "Identity and access", Label: "IAM roles", Permission: "iam:ListRoles", Run: func(ctx context.Context) error {
			_, err := iamc.ListRoles(ctx, &iam.ListRolesInput{MaxItems: aws.Int32(1)})
			return err
		}},
		{ID: "iam_policies", Group: "Identity and access", Label: "IAM policy documents", Permission: "iam:GetAccountAuthorizationDetails", Run: func(ctx context.Context) error {
			_, err := iamc.GetAccountAuthorizationDetails(ctx, &iam.GetAccountAuthorizationDetailsInput{MaxItems: aws.Int32(1), Filter: []iamtypes.EntityType{iamtypes.EntityTypeLocalManagedPolicy}})
			return err
		}},
		{ID: "iam_credential_report", Group: "Identity and access", Label: "Credential report (MFA, key age)", Permission: "iam:GetCredentialReport", Run: func(ctx context.Context) error {
			_, err := iamc.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
			return err
		}},
		{ID: "security_groups", Group: "Trust, exposure and takeover", Label: "Security groups", Permission: "ec2:DescribeSecurityGroups", Run: func(ctx context.Context) error {
			_, err := ec2c.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{MaxResults: aws.Int32(5)})
			return err
		}},
		{ID: "load_balancers", Group: "Trust, exposure and takeover", Label: "Load balancers", Permission: "elasticloadbalancing:DescribeLoadBalancers", Run: func(ctx context.Context) error {
			_, err := elb.DescribeLoadBalancers(ctx, &elbv2.DescribeLoadBalancersInput{PageSize: aws.Int32(1)})
			return err
		}},
		{ID: "rds", Group: "Trust, exposure and takeover", Label: "RDS databases", Permission: "rds:DescribeDBInstances", Run: func(ctx context.Context) error {
			_, err := rdsc.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{MaxRecords: aws.Int32(20)})
			return err
		}},
		{ID: "route53", Group: "Trust, exposure and takeover", Label: "Route 53 zones and records", Permission: "route53:ListHostedZones", Run: func(ctx context.Context) error {
			_, err := r53.ListHostedZones(ctx, &route53.ListHostedZonesInput{MaxItems: aws.Int32(1)})
			return err
		}},
		{ID: "cloudfront", Group: "Trust, exposure and takeover", Label: "CloudFront distributions", Permission: "cloudfront:ListDistributions", Run: func(ctx context.Context) error {
			_, err := cf.ListDistributions(ctx, &cloudfront.ListDistributionsInput{MaxItems: aws.Int32(1)})
			return err
		}},
		{ID: "s3", Group: "Trust, exposure and takeover", Label: "S3 buckets", Permission: "s3:ListAllMyBuckets", Run: func(ctx context.Context) error {
			_, err := s3c.ListBuckets(ctx, &s3.ListBucketsInput{MaxBuckets: aws.Int32(1)})
			return err
		}},
		{ID: "acm", Group: "Trust, exposure and takeover", Label: "ACM certificates", Permission: "acm:ListCertificates", Run: func(ctx context.Context) error {
			_, err := acmc.ListCertificates(ctx, &acm.ListCertificatesInput{MaxItems: aws.Int32(1)})
			return err
		}},
		{ID: "apigateway", Group: "Trust, exposure and takeover", Label: "API Gateway custom domains", Permission: "apigateway:GET on /domainnames", Run: func(ctx context.Context) error {
			_, err := apig.GetDomainNames(ctx, &apigateway.GetDomainNamesInput{Limit: aws.Int32(1)})
			return err
		}},
		{ID: "cognito", Group: "Trust, exposure and takeover", Label: "Cognito domains", Permission: "cognito-idp:ListUserPools", Run: func(ctx context.Context) error {
			_, err := cog.ListUserPools(ctx, &cognitoidentityprovider.ListUserPoolsInput{MaxResults: aws.Int32(1)})
			return err
		}},
		{ID: "ebs", Group: "Unused resources and cost", Label: "EBS volumes", Permission: "ec2:DescribeVolumes", Run: func(ctx context.Context) error {
			_, err := ec2c.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{MaxResults: aws.Int32(5)})
			return err
		}},
		{ID: "addresses", Group: "Unused resources and cost", Label: "Elastic IP addresses", Permission: "ec2:DescribeAddresses", Run: func(ctx context.Context) error {
			_, err := ec2c.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
			return err
		}},
		{ID: "pricing", Group: "Unused resources and cost", Label: "AWS list prices", Permission: "pricing:GetProducts", Run: func(ctx context.Context) error {
			_, err := pr.GetProducts(ctx, &pricing.GetProductsInput{ServiceCode: aws.String("AmazonEC2"), MaxResults: aws.Int32(1), Filters: []pricingtypes.Filter{{Type: pricingtypes.FilterTypeTermMatch, Field: aws.String("volumeApiName"), Value: aws.String("gp3")}}})
			return err
		}},
		{ID: "billing", Group: "Unused resources and cost", Label: "Your billing (Cost Explorer)", Permission: "ce:GetCostAndUsage", Untested: "Cost Explorer charges a cent per request, so it is not tested here. The scan reads it only when \"Attach account spend\" is on."},
		{ID: "organization", Group: "Scope", Label: "AWS Organization", Permission: "organizations:DescribeOrganization", Run: func(ctx context.Context) error {
			_, err := org.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
			return err
		}},
	}

	out := make([]schema.PreflightCheck, len(checks))
	var wg sync.WaitGroup
	for i, c := range checks {
		out[i] = schema.PreflightCheck{ID: c.ID, Group: c.Group, Label: c.Label, Permission: c.Permission}
		if c.Run == nil {
			out[i].Status, out[i].Detail = "untested", c.Untested
			continue
		}
		wg.Add(1)
		go func(i int, c check) {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			out[i].Status, out[i].Detail = classifyCheckError(c.Run(cctx))
		}(i, c)
	}
	wg.Wait()

	account := ""
	if id, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err == nil {
		account = aws.ToString(id.Account)
	}
	return out, account
}

// Preflight checks what a scan with this profile will be able to read.
func (s *scanControlCenter) Preflight() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg, err := config.Load(s.configPath)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "config_load_error", "failed to load runtime config", nil)
			return
		}
		var req schema.ValidateProfileRequest
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req)
		profile := strings.TrimSpace(req.Profile)
		if profile == "" {
			profile = defaultProfile(cfg)
		}
		var opts []func(*awsconfig.LoadOptions) error
		if profile != "" {
			opts = append(opts, awsconfig.WithSharedConfigProfile(profile))
		}
		awsCfg, err := awsconfig.LoadDefaultConfig(r.Context(), opts...)
		if err != nil {
			writeJSON(w, http.StatusOK, schema.PreflightResponse{Profile: profile, Checks: []schema.PreflightCheck{}, Notes: []string{"The profile could not be loaded: " + err.Error()}})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()
		// Credentials that cannot sign in fail every check the same way; say that once.
		signCfg := awsCfg
		signCfg.Region = preflightRegion
		if _, err := sts.NewFromConfig(signCfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err != nil {
			why := "The profile could not sign in."
			if _, d := classifyCheckError(err); d != "" {
				why = d
			}
			writeJSON(w, http.StatusOK, schema.PreflightResponse{Profile: profile, Checks: []schema.PreflightCheck{}, Notes: []string{why + " Nothing else was checked. Use \"Test sign-in only\", or sign in again, then retry."}})
			return
		}
		checks, account := runChecks(ctx, awsCfg)
		resp := schema.PreflightResponse{Profile: profile, AccountID: account, Region: preflightRegion, Checks: checks, Notes: []string{"Checked in " + preflightRegion + " with the smallest read each check needs. A Region that blocks a service by policy can still fail during the scan."}}
		if strings.TrimSpace(cfg.AWS.OrgRoleName) != "" {
			resp.Notes = append(resp.Notes, "In an organization scan the member accounts are read by the audit role, which this does not test. It tests the profile only.")
		}
		for _, c := range checks {
			switch c.Status {
			case "ok":
				resp.Summary.OK++
			case "denied":
				resp.Summary.Denied++
			case "untested":
				resp.Summary.Untested++
			default:
				resp.Summary.Problems++
			}
		}
		writeJSON(w, http.StatusOK, resp)
	}
}
