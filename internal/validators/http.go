package validators

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/models"
)

type ValidationResult struct {
	DNSStatus string `json:"dns_status"`
	// TargetDNSStatus is the lookup of the record's target when the name itself did not resolve.
	TargetDNSStatus  string `json:"target_dns_status,omitempty"`
	HTTPStatus       int    `json:"http_status"`
	TLSValid         bool   `json:"tls_valid"`
	CDNDetected      bool   `json:"cdn_detected"`
	CDNVendor        string `json:"cdn_vendor"`
	ErrorFingerprint string `json:"error_fingerprint"`
	// Claimable is true when the matched fingerprint indicates the backing name is
	// takeover-able (e.g. a deleted S3 bucket or an unclaimed third-party app/site),
	// as opposed to a merely misconfigured-but-AWS-controlled endpoint.
	Claimable   bool   `json:"claimable"`
	BodySnippet string `json:"body_snippet"`
}

type DNSResolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

func ValidateAssets(ctx context.Context, nodes []models.AssetNode, concurrency int, noHTTP bool, timeout time.Duration, userAgent string) map[string]ValidationResult {
	if concurrency < 1 {
		concurrency = 1
	}
	return validateAssetsWithClients(ctx, nodes, concurrency, noHTTP, timeout, userAgent, net.DefaultResolver, &http.Client{Timeout: timeout}, &net.Dialer{Timeout: timeout})
}

func ValidateAssetsWithConfig(ctx context.Context, cfg *config.Config, nodes []models.AssetNode, noHTTP bool) map[string]ValidationResult {
	return ValidateAssets(ctx, nodes, cfg.Scan.HTTPProbeConcurrency, noHTTP, time.Duration(cfg.Scan.HTTPTimeoutSeconds)*time.Second, cfg.Scan.UserAgent)
}

func validateAssetsWithClients(
	ctx context.Context,
	nodes []models.AssetNode,
	concurrency int,
	noHTTP bool,
	timeout time.Duration,
	userAgent string,
	resolver DNSResolver,
	client *http.Client,
	dialer *net.Dialer,
) map[string]ValidationResult {
	results := make(map[string]ValidationResult, len(nodes))
	sem := make(chan struct{}, concurrency)
	ch := make(chan struct {
		arn string
		res ValidationResult
	}, len(nodes))

	for _, n := range nodes {
		n := n
		go func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			res := validateNode(ctx, n, noHTTP, timeout, userAgent, resolver, client, dialer)
			ch <- struct {
				arn string
				res ValidationResult
			}{arn: n.ARN, res: res}
		}()
	}
	for range nodes {
		r := <-ch
		results[r.arn] = r.res
	}
	return results
}

func validateNode(
	ctx context.Context,
	node models.AssetNode,
	noHTTP bool,
	timeout time.Duration,
	userAgent string,
	resolver DNSResolver,
	client *http.Client,
	dialer *net.Dialer,
) ValidationResult {
	if typ, _ := node.Properties["type"].(string); typ == "NS" {
		return validateDelegation(ctx, node, resolver)
	}
	host, targetURL, scheme := targetForProbe(node)
	if host == "" {
		return ValidationResult{DNSStatus: "unknown"}
	}
	if _, err := resolver.LookupHost(ctx, host); err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok {
			switch {
			case dnsErr.IsNotFound:
				if res, deleted := targetDeleted(ctx, node, resolver); deleted {
					return res
				}
				return ValidationResult{DNSStatus: "nxdomain", ErrorFingerprint: "dns_nxdomain"}
			case dnsErr.IsTimeout:
				return ValidationResult{DNSStatus: "timeout"}
			}
		}
		return ValidationResult{DNSStatus: "servfail"}
	}
	res := ValidationResult{DNSStatus: "resolved"}
	if noHTTP {
		return res
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, targetURL, nil)
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		req, _ = http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		req.Header.Set("User-Agent", userAgent)
		resp, err = client.Do(req)
	}
	if err != nil {
		return res
	}
	defer resp.Body.Close()
	res.HTTPStatus = resp.StatusCode
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	res.BodySnippet = string(snippet)
	target, _ := node.Properties["value"].(string)
	if sig, ok := matchTakeoverSignature(resp.StatusCode, resp.Header.Get("Server"), res.BodySnippet, target); ok {
		res.ErrorFingerprint = sig.ID
		res.Claimable = sig.Claimable
	}
	if strings.Contains(strings.ToLower(host), "cloudfront.net") {
		res.CDNDetected = true
		res.CDNVendor = "cloudfront"
	}
	if scheme == "https" {
		conn, err := tls.DialWithDialer(dialer, "tcp", host+":443", &tls.Config{ServerName: host})
		if err == nil {
			res.TLSValid = true
			_ = conn.Close()
		}
	}
	return res
}

func targetForProbe(node models.AssetNode) (host, targetURL, scheme string) {
	if raw, ok := node.Properties["probe_url"].(string); ok && raw != "" {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			return u.Hostname(), raw, u.Scheme
		}
	}
	host = node.Name
	scheme = "https"
	if s, ok := node.Properties["scheme"].(string); ok && s != "" {
		scheme = strings.ToLower(s)
	}
	targetURL = scheme + "://" + host
	return host, targetURL, scheme
}

// TakeoverSignature is one entry in the extensible fingerprint catalog. A response
// matches when every specified condition holds (status, Server substring, and any one
// of the body substrings). Claimable distinguishes a takeover-able backing name from a
// merely misconfigured-but-controlled endpoint.
type TakeoverSignature struct {
	ID         string
	Service    string
	Status     int      // 0 = match any status
	ServerHas  string   // lowercased substring required in the Server header (empty = ignore)
	BodyHasAny []string // response matches if the body contains ANY of these (empty = ignore)
	// TargetSuffixes pair a body match with the record's target, so a page that merely says "not found" is only
	// counted when the name really points at that service. Empty = any target (AWS-native signatures).
	TargetSuffixes []string
	Claimable      bool
}

// takeoverSignatures is the ordered fingerprint catalog. First match wins, so place
// more specific signatures before broader ones. Add new edge/third-party takeover
// surfaces here — detection coverage scales by extending this table.
var takeoverSignatures = []TakeoverSignature{
	// AWS-native
	{ID: "s3_bucket_deleted", Service: "s3", BodyHasAny: []string{"<Code>NoSuchBucket</Code>"}, Claimable: true},
	{ID: "s3_bucket_exists_private", Service: "s3", Status: 403, ServerHas: "s3", Claimable: false},
	{ID: "cloudfront_origin_error", Service: "cloudfront", BodyHasAny: []string{"The request could not be satisfied"}, Claimable: false},
	{ID: "aws_endpoint_controlled", Service: "aws", BodyHasAny: []string{"<Code>InvalidClientTokenId</Code>"}, Claimable: false},
	{ID: "apigateway_missing_mapping", Service: "apigateway", Status: 403, BodyHasAny: []string{`{"message":"Forbidden"}`}, Claimable: false},
	// Third-party CNAME takeover surfaces (a name in Route 53 pointing at a SaaS). Each is paired with the CNAME
	// target suffix so a body match alone is never enough. Texts follow the public can-i-take-over-xyz list and
	// have not been checked against live accounts.
	{ID: "github_pages_unclaimed", Service: "github_pages", BodyHasAny: []string{"There isn't a GitHub Pages site here"}, TargetSuffixes: []string{"github.io"}, Claimable: true},
	{ID: "heroku_no_such_app", Service: "heroku", BodyHasAny: []string{"No such app", "no-such-app.html"}, TargetSuffixes: []string{"herokuapp.com", "herokudns.com"}, Claimable: true},
	{ID: "shopify_unavailable", Service: "shopify", BodyHasAny: []string{"Sorry, this shop is currently unavailable"}, TargetSuffixes: []string{"myshopify.com"}, Claimable: true},
	{ID: "fastly_unknown_domain", Service: "fastly", BodyHasAny: []string{"Fastly error: unknown domain"}, TargetSuffixes: []string{"fastly.net"}, Claimable: true},
	{ID: "zendesk_help_center_closed", Service: "zendesk", BodyHasAny: []string{"Help Center Closed"}, TargetSuffixes: []string{"zendesk.com"}, Claimable: true},
	{ID: "bitbucket_repo_not_found", Service: "bitbucket", BodyHasAny: []string{"Repository not found"}, TargetSuffixes: []string{"bitbucket.io"}, Claimable: true},
	{ID: "surge_project_not_found", Service: "surge", BodyHasAny: []string{"project not found"}, TargetSuffixes: []string{"surge.sh"}, Claimable: true},
	{ID: "ghost_unclaimed", Service: "ghost", BodyHasAny: []string{"The thing you were looking for is no longer here, or never was"}, TargetSuffixes: []string{"ghost.io"}, Claimable: true},
	{ID: "tumblr_unclaimed", Service: "tumblr", BodyHasAny: []string{"Whatever you were looking for doesn't currently exist at this address"}, TargetSuffixes: []string{"domains.tumblr.com"}, Claimable: true},
	{ID: "pantheon_unknown_site", Service: "pantheon", BodyHasAny: []string{"The gods are wise, but do not know of the site which you seek"}, TargetSuffixes: []string{"pantheonsite.io"}, Claimable: true},
	{ID: "readme_unclaimed", Service: "readme", BodyHasAny: []string{"The creators of this project are still working on making everything perfect"}, TargetSuffixes: []string{"readme.io"}, Claimable: true},
	{ID: "helpjuice_unclaimed", Service: "helpjuice", BodyHasAny: []string{"We could not find what you're looking for"}, TargetSuffixes: []string{"helpjuice.com"}, Claimable: true},
	{ID: "helpscout_unclaimed", Service: "helpscout", BodyHasAny: []string{"No settings were found for this company"}, TargetSuffixes: []string{"helpscoutdocs.com"}, Claimable: true},
	{ID: "uservoice_available", Service: "uservoice", BodyHasAny: []string{"This UserVoice subdomain is currently available"}, TargetSuffixes: []string{"uservoice.com"}, Claimable: true},
	{ID: "wordpress_com_unclaimed", Service: "wordpress", BodyHasAny: []string{"Do you want to register"}, TargetSuffixes: []string{"wordpress.com"}, Claimable: true},
	{ID: "intercom_unclaimed", Service: "intercom", BodyHasAny: []string{"This page is reserved for artistic dogs"}, TargetSuffixes: []string{"custom.intercom.help"}, Claimable: true},
	{ID: "agilecrm_unavailable", Service: "agilecrm", BodyHasAny: []string{"Sorry, this page is no longer available"}, TargetSuffixes: []string{"agilecrm.com"}, Claimable: true},
	{ID: "campaignmonitor_unclaimed", Service: "campaignmonitor", BodyHasAny: []string{"Trying to access your account?"}, TargetSuffixes: []string{"createsend.com"}, Claimable: true},
}

func matchTakeoverSignature(status int, server, body, target string) (TakeoverSignature, bool) {
	serverLower := strings.ToLower(server)
	target = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(target)), ".")
	for _, s := range takeoverSignatures {
		if len(s.TargetSuffixes) > 0 && !hasAnySuffix(target, s.TargetSuffixes) {
			continue
		}
		if s.Status != 0 && status != s.Status {
			continue
		}
		if s.ServerHas != "" && !strings.Contains(serverLower, s.ServerHas) {
			continue
		}
		if len(s.BodyHasAny) > 0 {
			matched := false
			for _, sub := range s.BodyHasAny {
				if strings.Contains(body, sub) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		return s, true
	}
	return TakeoverSignature{}, false
}

// fingerprint returns the matched signature ID (or "") — retained for the evidence map
// and for callers that only need the legacy string form.
func fingerprint(status int, server, body string) string {
	if s, ok := matchTakeoverSignature(status, server, body, ""); ok {
		return s.ID
	}
	return ""
}

func dnsTimeoutErr() error {
	return &net.DNSError{IsTimeout: true}
}

func dnsNotFoundErr() error {
	return &net.DNSError{IsNotFound: true}
}

func hasAnySuffix(target string, suffixes []string) bool {
	for _, suf := range suffixes {
		if target == suf || strings.HasSuffix(target, "."+suf) {
			return true
		}
	}
	return false
}

// deletedTargetServices are the AWS services whose per-resource DNS name disappears when the resource is
// deleted. Only Elastic Beanstalk names can then be registered again by anyone; the others are left dangling.
var deletedTargetServices = map[string]bool{"elasticbeanstalk": true, "alb": true, "apigateway": true, "cloudfront": true}

// targetDeleted reports a record whose own name no longer resolves because the AWS resource it points at is gone.
func targetDeleted(ctx context.Context, node models.AssetNode, resolver DNSResolver) (ValidationResult, bool) {
	service, _ := node.Properties["target_service"].(string)
	target, _ := node.Properties["value"].(string)
	if !deletedTargetServices[service] || target == "" {
		return ValidationResult{}, false
	}
	_, err := resolver.LookupHost(ctx, target)
	dnsErr, ok := err.(*net.DNSError)
	if err == nil || !ok || !dnsErr.IsNotFound {
		return ValidationResult{}, false
	}
	return ValidationResult{DNSStatus: "nxdomain", TargetDNSStatus: "nxdomain", ErrorFingerprint: "target_deleted_" + service, Claimable: service == "elasticbeanstalk"}, true
}
