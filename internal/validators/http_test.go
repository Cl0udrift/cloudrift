package validators

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Zero0x00/cloudrift/internal/models"
)

type fakeResolver struct {
	err error
}

func (f fakeResolver) LookupHost(_ context.Context, _ string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return []string{"127.0.0.1"}, nil
}

type failHeadTransport struct {
	next http.RoundTripper
}

func (t failHeadTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodHead {
		return nil, errors.New("head blocked")
	}
	return t.next.RoundTrip(req)
}

func TestFingerprint(t *testing.T) {
	if got := fingerprint(404, "", "<Code>NoSuchBucket</Code>"); got != "s3_bucket_deleted" {
		t.Fatalf("unexpected fingerprint: %s", got)
	}
	if got := fingerprint(403, "AmazonS3", ""); got != "s3_bucket_exists_private" {
		t.Fatalf("unexpected fingerprint: %s", got)
	}
}

func TestTakeoverSignatureCatalog(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		server    string
		body      string
		wantID    string
		wantClaim bool
	}{
		{"s3 deleted", 404, "AmazonS3", "<Code>NoSuchBucket</Code>", "s3_bucket_deleted", true},
		{"s3 private exists", 403, "AmazonS3", "<Code>AccessDenied</Code>", "s3_bucket_exists_private", false},
		{"cloudfront origin error", 403, "CloudFront", "The request could not be satisfied", "cloudfront_origin_error", false},
		{"apigateway missing mapping", 403, "", `{"message":"Forbidden"}`, "apigateway_missing_mapping", false},
		{"github pages unclaimed", 404, "GitHub.com", "There isn't a GitHub Pages site here.", "github_pages_unclaimed", true},
		{"heroku no such app", 404, "Cowboy", "<title>No such app</title>", "heroku_no_such_app", true},
		{"shopify unavailable", 404, "", "Sorry, this shop is currently unavailable.", "shopify_unavailable", true},
		{"fastly unknown domain", 500, "", "Fastly error: unknown domain: docs.example.com", "fastly_unknown_domain", true},
		{"zendesk closed", 404, "", "<title>Help Center Closed</title>", "zendesk_help_center_closed", true},
		{"healthy page no match", 200, "nginx", "<html>hello</html>", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sig, ok := matchTakeoverSignature(tc.status, tc.server, tc.body, map[string]string{"github_pages_unclaimed": "org.github.io", "heroku_no_such_app": "x.herokuapp.com", "shopify_unavailable": "shops.myshopify.com", "fastly_unknown_domain": "x.global.prod.fastly.net", "zendesk_help_center_closed": "acme.zendesk.com"}[tc.wantID])
			if tc.wantID == "" {
				if ok {
					t.Fatalf("expected no match, got %s", sig.ID)
				}
				return
			}
			if !ok || sig.ID != tc.wantID {
				t.Fatalf("expected %s, got id=%q ok=%v", tc.wantID, sig.ID, ok)
			}
			if sig.Claimable != tc.wantClaim {
				t.Fatalf("%s: expected claimable=%v, got %v", tc.wantID, tc.wantClaim, sig.Claimable)
			}
		})
	}
}

func TestValidateAssets_HTTPFallbackAndFingerprint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<Code>NoSuchBucket</Code>"))
	}))
	defer srv.Close()

	node := models.AssetNode{
		ARN:  "arn:test",
		Name: "example.com",
		Properties: map[string]any{
			"probe_url": srv.URL,
		},
	}
	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: failHeadTransport{next: http.DefaultTransport},
	}
	got := validateAssetsWithClients(context.Background(), []models.AssetNode{node}, 5, false, 2*time.Second, "cloudrift-test", fakeResolver{}, client, &net.Dialer{Timeout: time.Second})
	res := got["arn:test"]
	if res.DNSStatus != "resolved" {
		t.Fatalf("expected resolved dns, got %s", res.DNSStatus)
	}
	if res.ErrorFingerprint != "s3_bucket_deleted" {
		t.Fatalf("expected s3_bucket_deleted, got %s", res.ErrorFingerprint)
	}
}

func TestValidateAssets_NoHTTPSkipsProbing(t *testing.T) {
	node := models.AssetNode{ARN: "arn:nohttp", Name: "example.com"}
	got := validateAssetsWithClients(context.Background(), []models.AssetNode{node}, 2, true, time.Second, "ua", fakeResolver{}, &http.Client{}, &net.Dialer{})
	res := got["arn:nohttp"]
	if res.DNSStatus != "resolved" {
		t.Fatalf("expected resolved, got %s", res.DNSStatus)
	}
	if res.HTTPStatus != 0 || res.BodySnippet != "" {
		t.Fatalf("expected no http probing result")
	}
}

func TestValidateAssets_DNSFailureModes(t *testing.T) {
	node := models.AssetNode{ARN: "arn:dns", Name: "bad.example"}
	nx := validateAssetsWithClients(context.Background(), []models.AssetNode{node}, 1, false, time.Second, "ua", fakeResolver{err: dnsNotFoundErr()}, &http.Client{}, &net.Dialer{})["arn:dns"]
	if nx.DNSStatus != "nxdomain" {
		t.Fatalf("expected nxdomain, got %s", nx.DNSStatus)
	}
	timeout := validateAssetsWithClients(context.Background(), []models.AssetNode{node}, 1, false, time.Second, "ua", fakeResolver{err: dnsTimeoutErr()}, &http.Client{}, &net.Dialer{})["arn:dns"]
	if timeout.DNSStatus != "timeout" {
		t.Fatalf("expected timeout, got %s", timeout.DNSStatus)
	}
	servfail := validateAssetsWithClients(context.Background(), []models.AssetNode{node}, 1, false, time.Second, "ua", fakeResolver{err: errors.New("boom")}, &http.Client{}, &net.Dialer{})["arn:dns"]
	if servfail.DNSStatus != "servfail" {
		t.Fatalf("expected servfail, got %s", servfail.DNSStatus)
	}
}

func TestTargetForProbeOverride(t *testing.T) {
	node := models.AssetNode{
		Name: "ignored.example",
		Properties: map[string]any{
			"probe_url": "http://localhost:9000/p",
		},
	}
	host, target, scheme := targetForProbe(node)
	if host != "localhost" || scheme != "http" || !strings.Contains(target, "localhost:9000") {
		t.Fatalf("unexpected target parse host=%s scheme=%s target=%s", host, scheme, target)
	}
}

func TestThirdPartyFingerprintNeedsTheMatchingTarget(t *testing.T) {
	body := "There isn't a GitHub Pages site here."
	if _, ok := matchTakeoverSignature(404, "GitHub.com", body, "evil.example.net"); ok {
		t.Fatal("a body match alone must not count when the record does not point at the service")
	}
	if _, ok := matchTakeoverSignature(404, "", body, "org.github.io."); !ok {
		t.Fatal("matching target and body must count")
	}
}

type mapResolver map[string]error

func (f mapResolver) LookupHost(_ context.Context, h string) ([]string, error) {
	if err, ok := f[h]; ok {
		return nil, err
	}
	return []string{"1.2.3.4"}, nil
}

func TestDeletedAWSTargetIsFoundFromTheTarget(t *testing.T) {
	node := models.AssetNode{Name: "app.example.com", Properties: map[string]any{"type": "CNAME", "value": "old-env.us-east-1.elasticbeanstalk.com", "target_service": "elasticbeanstalk"}}
	res := validateNode(context.Background(), node, true, time.Second, "ua", mapResolver{"app.example.com": dnsNotFoundErr(), "old-env.us-east-1.elasticbeanstalk.com": dnsNotFoundErr()}, nil, nil)
	if res.ErrorFingerprint != "target_deleted_elasticbeanstalk" || !res.Claimable {
		t.Fatalf("a deleted Beanstalk environment is claimable: %+v", res)
	}
	node.Properties["value"], node.Properties["target_service"] = "x.us-east-1.elb.amazonaws.com", "alb"
	res = validateNode(context.Background(), node, true, time.Second, "ua", mapResolver{"app.example.com": dnsNotFoundErr(), "x.us-east-1.elb.amazonaws.com": dnsNotFoundErr()}, nil, nil)
	if res.ErrorFingerprint != "target_deleted_alb" || res.Claimable {
		t.Fatalf("a deleted load balancer is dangling, not claimable: %+v", res)
	}
	res = validateNode(context.Background(), node, true, time.Second, "ua", mapResolver{"app.example.com": dnsNotFoundErr()}, nil, nil)
	if res.ErrorFingerprint != "dns_nxdomain" {
		t.Fatalf("a target that still resolves keeps the plain result: %+v", res)
	}
}

func TestLameDelegation(t *testing.T) {
	defer func(old func(context.Context, string, string) string) { delegationProbe = old }(delegationProbe)
	node := models.AssetNode{Name: "sub.example.com", Properties: map[string]any{"type": "NS", "values": []string{"ns-1.awsdns-01.org.", "ns-2.awsdns-02.com."}}}
	delegationProbe = func(context.Context, string, string) string { return "refused" }
	res := validateDelegation(context.Background(), node, nil)
	if res.ErrorFingerprint != "ns_delegation_lame" || !res.Claimable {
		t.Fatalf("all Route 53 servers refusing is a claimable lame delegation: %+v", res)
	}
	delegationProbe = func(_ context.Context, _, h string) string {
		if strings.HasPrefix(h, "ns-1") {
			return "refused"
		}
		return "answered"
	}
	if res = validateDelegation(context.Background(), node, nil); res.ErrorFingerprint != "" {
		t.Fatalf("one server that answers means the zone is served: %+v", res)
	}
	delegationProbe = func(context.Context, string, string) string { return "timeout" }
	if res = validateDelegation(context.Background(), node, nil); res.ErrorFingerprint != "" {
		t.Fatalf("a timeout proves nothing: %+v", res)
	}
}

func TestBucketStateFromResponse(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   string
	}{{404, "<Code>NoSuchBucket</Code>", "missing"}, {403, "<Code>AccessDenied</Code>", "exists"}, {301, "", "exists"}, {200, "", "exists"}, {503, "", "unknown"}, {404, "other", "unknown"}}
	for _, c := range cases {
		if got := bucketStateFrom(c.status, c.body); got != c.want {
			t.Errorf("%d %q: got %s want %s", c.status, c.body, got, c.want)
		}
	}
}

func TestAnyEC2Name(t *testing.T) {
	if !anyEC2Name([]string{"ec2-3-0-0-1.compute-1.amazonaws.com."}) || anyEC2Name([]string{"host.example.net.", "lb-1.elb.amazonaws.com"}) {
		t.Fatal("only ec2-… names under amazonaws.com count")
	}
}
