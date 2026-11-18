package collectors

import (
	"testing"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
)

func TestClassifyTargetService(t *testing.T) {
	cases := map[string]string{
		"app.s3-website-us-east-1.amazonaws.com":  "s3_website",
		"d111111abcdef8.cloudfront.net":           "cloudfront",
		"abc.execute-api.us-east-1.amazonaws.com": "apigateway",
		"foo.elb.amazonaws.com":                   "alb",
		"foo.elasticbeanstalk.com":                "elasticbeanstalk",
		"example.vendor.com":                      "third_party",
	}
	for target, want := range cases {
		got := classifyTargetService(target)
		if got != want {
			t.Fatalf("target %s: got %s, want %s", target, got, want)
		}
	}
}

func TestWebsiteEndpointFor(t *testing.T) {
	if got := websiteEndpointFor("bucket", "us-east-1"); got != "bucket.s3-website-us-east-1.amazonaws.com" {
		t.Fatalf("unexpected legacy endpoint: %s", got)
	}
	if got := websiteEndpointFor("bucket", "cn-north-1"); got != "bucket.s3-website.cn-north-1.amazonaws.com.cn" {
		t.Fatalf("unexpected cn endpoint: %s", got)
	}
}

func TestRecordTargetAliasAndValue(t *testing.T) {
	alias := r53types.ResourceRecordSet{
		AliasTarget: &r53types.AliasTarget{DNSName: awsv2.String("d111.cloudfront.net.")},
	}
	if got := recordTarget(alias); got != "d111.cloudfront.net" {
		t.Fatalf("unexpected alias target %q", got)
	}

	value := r53types.ResourceRecordSet{
		ResourceRecords: []r53types.ResourceRecord{{Value: awsv2.String("\"bucket.s3-website-us-east-1.amazonaws.com.\"")}},
	}
	if got := recordTarget(value); got != "bucket.s3-website-us-east-1.amazonaws.com" {
		t.Fatalf("unexpected rr value %q", got)
	}
}
