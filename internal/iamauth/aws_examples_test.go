package iamauth

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	docSCPExamples = "https://github.com/aws-samples/service-control-policy-examples"
	docRCPExamples = "https://github.com/aws-samples/resource-control-policy-examples"
)

var awsExampleReplacer = strings.NewReplacer(
	"${Account}", "111111111111",
	"[PRIVILEGED_ROLE]", "Admin",
	"[PROTECTED_ROLE_PREFIX]", "Protected-",
	"[PROTECTED_ROLE_NAME]", "Crown",
	"[BUCKET_TO_PROTECT]", "vault",
)

// AWSExampleOrgSlot returns an organization control set for one account: the default allow-all policy on the root,
// an OU and the account, plus one of AWS's own example policies attached to the OU (deny list strategy).
func AWSExampleOrgSlot(kind, file string) PolicySlot {
	raw, err := os.ReadFile(filepath.Join("testdata", "aws_examples", kind, file))
	if err != nil {
		panic(err)
	}
	allowAll := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	doc := func(id, level, target, body string) PolicyDocument {
		return PolicyDocument{ID: id, PolicyType: kind, Raw: body, AttachmentLevel: level, AttachmentTarget: target}
	}
	return PolicySlot{State: EvidencePresent, HierarchyComplete: true, Evidence: "AWS example policy", Documents: []PolicyDocument{
		doc("full-root", "root", "r-root", allowAll),
		doc("full-ou", "organizational_unit", "ou-1", allowAll),
		doc("full-acct", "account", "111111111111", allowAll),
		doc("example-"+strings.TrimSuffix(file, ".json"), "organizational_unit", "ou-1", awsExampleReplacer.Replace(string(raw))),
	}}
}

func awsExampleCases() []goldenCase {
	scp := func(file string, mut func(*AuthorizationRequest)) func() AuthorizationRequest {
		return getReq(func(r *AuthorizationRequest) {
			r.SCPs = AWSExampleOrgSlot("scp", file)
			r.RequestContext = map[string]string{"aws:PrincipalArn": r.PrincipalARN}
			if mut != nil {
				mut(r)
			}
		})
	}
	rcp := func(file string, mut func(*AuthorizationRequest)) func() AuthorizationRequest {
		return getReq(func(r *AuthorizationRequest) {
			r.RCPs = AWSExampleOrgSlot("rcp", file)
			r.RequestContext = map[string]string{}
			if mut != nil {
				mut(r)
			}
		})
	}
	region := func(v string) func(*AuthorizationRequest) {
		return func(r *AuthorizationRequest) { r.RequestContext["aws:RequestedRegion"] = v }
	}
	action := func(a, res string, extra map[string]string) func(*AuthorizationRequest) {
		return func(r *AuthorizationRequest) {
			r.Action, r.ResourceARN = a, res
			r.Identity = statements("id", "A", "Allow", []string{a}, []string{"*"}, nil)
			for k, v := range extra {
				r.RequestContext[k] = v
			}
		}
	}
	both := func(fs ...func(*AuthorizationRequest)) func(*AuthorizationRequest) {
		return func(r *AuthorizationRequest) {
			for _, f := range fs {
				f(r)
			}
		}
	}
	admin := func(r *AuthorizationRequest) {
		r.PrincipalARN = "arn:aws:iam::111111111111:role/Admin"
		r.RequestContext["aws:PrincipalArn"] = r.PrincipalARN
	}
	const obj = "arn:aws:s3:::data/readme.txt"
	const vault = "arn:aws:s3:::vault/secret.txt"
	return []goldenCase{
		{"AWS SCP example, region restriction: s3:GetObject outside the allowed regions", docSCPExamples, StatusDenied, scp("region.json", region("us-east-1"))},
		{"AWS SCP example, region restriction: allowed region", docSCPExamples, StatusAllowed, scp("region.json", region("eu-west-1"))},
		{"AWS SCP example, region restriction: sts:AssumeRole is in NotAction", docSCPExamples, StatusAllowed, func() AuthorizationRequest {
			r := assumeReq(nil)()
			r.SCPs = AWSExampleOrgSlot("scp", "region.json")
			r.RequestContext = map[string]string{"aws:PrincipalArn": r.PrincipalARN, "aws:RequestedRegion": "us-east-1"}
			return r
		}},
		{"AWS SCP example, region restriction: iam:CreateAccessKey is in NotAction", docSCPExamples, StatusAllowed, scp("region.json",
			both(region("us-east-1"), action("iam:CreateAccessKey", "arn:aws:iam::111111111111:user/bob", nil)))},
		{"AWS SCP example, region restriction: privileged role is exempt", docSCPExamples, StatusAllowed, scp("region.json", both(admin, region("us-east-1")))},
		{"AWS SCP example, region restriction: region not known: a deny cannot be ruled out", docSCPExamples, StatusUnknown, scp("region.json", nil)},
		{"AWS SCP example, protect a bucket from deletes: protected bucket", docSCPExamples, StatusDenied, scp("s3_delete.json", action("s3:DeleteObject", vault, nil))},
		{"AWS SCP example, protect a bucket from deletes: another bucket", docSCPExamples, StatusAllowed, scp("s3_delete.json", action("s3:DeleteObject", obj, nil))},
		{"AWS SCP example, protect a bucket from deletes: reads are not blocked", docSCPExamples, StatusAllowed, scp("s3_delete.json", action("s3:GetObject", vault, nil))},
		{"AWS SCP example, unencrypted uploads: no encryption header", docSCPExamples, StatusDenied, scp("s3_unencrypted.json", action("s3:PutObject", obj, map[string]string{"aws:RequestedRegion": "eu-west-1"}))},
		{"AWS SCP example, unencrypted uploads: header sent", docSCPExamples, StatusAllowed, scp("s3_unencrypted.json", action("s3:PutObject", obj, map[string]string{"s3:x-amz-server-side-encryption": "AES256"}))},
		{"AWS SCP example, protect IAM roles: assume a protected role", docSCPExamples, StatusDenied, func() AuthorizationRequest {
			r := assumeReq(nil)()
			r.ResourceARN = "arn:aws:iam::111111111111:role/Protected-billing"
			r.Identity = statements("id", "A", "Allow", []string{"sts:AssumeRole"}, []string{r.ResourceARN}, nil)
			r.SCPs = AWSExampleOrgSlot("scp", "iam_roles.json")
			r.RequestContext = map[string]string{"aws:PrincipalArn": r.PrincipalARN}
			return r
		}},
		{"AWS SCP example, protect IAM roles: the privileged role may assume it", docSCPExamples, StatusAllowed, func() AuthorizationRequest {
			r := assumeReq(nil)()
			r.PrincipalARN = "arn:aws:iam::111111111111:role/Admin"
			r.ResourceARN = "arn:aws:iam::111111111111:role/Protected-billing"
			r.Identity = statements("id", "A", "Allow", []string{"sts:AssumeRole"}, []string{r.ResourceARN}, nil)
			r.TrustPolicy = slotOf(StatementView{PolicyID: "trust", StatementID: "t", Effect: "Allow", Action: []string{"sts:AssumeRole"}, Principal: map[string]any{"AWS": r.PrincipalARN}})
			r.SCPs = AWSExampleOrgSlot("scp", "iam_roles.json")
			r.RequestContext = map[string]string{"aws:PrincipalArn": r.PrincipalARN}
			return r
		}},
		{"AWS RCP example, HTTPS only: plain HTTP request", docRCPExamples, StatusDenied, rcp("https_only.json", func(r *AuthorizationRequest) { r.RequestContext = map[string]string{"aws:SecureTransport": "false"} })},
		{"AWS RCP example, HTTPS only: TLS request", docRCPExamples, StatusAllowed, rcp("https_only.json", func(r *AuthorizationRequest) { r.RequestContext = map[string]string{"aws:SecureTransport": "true"} })},
		{"AWS RCP example, protect a bucket from deletes: protected bucket", docRCPExamples, StatusDenied, rcp("s3_delete.json", action("s3:DeleteObject", vault, nil))},
		{"AWS RCP example, protect a bucket from deletes: another bucket", docRCPExamples, StatusAllowed, rcp("s3_delete.json", action("s3:DeleteObject", obj, nil))},
		{"AWS RCP example, deny SSE-C uploads: customer key algorithm sent", docRCPExamples, StatusDenied, rcp("s3_deny_ssec.json", action("s3:PutObject", obj, map[string]string{"s3:x-amz-server-side-encryption-customer-algorithm": "AES256"}))},
		{"AWS RCP example, deny SSE-C uploads: no customer key", docRCPExamples, StatusAllowed, rcp("s3_deny_ssec.json", action("s3:PutObject", obj, nil))},
	}
}
