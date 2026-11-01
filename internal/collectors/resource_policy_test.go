package collectors

import (
	"context"
	"errors"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/smithy-go"

	"github.com/Zero0x00/cloudrift/internal/models"
)

type fakeSecrets struct {
	list     []smtypes.SecretListEntry
	policies map[string]*string // nil value = no policy
	errFor   map[string]error
	pages    int
}

func (f *fakeSecrets) ListSecrets(_ context.Context, in *secretsmanager.ListSecretsInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error) {
	f.pages++
	if in.NextToken == nil && len(f.list) > 1 { // split into two pages
		return &secretsmanager.ListSecretsOutput{SecretList: f.list[:1], NextToken: awsv2.String("p2")}, nil
	}
	if in.NextToken != nil {
		return &secretsmanager.ListSecretsOutput{SecretList: f.list[1:]}, nil
	}
	return &secretsmanager.ListSecretsOutput{SecretList: f.list}, nil
}

func (f *fakeSecrets) GetResourcePolicy(_ context.Context, in *secretsmanager.GetResourcePolicyInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetResourcePolicyOutput, error) {
	id := awsv2.ToString(in.SecretId)
	if err := f.errFor[id]; err != nil {
		return nil, err
	}
	return &secretsmanager.GetResourcePolicyOutput{ResourcePolicy: f.policies[id]}, nil
}

type fakeKMS struct {
	keys     map[string]kmstypes.KeyMetadata
	policies map[string]string
	aliases  map[string]string
	aliasErr error
	polErr   map[string]error
	grants   map[string][]kmstypes.GrantListEntry
	grantErr error
}

func (f *fakeKMS) ListKeys(context.Context, *kms.ListKeysInput, ...func(*kms.Options)) (*kms.ListKeysOutput, error) {
	var out []kmstypes.KeyListEntry
	for id, m := range f.keys {
		out = append(out, kmstypes.KeyListEntry{KeyId: awsv2.String(id), KeyArn: m.Arn})
	}
	return &kms.ListKeysOutput{Keys: out}, nil
}

func (f *fakeKMS) DescribeKey(_ context.Context, in *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	m := f.keys[awsv2.ToString(in.KeyId)]
	return &kms.DescribeKeyOutput{KeyMetadata: &m}, nil
}

func (f *fakeKMS) GetKeyPolicy(_ context.Context, in *kms.GetKeyPolicyInput, _ ...func(*kms.Options)) (*kms.GetKeyPolicyOutput, error) {
	id := awsv2.ToString(in.KeyId)
	if err := f.polErr[id]; err != nil {
		return nil, err
	}
	return &kms.GetKeyPolicyOutput{Policy: awsv2.String(f.policies[id])}, nil
}

func (f *fakeKMS) ListGrants(_ context.Context, in *kms.ListGrantsInput, _ ...func(*kms.Options)) (*kms.ListGrantsOutput, error) {
	if f.grantErr != nil {
		return nil, f.grantErr
	}
	return &kms.ListGrantsOutput{Grants: f.grants[awsv2.ToString(in.KeyId)]}, nil
}

func (f *fakeKMS) ListAliases(context.Context, *kms.ListAliasesInput, ...func(*kms.Options)) (*kms.ListAliasesOutput, error) {
	if f.aliasErr != nil {
		return nil, f.aliasErr
	}
	var out []kmstypes.AliasListEntry
	for name, target := range f.aliases {
		out = append(out, kmstypes.AliasListEntry{AliasName: awsv2.String(name), TargetKeyId: awsv2.String(target)})
	}
	return &kms.ListAliasesOutput{Aliases: out}, nil
}

type apiErr struct{ code string }

func (e apiErr) Error() string                 { return e.code }
func (e apiErr) ErrorCode() string             { return e.code }
func (e apiErr) ErrorMessage() string          { return e.code }
func (e apiErr) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }

func byARN(nodes []models.AssetNode) map[string]models.AssetNode {
	m := map[string]models.AssetNode{}
	for _, n := range nodes {
		m[n.ARN] = n
	}
	return m
}

func TestCollectRegionalResourcePolicies(t *testing.T) {
	const acct, region = "111111111111", "us-east-1"
	secretARN := func(n string) string { return "arn:aws:secretsmanager:" + region + ":" + acct + ":secret:" + n }
	keyARN := "arn:aws:kms:" + region + ":" + acct + ":key/k1"
	pol := `{"Version":"2012-10-17","Statement":[]}`
	sec := &fakeSecrets{
		list: []smtypes.SecretListEntry{
			{ARN: awsv2.String(secretARN("default-AAAAAA")), Name: awsv2.String("default")},
			{ARN: awsv2.String(secretARN("cmk-BBBBBB")), Name: awsv2.String("cmk"), KmsKeyId: awsv2.String("alias/team")},
			{ARN: awsv2.String(secretARN("denied-CCCCCC")), Name: awsv2.String("denied"), KmsKeyId: awsv2.String("alias/gone")},
		},
		policies: map[string]*string{secretARN("cmk-BBBBBB"): awsv2.String(pol)},
		errFor:   map[string]error{secretARN("denied-CCCCCC"): apiErr{"AccessDeniedException"}},
	}
	k := &fakeKMS{
		keys: map[string]kmstypes.KeyMetadata{
			"k1":  {Arn: awsv2.String(keyARN), KeyId: awsv2.String("k1"), KeyManager: kmstypes.KeyManagerTypeCustomer, KeyState: kmstypes.KeyStateEnabled},
			"aws": {Arn: awsv2.String("arn:aws:kms:us-east-1:111111111111:key/aws"), KeyId: awsv2.String("aws"), KeyManager: kmstypes.KeyManagerTypeAws},
		},
		policies: map[string]string{"k1": pol},
		aliases:  map[string]string{"alias/team": "k1"},
		grants: map[string][]kmstypes.GrantListEntry{"k1": {
			{GranteePrincipal: awsv2.String("arn:aws:iam::111111111111:role/App"), Operations: []kmstypes.GrantOperation{kmstypes.GrantOperationDecrypt}},
			{GranteePrincipal: awsv2.String("arn:aws:iam::111111111111:role/Ctx"), Operations: []kmstypes.GrantOperation{kmstypes.GrantOperationDecrypt}, Constraints: &kmstypes.GrantConstraints{}},
		}},
	}
	got := byARN(CollectRegionalResourcePolicies(context.Background(), acct, region, ResourcePolicyClients{Secrets: sec, KMS: k}, time.Unix(0, 0)))

	if len(got) != 4 { // 3 secrets + 1 customer key; the AWS managed key is skipped
		t.Fatalf("assets: %d %v", len(got), got)
	}
	d := got[secretARN("default-AAAAAA")].Properties
	if d["secret_kms_mode"] != SecretKMSAWSManaged || d["secret_policy_status"] != "confirmed_absent" {
		t.Fatalf("default secret: %v", d)
	}
	c := got[secretARN("cmk-BBBBBB")].Properties
	if c["secret_kms_mode"] != SecretKMSCustomerManaged || c["secret_kms_key_arn"] != keyARN || c["secret_policy_status"] != "present" || c["secret_policy_document"] != pol {
		t.Fatalf("cmk secret: %v", c)
	}
	x := got[secretARN("denied-CCCCCC")].Properties
	if x["secret_policy_status"] != "missing" || x["secret_kms_mode"] != SecretKMSUnknown {
		t.Fatalf("denied secret must be missing/unknown, never absent: %v", x)
	}
	key := got[keyARN].Properties
	if key["key_policy_status"] != "present" || key["key_state"] != "Enabled" {
		t.Fatalf("key: %v", key)
	}
	grants, _ := key["key_grants"].([]map[string]any)
	if key["key_grants_status"] != "collected" || len(grants) != 2 || grants[0]["constrained"] != false || grants[1]["constrained"] != true {
		t.Fatalf("grants: %v", key)
	}
}

func TestResourcePolicyFailuresAreNotAbsence(t *testing.T) {
	const acct, region = "111111111111", "us-east-1"
	keyARN := "arn:aws:kms:us-east-1:111111111111:key/k1"
	k := &fakeKMS{
		keys:     map[string]kmstypes.KeyMetadata{"k1": {Arn: awsv2.String(keyARN), KeyId: awsv2.String("k1"), KeyManager: kmstypes.KeyManagerTypeCustomer, KeyState: kmstypes.KeyStateEnabled}},
		polErr:   map[string]error{"k1": errors.New("boom")},
		aliasErr: apiErr{"AccessDeniedException"},
		grantErr: apiErr{"AccessDeniedException"},
	}
	sec := &fakeSecrets{list: []smtypes.SecretListEntry{{ARN: awsv2.String("arn:aws:secretsmanager:us-east-1:111111111111:secret:a-AAAAAA"), Name: awsv2.String("a"), KmsKeyId: awsv2.String("alias/x")}}}
	got := byARN(CollectRegionalResourcePolicies(context.Background(), acct, region, ResourcePolicyClients{Secrets: sec, KMS: k}, time.Unix(0, 0)))
	if got[keyARN].Properties["key_grants_status"] != "missing" {
		t.Fatalf("failed ListGrants must be missing: %v", got[keyARN].Properties)
	}
	if got[keyARN].Properties["key_policy_status"] != "missing" {
		t.Fatalf("failed GetKeyPolicy must be missing: %v", got[keyARN].Properties)
	}
	if p := got[awsv2.ToString(sec.list[0].ARN)].Properties; p["secret_kms_mode"] != SecretKMSUnknown {
		t.Fatalf("alias with failed ListAliases must be unknown: %v", p)
	}
}

func TestResolveSecretKey(t *testing.T) {
	cases := []struct{ in, mode, arn string }{
		{"", SecretKMSAWSManaged, ""},
		{"alias/aws/secretsmanager", SecretKMSAWSManaged, ""},
		{"abcd-1234", SecretKMSCustomerManaged, "arn:aws:kms:us-east-1:1:key/abcd-1234"},
		{"arn:aws:kms:eu-west-1:2:key/zz", SecretKMSCustomerManaged, "arn:aws:kms:eu-west-1:2:key/zz"},
		{"arn:aws:kms:us-east-1:1:alias/a", SecretKMSCustomerManaged, "arn:aws:kms:us-east-1:1:key/t"},
		{"alias/missing", SecretKMSUnknown, ""},
	}
	for _, c := range cases {
		mode, arn, _ := resolveSecretKey(c.in, "1", "us-east-1", map[string]string{"alias/a": "t"}, nil)
		if mode != c.mode || arn != c.arn {
			t.Errorf("%q: got %s %s", c.in, mode, arn)
		}
	}
}

type fakeRDS struct{ pages [][]rdstypes.DBInstance }

func (f *fakeRDS) DescribeDBInstances(_ context.Context, in *rds.DescribeDBInstancesInput, _ ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	if in.Marker == nil {
		return &rds.DescribeDBInstancesOutput{DBInstances: f.pages[0], Marker: awsv2.String("m")}, nil
	}
	return &rds.DescribeDBInstancesOutput{DBInstances: f.pages[1]}, nil
}

func TestCollectRDSInstances(t *testing.T) {
	api := &fakeRDS{pages: [][]rdstypes.DBInstance{
		{{DBInstanceArn: awsv2.String("arn:aws:rds:us-east-1:1:db:a"), DBInstanceIdentifier: awsv2.String("a"), DeletionProtection: awsv2.Bool(true)}},
		{{DBInstanceArn: awsv2.String("arn:aws:rds:us-east-1:1:db:b"), DBInstanceIdentifier: awsv2.String("b")}},
	}}
	nodes := collectRDSInstances(context.Background(), "1", "us-east-1", api, "now")
	if len(nodes) != 2 || nodes[0].AssetType != models.AssetRDSInstance || nodes[0].Properties["deletion_protection"] != true {
		t.Fatalf("%v", nodes)
	}
}

type fakeLambdaPolicy struct{ byARN map[string]error }

func (f fakeLambdaPolicy) GetPolicy(_ context.Context, in *lambda.GetPolicyInput, _ ...func(*lambda.Options)) (*lambda.GetPolicyOutput, error) {
	if err, ok := f.byARN[awsv2.ToString(in.FunctionName)]; ok {
		return nil, err
	}
	return &lambda.GetPolicyOutput{Policy: awsv2.String(`{"Statement":[]}`)}, nil
}

func TestReadLambdaPolicy(t *testing.T) {
	api := fakeLambdaPolicy{byARN: map[string]error{"none": apiErr{"ResourceNotFoundException"}, "denied": apiErr{"AccessDeniedException"}}}
	if s, _, _ := readLambdaPolicy(context.Background(), api, "none"); s != "confirmed_absent" {
		t.Fatal(s)
	}
	if s, _, _ := readLambdaPolicy(context.Background(), api, "denied"); s != "missing" {
		t.Fatal("a denied call is not absence:", s)
	}
	if s, _, d := readLambdaPolicy(context.Background(), api, "ok"); s != "present" || d == "" {
		t.Fatal(s)
	}
}

type fakeEndpoints struct{ err error }

func (f fakeEndpoints) DescribeVpcEndpoints(_ context.Context, _ *ec2.DescribeVpcEndpointsInput, _ ...func(*ec2.Options)) (*ec2.DescribeVpcEndpointsOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &ec2.DescribeVpcEndpointsOutput{VpcEndpoints: []ec2types.VpcEndpoint{
		{VpcEndpointId: awsv2.String("vpce-1"), ServiceName: awsv2.String("com.amazonaws.us-east-1.s3"), PolicyDocument: awsv2.String(`{"Statement":[]}`)},
		{VpcEndpointId: awsv2.String("vpce-2")},
	}}, nil
}

func TestCollectVPCEndpoints(t *testing.T) {
	nodes := collectVPCEndpoints(context.Background(), "1", "us-east-1", fakeEndpoints{}, "now")
	if len(nodes) != 2 || nodes[0].AssetType != models.AssetVPCEndpoint || nodes[0].Properties["endpoint_policy_status"] != "collected" || nodes[1].Properties["endpoint_policy_status"] != "not_returned" {
		t.Fatalf("%v", nodes)
	}
	failed := collectVPCEndpoints(context.Background(), "1", "us-east-1", fakeEndpoints{err: apiErr{"UnauthorizedOperation"}}, "now")
	if len(failed) != 1 || failed[0].AssetType == models.AssetVPCEndpoint {
		t.Fatalf("a failed call must be a status, not an endpoint: %v", failed)
	}
}
