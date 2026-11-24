package collectors

import (
	"context"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	cogtypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type fakeAddr struct{}

func (fakeAddr) DescribeAddresses(context.Context, *ec2.DescribeAddressesInput, ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error) {
	return &ec2.DescribeAddressesOutput{Addresses: []ec2types.Address{{PublicIp: awsv2.String("3.0.0.1")}}}, nil
}
func (fakeAddr) DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	return &ec2.DescribeNetworkInterfacesOutput{NetworkInterfaces: []ec2types.NetworkInterface{
		{Association: &ec2types.NetworkInterfaceAssociation{PublicIp: awsv2.String("3.0.0.2")}},
		{PrivateIpAddresses: []ec2types.NetworkInterfacePrivateIpAddress{{Association: &ec2types.NetworkInterfaceAssociation{PublicIp: awsv2.String("3.0.0.3")}}}},
	}}, nil
}

type fakeACM struct{}

func (fakeACM) ListCertificates(context.Context, *acm.ListCertificatesInput, ...func(*acm.Options)) (*acm.ListCertificatesOutput, error) {
	return &acm.ListCertificatesOutput{CertificateSummaryList: []acmtypes.CertificateSummary{{CertificateArn: awsv2.String("arn:aws:acm:us-east-1:1:certificate/c")}}}, nil
}
func (fakeACM) DescribeCertificate(context.Context, *acm.DescribeCertificateInput, ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error) {
	return &acm.DescribeCertificateOutput{Certificate: &acmtypes.CertificateDetail{DomainName: awsv2.String("example.com"), DomainValidationOptions: []acmtypes.DomainValidation{{ResourceRecord: &acmtypes.ResourceRecord{Name: awsv2.String("_ABC.example.com.")}}}}}, nil
}

type fakeCog struct{}

func (fakeCog) ListUserPools(context.Context, *cognitoidentityprovider.ListUserPoolsInput, ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ListUserPoolsOutput, error) {
	return &cognitoidentityprovider.ListUserPoolsOutput{UserPools: []cogtypes.UserPoolDescriptionType{{Id: awsv2.String("p1")}, {Id: awsv2.String("p2")}}}, nil
}
func (fakeCog) DescribeUserPool(_ context.Context, in *cognitoidentityprovider.DescribeUserPoolInput, _ ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.DescribeUserPoolOutput, error) {
	if awsv2.ToString(in.UserPoolId) == "p2" {
		return &cognitoidentityprovider.DescribeUserPoolOutput{UserPool: &cogtypes.UserPoolType{Name: awsv2.String("no-domain")}}, nil
	}
	return &cognitoidentityprovider.DescribeUserPoolOutput{UserPool: &cogtypes.UserPoolType{Name: awsv2.String("app"), Domain: awsv2.String("myapp")}}, nil
}

func TestEdgeServicesCollectOwnedNamesAndAddresses(t *testing.T) {
	assets, _ := collectEdgeServices(context.Background(), "1", "us-east-1", WorkloadClients{Addresses: fakeAddr{}, ACM: fakeACM{}, Cognito: fakeCog{}}, time.Now())
	var ips []string
	var validation []string
	var host string
	status := map[string]string{}
	for _, a := range assets {
		switch a.AssetType {
		case "public_address_set":
			ips = stringSlice(a.Properties["addresses"])
		case "acm_cert":
			validation = stringSlice(a.Properties["validation_records"])
		case "cognito_user_pool":
			host, _ = a.Properties["hosted_ui_host"].(string)
		case "collection_status":
			status[a.Properties["collector"].(string)], _ = a.Properties["status"].(string)
		}
	}
	if len(ips) != 3 {
		t.Fatalf("elastic IP plus both interface address forms: %v", ips)
	}
	if len(validation) != 1 || validation[0] != "_abc.example.com" {
		t.Fatalf("validation record name must be lower-case without the trailing dot: %v", validation)
	}
	if host != "myapp.auth.us-east-1.amazoncognito.com" {
		t.Fatalf("a pool without a domain has none, and the host is built from the prefix: %q", host)
	}
	if status["public_addresses"] != "succeeded" || status["acm"] != "succeeded" || status["cognito"] != "succeeded" {
		t.Fatalf("each collector records success: %v", status)
	}
}

type fakeVol struct{}

func (fakeVol) DescribeVolumes(context.Context, *ec2.DescribeVolumesInput, ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	return &ec2.DescribeVolumesOutput{Volumes: []ec2types.Volume{
		{VolumeId: awsv2.String("vol-1"), Size: awsv2.Int32(100), VolumeType: ec2types.VolumeTypeGp3, State: ec2types.VolumeStateAvailable, Encrypted: awsv2.Bool(false)},
		{VolumeId: awsv2.String("vol-2"), Size: awsv2.Int32(8), VolumeType: ec2types.VolumeTypeGp2, State: ec2types.VolumeStateInUse, Encrypted: awsv2.Bool(true), Attachments: []ec2types.VolumeAttachment{{InstanceId: awsv2.String("i-1")}}},
	}}, nil
}

func TestVolumesRecordSizeTypeStateAndAttachment(t *testing.T) {
	assets, _ := collectEdgeServices(context.Background(), "1", "us-east-1", WorkloadClients{Volumes: fakeVol{}}, time.Now())
	byName := map[string]map[string]any{}
	for _, a := range assets {
		if a.AssetType == "ebs_volume" {
			byName[a.Name] = a.Properties
		}
	}
	if byName["vol-1"]["state"] != "available" || byName["vol-1"]["size_gb"] != int64(100) || byName["vol-1"]["volume_type"] != "gp3" || byName["vol-1"]["encrypted"] != false {
		t.Fatalf("vol-1: %v", byName["vol-1"])
	}
	if att := byName["vol-2"]["attached_to"].([]string); len(att) != 1 || att[0] != "i-1" {
		t.Fatalf("vol-2 attachment: %v", byName["vol-2"])
	}
}
