package collectors

import (
	"context"
	"reflect"
	"testing"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/Zero0x00/cloudrift/internal/models"
)

type fakeSG struct{ groups []ec2types.SecurityGroup }

func (f fakeSG) DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	return &ec2.DescribeSecurityGroupsOutput{SecurityGroups: f.groups}, nil
}

type fakeELB struct{}

func (fakeELB) DescribeLoadBalancers(context.Context, *elbv2.DescribeLoadBalancersInput, ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancersOutput, error) {
	return &elbv2.DescribeLoadBalancersOutput{LoadBalancers: []elbtypes.LoadBalancer{{
		LoadBalancerArn: awsv2.String("arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/web/1"), LoadBalancerName: awsv2.String("web"),
		Scheme: elbtypes.LoadBalancerSchemeEnumInternetFacing, SecurityGroups: []string{"sg-lb"},
	}}}, nil
}
func (fakeELB) DescribeTargetGroups(context.Context, *elbv2.DescribeTargetGroupsInput, ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupsOutput, error) {
	return &elbv2.DescribeTargetGroupsOutput{TargetGroups: []elbtypes.TargetGroup{
		{TargetGroupArn: awsv2.String("tg-inst"), TargetType: elbtypes.TargetTypeEnumInstance},
		{TargetGroupArn: awsv2.String("tg-ip"), TargetType: elbtypes.TargetTypeEnumIp},
	}}, nil
}
func (fakeELB) DescribeTargetHealth(_ context.Context, in *elbv2.DescribeTargetHealthInput, _ ...func(*elbv2.Options)) (*elbv2.DescribeTargetHealthOutput, error) {
	return &elbv2.DescribeTargetHealthOutput{TargetHealthDescriptions: []elbtypes.TargetHealthDescription{{Target: &elbtypes.TargetDescription{Id: awsv2.String("i-1")}}}}, nil
}
func (fakeELB) DescribeTags(context.Context, *elbv2.DescribeTagsInput, ...func(*elbv2.Options)) (*elbv2.DescribeTagsOutput, error) {
	return &elbv2.DescribeTagsOutput{TagDescriptions: []elbtypes.TagDescription{{
		ResourceArn: awsv2.String("arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/web/1"),
		Tags:        []elbtypes.Tag{{Key: awsv2.String("owner"), Value: awsv2.String("payments")}},
	}}}, nil
}

type fakeNetRDS struct{}

func (fakeNetRDS) DescribeDBInstances(context.Context, *rds.DescribeDBInstancesInput, ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	return &rds.DescribeDBInstancesOutput{DBInstances: []rdstypes.DBInstance{{
		DBInstanceArn: awsv2.String("arn:aws:rds:us-east-1:111111111111:db:prod"), DBInstanceIdentifier: awsv2.String("prod"),
		PubliclyAccessible: awsv2.Bool(true), VpcSecurityGroups: []rdstypes.VpcSecurityGroupMembership{{VpcSecurityGroupId: awsv2.String("sg-db")}},
	}}}, nil
}

func TestWorldOpenPortsListsOnlyAnywhereRules(t *testing.T) {
	perms := []ec2types.IpPermission{
		{IpProtocol: awsv2.String("tcp"), FromPort: awsv2.Int32(443), ToPort: awsv2.Int32(443), IpRanges: []ec2types.IpRange{{CidrIp: awsv2.String("0.0.0.0/0")}}},
		{IpProtocol: awsv2.String("tcp"), FromPort: awsv2.Int32(22), ToPort: awsv2.Int32(22), IpRanges: []ec2types.IpRange{{CidrIp: awsv2.String("10.0.0.0/8")}}},
		{IpProtocol: awsv2.String("tcp"), FromPort: awsv2.Int32(8000), ToPort: awsv2.Int32(8100), Ipv6Ranges: []ec2types.Ipv6Range{{CidrIpv6: awsv2.String("::/0")}}},
		{IpProtocol: awsv2.String("tcp"), FromPort: awsv2.Int32(3306), ToPort: awsv2.Int32(3306), UserIdGroupPairs: []ec2types.UserIdGroupPair{{GroupId: awsv2.String("sg-app")}}},
		{IpProtocol: awsv2.String("-1"), IpRanges: []ec2types.IpRange{{CidrIp: awsv2.String("0.0.0.0/0")}}},
	}
	got := worldOpenPorts(perms)
	want := []string{"all", "tcp/443", "tcp/8000-8100"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v (a private CIDR or another group must not count)", got, want)
	}
}

func TestCollectNetworkLinksGroupsBalancersAndDatabases(t *testing.T) {
	inst := models.AssetNode{ARN: "arn:aws:ec2:us-east-1:111111111111:instance/i-1", AssetType: models.AssetEC2Instance, AccountID: "111111111111", Region: "us-east-1",
		Properties: map[string]any{"security_group_ids": []string{"sg-web"}}}
	sg := fakeSG{groups: []ec2types.SecurityGroup{{GroupId: awsv2.String("sg-web"), GroupName: awsv2.String("web"),
		IpPermissions: []ec2types.IpPermission{{IpProtocol: awsv2.String("tcp"), FromPort: awsv2.Int32(80), ToPort: awsv2.Int32(80), IpRanges: []ec2types.IpRange{{CidrIp: awsv2.String("0.0.0.0/0")}}}}}}}
	assets, rels := collectNetwork(context.Background(), "111111111111", "us-east-1", sg, fakeELB{}, fakeNetRDS{}, time.Now(), []models.AssetNode{inst})

	has := func(typ models.AssetType) *models.AssetNode {
		for i := range assets {
			if assets[i].AssetType == typ {
				return &assets[i]
			}
		}
		return nil
	}
	if g := has(models.AssetSecurityGroup); g == nil || !reflect.DeepEqual(g.Properties["world_open_ports"], []string{"tcp/80"}) {
		t.Fatalf("security group with its open port, got %+v", g)
	}
	if lb := has(models.AssetLoadBalancer); lb == nil || lb.Properties["scheme"] != "internet-facing" || lb.Properties["tags"].(map[string]string)["owner"] != "payments" {
		t.Fatalf("load balancer with scheme and tags, got %+v", lb)
	}
	if db := has(models.AssetRDSInstance); db == nil || db.Properties["publicly_accessible"] != true {
		t.Fatalf("rds with its public flag, got %+v", db)
	}
	var routes, groups int
	for _, r := range rels {
		switch r.RelType {
		case models.RelRoutesTo:
			routes++
			if r.TargetARN != inst.ARN {
				t.Fatalf("route must point at the instance, got %s", r.TargetARN)
			}
		case models.RelUsesSecurityGroup:
			groups++
		}
	}
	if routes != 1 {
		t.Fatalf("one instance target (the IP target group is not an instance), got %d", routes)
	}
	if groups != 3 { // instance, load balancer, database
		t.Fatalf("want 3 security group edges, got %d", groups)
	}
}

func TestIngressRulesKeepSourcesAndPorts(t *testing.T) {
	rules, truncated := ingressRules([]ec2types.IpPermission{
		{IpProtocol: awsv2.String("tcp"), FromPort: awsv2.Int32(22), ToPort: awsv2.Int32(22), IpRanges: []ec2types.IpRange{{CidrIp: awsv2.String("10.0.0.0/8")}}, UserIdGroupPairs: []ec2types.UserIdGroupPair{{GroupId: awsv2.String("sg-app")}}},
		{IpProtocol: awsv2.String("-1"), IpRanges: []ec2types.IpRange{{CidrIp: awsv2.String("0.0.0.0/0")}}},
		{IpProtocol: awsv2.String("tcp"), FromPort: awsv2.Int32(8000), ToPort: awsv2.Int32(8100), PrefixListIds: []ec2types.PrefixListId{{PrefixListId: awsv2.String("pl-1")}}},
	})
	if truncated || len(rules) != 3 {
		t.Fatalf("got %d rules truncated=%v", len(rules), truncated)
	}
	if rules[0]["ports"] != "22" || !reflect.DeepEqual(rules[0]["sources"], []string{"10.0.0.0/8", "sg-app"}) {
		t.Fatalf("rule 0: %+v", rules[0])
	}
	if rules[1]["ports"] != "all" || rules[2]["ports"] != "8000-8100" || !reflect.DeepEqual(rules[2]["sources"], []string{"pl-1"}) {
		t.Fatalf("rules: %+v %+v", rules[1], rules[2])
	}
}
