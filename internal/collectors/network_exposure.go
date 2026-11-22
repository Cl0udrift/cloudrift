package collectors

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"time"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// Network exposure: security groups, load balancers and databases, and how they connect to the instances
// already collected. Every call is a read-only Describe*. Exposure is recorded as facts (a rule open to
// 0.0.0.0/0, a public scheme, a public flag); the inventory view derives "internet-facing" from them.

type SecurityGroupAPI interface {
	DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
}

type ELBv2API interface {
	DescribeLoadBalancers(context.Context, *elbv2.DescribeLoadBalancersInput, ...func(*elbv2.Options)) (*elbv2.DescribeLoadBalancersOutput, error)
	DescribeTargetGroups(context.Context, *elbv2.DescribeTargetGroupsInput, ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupsOutput, error)
	DescribeTargetHealth(context.Context, *elbv2.DescribeTargetHealthInput, ...func(*elbv2.Options)) (*elbv2.DescribeTargetHealthOutput, error)
	DescribeTags(context.Context, *elbv2.DescribeTagsInput, ...func(*elbv2.Options)) (*elbv2.DescribeTagsOutput, error)
}

// maxTargetGroupsPerLB bounds the calls spent on one load balancer. AWS allows 100 listeners' worth of groups,
// so a larger count is recorded as truncated and never read as "no more targets".
const maxTargetGroupsPerLB = 50

// collectNetwork records security groups, load balancers and RDS instances for one account and Region and links
// them to the instances in haveAssets. A failed collector adds a failed status and leaves the others running.
func collectNetwork(ctx context.Context, accountID, region string, sg SecurityGroupAPI, lb ELBv2API, db RDSAPI, at time.Time, haveAssets []models.AssetNode) ([]models.AssetNode, []models.Relationship) {
	var assets []models.AssetNode
	var rels []models.Relationship
	run := func(name string, fn func() ([]models.AssetNode, []models.Relationship, error)) {
		nodes, edges, err := fn()
		if err != nil {
			status, detail := serviceStatus(err)
			assets = append(assets, CollectionStatus(accountID, region, name, "regional", status, detail))
			return
		}
		assets = append(assets, nodes...)
		rels = append(rels, edges...)
		assets = append(assets, CollectionStatus(accountID, region, name, "regional", "succeeded", ""))
	}
	if sg != nil {
		run("security_groups", func() ([]models.AssetNode, []models.Relationship, error) {
			return collectSecurityGroups(ctx, accountID, region, sg, at, haveAssets)
		})
	}
	if lb != nil {
		run("elbv2", func() ([]models.AssetNode, []models.Relationship, error) {
			return collectLoadBalancers(ctx, accountID, region, lb, at)
		})
	}
	if db != nil {
		run("rds", func() ([]models.AssetNode, []models.Relationship, error) {
			return collectRDSNetwork(ctx, accountID, region, db, at)
		})
	}
	return assets, rels
}

func sgARN(region, account, id string) string {
	return "arn:aws:ec2:" + region + ":" + account + ":security-group/" + id
}

func collectSecurityGroups(ctx context.Context, accountID, region string, api SecurityGroupAPI, at time.Time, haveAssets []models.AssetNode) ([]models.AssetNode, []models.Relationship, error) {
	var assets []models.AssetNode
	var token *string
	for {
		out, err := api.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{NextToken: token})
		if err != nil {
			return nil, nil, err
		}
		for _, g := range out.SecurityGroups {
			id := awsv2.ToString(g.GroupId)
			props := map[string]any{
				"group_name": awsv2.ToString(g.GroupName), "vpc_id": awsv2.ToString(g.VpcId),
				"collected_at": at.Format(time.RFC3339), "source_api": "ec2:DescribeSecurityGroups", "tags_collected": true,
			}
			if ports := worldOpenPorts(g.IpPermissions); len(ports) > 0 {
				props["world_open_ports"] = ports
			}
			if tags := ec2TagMap(g.Tags); len(tags) > 0 {
				props["tags"] = tags
			}
			if d := awsv2.ToString(g.Description); d != "" {
				props["description"] = d
			}
			rules, truncated := ingressRules(g.IpPermissions)
			props["ingress_rules"] = rules
			if truncated {
				props["ingress_rules_truncated"] = true
			}
			assets = append(assets, models.AssetNode{ARN: sgARN(region, accountID, id), AssetType: models.AssetSecurityGroup, Name: nameOr(awsv2.ToString(g.GroupName), id), AccountID: accountID, Region: region, Properties: props})
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	// Instances name their groups in DescribeInstances; the edge is added here so a missing group collector never leaves a dangling edge.
	var rels []models.Relationship
	for _, a := range haveAssets {
		if a.AssetType != models.AssetEC2Instance || a.Region != region || a.AccountID != accountID {
			continue
		}
		for _, id := range stringSlice(a.Properties["security_group_ids"]) {
			rels = append(rels, models.Relationship{SourceARN: a.ARN, TargetARN: sgARN(region, accountID, id), RelType: models.RelUsesSecurityGroup})
		}
	}
	return assets, rels, nil
}

// worldOpenPorts lists the inbound rules that accept traffic from anywhere (0.0.0.0/0 or ::/0), as "tcp/443",
// "tcp/0-65535" or "all". A rule limited to a prefix list or another security group is not listed.
func worldOpenPorts(perms []ec2types.IpPermission) []string {
	seen := map[string]bool{}
	for _, p := range perms {
		open := false
		for _, r := range p.IpRanges {
			if awsv2.ToString(r.CidrIp) == "0.0.0.0/0" {
				open = true
			}
		}
		for _, r := range p.Ipv6Ranges {
			if awsv2.ToString(r.CidrIpv6) == "::/0" {
				open = true
			}
		}
		if !open {
			continue
		}
		proto := awsv2.ToString(p.IpProtocol)
		switch {
		case proto == "-1":
			seen["all"] = true
		case p.FromPort == nil || p.ToPort == nil:
			seen[proto] = true
		case awsv2.ToInt32(p.FromPort) == awsv2.ToInt32(p.ToPort):
			seen[proto+"/"+strconv.Itoa(int(awsv2.ToInt32(p.FromPort)))] = true
		default:
			seen[fmt.Sprintf("%s/%d-%d", proto, awsv2.ToInt32(p.FromPort), awsv2.ToInt32(p.ToPort))] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func collectLoadBalancers(ctx context.Context, accountID, region string, api ELBv2API, at time.Time) ([]models.AssetNode, []models.Relationship, error) {
	var lbs []elbtypes.LoadBalancer
	var marker *string
	for {
		out, err := api.DescribeLoadBalancers(ctx, &elbv2.DescribeLoadBalancersInput{Marker: marker})
		if err != nil {
			return nil, nil, err
		}
		lbs = append(lbs, out.LoadBalancers...)
		if out.NextMarker == nil || *out.NextMarker == "" {
			break
		}
		marker = out.NextMarker
	}
	tags := loadBalancerTags(ctx, api, lbs)
	var assets []models.AssetNode
	var rels []models.Relationship
	for _, lb := range lbs {
		arn := awsv2.ToString(lb.LoadBalancerArn)
		state := ""
		if lb.State != nil {
			state = string(lb.State.Code)
		}
		props := map[string]any{
			"scheme": string(lb.Scheme), "lb_type": string(lb.Type), "dns_name": awsv2.ToString(lb.DNSName), "vpc_id": awsv2.ToString(lb.VpcId),
			"state": state, "security_group_ids": lb.SecurityGroups, "collected_at": at.Format(time.RFC3339), "source_api": "elasticloadbalancing:DescribeLoadBalancers",
			"tags_collected": true,
		}
		if t := tags[arn]; len(t) > 0 {
			props["tags"] = t
		}
		targets, truncated := lbTargets(ctx, api, accountID, region, arn)
		if truncated {
			props["targets_truncated"] = true
		}
		assets = append(assets, models.AssetNode{ARN: arn, AssetType: models.AssetLoadBalancer, Name: awsv2.ToString(lb.LoadBalancerName), AccountID: accountID, Region: region, Properties: props})
		for _, id := range lb.SecurityGroups {
			rels = append(rels, models.Relationship{SourceARN: arn, TargetARN: sgARN(region, accountID, id), RelType: models.RelUsesSecurityGroup})
		}
		for _, t := range targets {
			rels = append(rels, models.Relationship{SourceARN: arn, TargetARN: t, RelType: models.RelRoutesTo, Properties: map[string]any{"source_api": "elasticloadbalancing:DescribeTargetHealth", "collected_at": at.Format(time.RFC3339)}})
		}
	}
	return assets, rels, nil
}

// lbTargets returns the instances registered behind a load balancer. Only instance targets are linked (an IP or
// Lambda target is not an instance). A failure on one load balancer yields no targets for it, never a guess.
func lbTargets(ctx context.Context, api ELBv2API, accountID, region, lbARN string) ([]string, bool) {
	groups, err := api.DescribeTargetGroups(ctx, &elbv2.DescribeTargetGroupsInput{LoadBalancerArn: awsv2.String(lbARN), PageSize: awsv2.Int32(maxTargetGroupsPerLB)})
	if err != nil {
		return nil, false
	}
	seen := map[string]bool{}
	var out []string
	for _, g := range groups.TargetGroups {
		if g.TargetType != elbtypes.TargetTypeEnumInstance {
			continue
		}
		health, err := api.DescribeTargetHealth(ctx, &elbv2.DescribeTargetHealthInput{TargetGroupArn: g.TargetGroupArn})
		if err != nil {
			continue
		}
		for _, d := range health.TargetHealthDescriptions {
			if d.Target == nil {
				continue
			}
			arn := "arn:aws:ec2:" + region + ":" + accountID + ":instance/" + awsv2.ToString(d.Target.Id)
			if !seen[arn] {
				seen[arn] = true
				out = append(out, arn)
			}
		}
	}
	sort.Strings(out)
	return out, groups.NextMarker != nil && *groups.NextMarker != ""
}

func loadBalancerTags(ctx context.Context, api ELBv2API, lbs []elbtypes.LoadBalancer) map[string]map[string]string {
	out := map[string]map[string]string{}
	for i := 0; i < len(lbs); i += 20 { // DescribeTags accepts at most 20 ARNs
		end := i + 20
		if end > len(lbs) {
			end = len(lbs)
		}
		arns := make([]string, 0, 20)
		for _, lb := range lbs[i:end] {
			arns = append(arns, awsv2.ToString(lb.LoadBalancerArn))
		}
		resp, err := api.DescribeTags(ctx, &elbv2.DescribeTagsInput{ResourceArns: arns})
		if err != nil {
			continue
		}
		for _, d := range resp.TagDescriptions {
			m := map[string]string{}
			for _, t := range d.Tags {
				m[awsv2.ToString(t.Key)] = awsv2.ToString(t.Value)
			}
			out[awsv2.ToString(d.ResourceArn)] = m
		}
	}
	return out
}

func collectRDSNetwork(ctx context.Context, accountID, region string, api RDSAPI, at time.Time) ([]models.AssetNode, []models.Relationship, error) {
	var assets []models.AssetNode
	var rels []models.Relationship
	var marker *string
	for {
		page, err := api.DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{Marker: marker})
		if err != nil {
			return nil, nil, err
		}
		for _, db := range page.DBInstances {
			arn := awsv2.ToString(db.DBInstanceArn)
			if arn == "" {
				continue
			}
			var sgs []string
			for _, g := range db.VpcSecurityGroups {
				sgs = append(sgs, awsv2.ToString(g.VpcSecurityGroupId))
			}
			props := map[string]any{
				"publicly_accessible": awsv2.ToBool(db.PubliclyAccessible), "engine": awsv2.ToString(db.Engine), "security_group_ids": sgs,
				"storage_encrypted": awsv2.ToBool(db.StorageEncrypted), "collected_at": at.Format(time.RFC3339), "source_api": "rds:DescribeDBInstances", "tags_collected": true,
			}
			if db.DBSubnetGroup != nil {
				props["vpc_id"] = awsv2.ToString(db.DBSubnetGroup.VpcId)
			}
			if len(db.TagList) > 0 {
				m := map[string]string{}
				for _, t := range db.TagList {
					m[awsv2.ToString(t.Key)] = awsv2.ToString(t.Value)
				}
				props["tags"] = m
			}
			assets = append(assets, models.AssetNode{ARN: arn, AssetType: models.AssetRDSInstance, Name: awsv2.ToString(db.DBInstanceIdentifier), AccountID: accountID, Region: region, Properties: props})
			for _, id := range sgs {
				rels = append(rels, models.Relationship{SourceARN: arn, TargetARN: sgARN(region, accountID, id), RelType: models.RelUsesSecurityGroup})
			}
		}
		if page.Marker == nil || *page.Marker == "" {
			break
		}
		marker = page.Marker
	}
	return assets, rels, nil
}

func nameOr(name, fallback string) string {
	if name != "" {
		return name
	}
	return fallback
}

func stringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// maxIngressRules bounds the rules stored per group. A group over it is marked truncated and never read as having no more rules.
const maxIngressRules = 100

// ingressRules flattens a group's inbound rules to one row per protocol and port range, each with its sources
// (CIDRs, other security groups, prefix lists), so the inventory can show what a group lets in.
func ingressRules(perms []ec2types.IpPermission) ([]map[string]any, bool) {
	out := []map[string]any{}
	for _, p := range perms {
		var sources []string
		for _, r := range p.IpRanges {
			sources = append(sources, awsv2.ToString(r.CidrIp))
		}
		for _, r := range p.Ipv6Ranges {
			sources = append(sources, awsv2.ToString(r.CidrIpv6))
		}
		for _, g := range p.UserIdGroupPairs {
			sources = append(sources, awsv2.ToString(g.GroupId))
		}
		for _, l := range p.PrefixListIds {
			sources = append(sources, awsv2.ToString(l.PrefixListId))
		}
		if len(out) == maxIngressRules {
			return out, true
		}
		out = append(out, map[string]any{"protocol": awsv2.ToString(p.IpProtocol), "ports": portRange(p), "sources": sources})
	}
	return out, false
}

func portRange(p ec2types.IpPermission) string {
	switch {
	case awsv2.ToString(p.IpProtocol) == "-1":
		return "all"
	case p.FromPort == nil || p.ToPort == nil:
		return "all"
	case awsv2.ToInt32(p.FromPort) == awsv2.ToInt32(p.ToPort):
		return strconv.Itoa(int(awsv2.ToInt32(p.FromPort)))
	}
	return fmt.Sprintf("%d-%d", awsv2.ToInt32(p.FromPort), awsv2.ToInt32(p.ToPort))
}
