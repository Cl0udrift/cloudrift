package inventory

import (
	"strconv"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// factsOf lists the attributes worth reading first for a resource type, from collected properties only.
// A property that was not collected is left out, never shown as a default.
func factsOf(a models.AssetNode, rels []models.Relationship) []schema.InventoryFact {
	out := []schema.InventoryFact{}
	add := func(label, value string) {
		if strings.TrimSpace(value) != "" {
			out = append(out, schema.InventoryFact{Label: label, Value: value})
		}
	}
	str := func(key string) string { v, _ := a.Properties[key].(string); return v }
	flag := func(key string) string {
		if v, ok := a.Properties[key].(bool); ok {
			return strconv.FormatBool(v)
		}
		return ""
	}
	count := func(rel models.RelType, source bool) int {
		n := 0
		for _, r := range rels {
			if r.RelType == rel && ((source && r.SourceARN == a.ARN) || (!source && r.TargetARN == a.ARN)) {
				n++
			}
		}
		return n
	}
	switch a.AssetType {
	case models.AssetSecurityGroup:
		add("Group name", str("group_name"))
		add("Description", str("description"))
		add("VPC", str("vpc_id"))
		add("Inbound rules", strconv.Itoa(len(inboundRules(a))))
		add("Attached to", strconv.Itoa(count(models.RelUsesSecurityGroup, false))+" resource(s)")
	case models.AssetLoadBalancer:
		add("Scheme", str("scheme"))
		add("Type", str("lb_type"))
		add("DNS name", str("dns_name"))
		add("VPC", str("vpc_id"))
		add("State", str("state"))
		add("Targets", strconv.Itoa(count(models.RelRoutesTo, true))+" instance(s)")
	case models.AssetRDSInstance:
		add("Engine", str("engine"))
		add("Publicly accessible", flag("publicly_accessible"))
		add("Storage encrypted", flag("storage_encrypted"))
		add("VPC", str("vpc_id"))
	case models.AssetEC2Instance:
		add("State", str("instance_state"))
		add("Public IP", str("public_ip"))
		add("VPC", str("vpc_id"))
		add("Security groups", strconv.Itoa(count(models.RelUsesSecurityGroup, true)))
	}
	return out
}

// inboundRules reads the stored rules of a security group. Stored JSON gives []any of maps; tests give typed values.
func inboundRules(a models.AssetNode) []schema.InventoryRule {
	var rules []schema.InventoryRule
	switch raw := a.Properties["ingress_rules"].(type) {
	case []map[string]any:
		for _, m := range raw {
			rules = append(rules, ruleFrom(m))
		}
	case []any:
		for _, x := range raw {
			if m, ok := x.(map[string]any); ok {
				rules = append(rules, ruleFrom(m))
			}
		}
	}
	return rules
}

func ruleFrom(m map[string]any) schema.InventoryRule {
	r := schema.InventoryRule{Sources: stringList(m["sources"])}
	r.Protocol, _ = m["protocol"].(string)
	r.Ports, _ = m["ports"].(string)
	if r.Protocol == "-1" {
		r.Protocol = "all"
	}
	for _, s := range r.Sources {
		if s == "0.0.0.0/0" || s == "::/0" {
			r.World = true
		}
	}
	return r
}
