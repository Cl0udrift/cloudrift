package collectors

import (
	"context"
	"regexp"
	"sort"
	"strings"

	awsv2 "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/Zero0x00/cloudrift/internal/models"
)

// PolicyVersionsAPI is the extra read access to a policy's older versions. A client that lacks it is skipped.
type PolicyVersionsAPI interface {
	ListPolicyVersions(ctx context.Context, params *iam.ListPolicyVersionsInput, optFns ...func(*iam.Options)) (*iam.ListPolicyVersionsOutput, error)
	GetPolicyVersion(ctx context.Context, params *iam.GetPolicyVersionInput, optFns ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
}

// maxSwitchablePolicies bounds the extra calls: one list and up to four gets per policy.
const maxSwitchablePolicies = 200

// collectSwitchablePolicyVersions reads the non-default versions of the customer managed policies that some collected
// statement lets a principal switch with iam:SetDefaultPolicyVersion. Only those need it: a policy nobody can switch
// cannot be escalated through an older version, so reading every policy's history would only add API calls.
//
// Each policy it tried gets policy_versions_status (collected, failed or capped) and, when collected, non_default_versions.
// A policy it did not try has neither, which the attack search reads as "versions not collected", never as "no other versions".
func collectSwitchablePolicyVersions(ctx context.Context, client any, nodes []models.AssetNode) {
	api, ok := client.(PolicyVersionsAPI)
	if !ok {
		return
	}
	var grants []*regexp.Regexp
	for _, n := range nodes {
		if n.AssetType != models.AssetIAMPolicyStatement || !strings.EqualFold(propStr(n, "effect"), "Allow") {
			continue
		}
		if !coversSetDefault(n.Properties["action"], n.Properties["not_action"]) {
			continue
		}
		for _, r := range propList(n.Properties["resource"]) {
			grants = append(grants, globRegexp(r))
		}
	}
	if len(grants) == 0 {
		return
	}
	var targets []int
	seen := map[string]bool{}
	for i, n := range nodes {
		if n.AssetType != models.AssetIAMPolicy || propStr(n, "policy_type") != models.PolicyTypeManaged || strings.Contains(n.ARN, ":aws:policy/") || seen[n.ARN] {
			continue
		}
		for _, g := range grants {
			if g.MatchString(n.ARN) {
				seen[n.ARN] = true
				targets = append(targets, i)
				break
			}
		}
	}
	sort.Ints(targets)
	byARN := map[string][]int{}
	for i, n := range nodes {
		if n.AssetType == models.AssetIAMPolicy {
			byARN[n.ARN] = append(byARN[n.ARN], i)
		}
	}
	set := func(arn string, props map[string]any) {
		for _, i := range byARN[arn] {
			if nodes[i].Properties == nil {
				nodes[i].Properties = map[string]any{}
			}
			for k, v := range props {
				nodes[i].Properties[k] = v
			}
		}
	}
	for n, i := range targets {
		arn := nodes[i].ARN
		if n >= maxSwitchablePolicies {
			set(arn, map[string]any{"policy_versions_status": "capped"})
			continue
		}
		versions, err := readNonDefaultVersions(ctx, api, arn)
		if err != nil {
			set(arn, map[string]any{"policy_versions_status": "failed", "policy_versions_error": err.Error()})
			continue
		}
		set(arn, map[string]any{"policy_versions_status": "collected", "non_default_versions": versions})
	}
}

func readNonDefaultVersions(ctx context.Context, api PolicyVersionsAPI, arn string) ([]map[string]any, error) {
	list, err := api.ListPolicyVersions(ctx, &iam.ListPolicyVersionsInput{PolicyArn: awsv2.String(arn)})
	if err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for _, v := range list.Versions {
		if v.IsDefaultVersion {
			continue
		}
		id := awsv2.ToString(v.VersionId)
		got, err := api.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: awsv2.String(arn), VersionId: awsv2.String(id)})
		if err != nil || got == nil || got.PolicyVersion == nil {
			return nil, errVersionRead(id, err)
		}
		out = append(out, map[string]any{"version_id": id, "document": decodeIAMDocument(awsv2.ToString(got.PolicyVersion.Document))})
	}
	return out, nil
}

type versionReadError struct{ id, cause string }

func (e versionReadError) Error() string { return "version " + e.id + " was not read: " + e.cause }

func errVersionRead(id string, err error) error {
	cause := "no document returned"
	if err != nil {
		cause = err.Error()
	}
	return versionReadError{id, cause}
}

// coversSetDefault is true when an Allow statement's actions can include iam:SetDefaultPolicyVersion. A statement with
// NotAction is treated as covering it unless it excludes it, so a wide Allow is never skipped.
func coversSetDefault(action, notAction any) bool {
	const want = "iam:setdefaultpolicyversion"
	if na := propList(notAction); len(na) > 0 {
		for _, a := range na {
			if globRegexp(strings.ToLower(a)).MatchString(want) {
				return false
			}
		}
		return true
	}
	for _, a := range propList(action) {
		if globRegexp(strings.ToLower(a)).MatchString(want) {
			return true
		}
	}
	return false
}

func globRegexp(pattern string) *regexp.Regexp {
	q := regexp.QuoteMeta(strings.TrimSpace(pattern))
	q = strings.ReplaceAll(strings.ReplaceAll(q, `\*`, ".*"), `\?`, ".")
	return regexp.MustCompile("^" + q + "$")
}

func propStr(n models.AssetNode, key string) string {
	s, _ := n.Properties[key].(string)
	return s
}

func propList(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case string:
		return []string{t}
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
