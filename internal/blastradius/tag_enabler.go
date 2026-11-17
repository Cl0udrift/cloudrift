package blastradius

import (
	"strings"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/iamauth"
	"github.com/Zero0x00/cloudrift/internal/models"
)

// tagActions are the calls that can move a target's tags to the state a condition needs: set or change a tag, or remove it.
// Setting or changing a tag can also break a negated condition (change the value), so it is always an option.
func tagActions(target models.AssetNode, gaps []iamauth.TagGap) []string {
	removeOnly := true
	for _, g := range gaps {
		if !g.Remove {
			removeOnly = false
		}
	}
	var set, del string
	switch target.AssetType {
	case models.AssetIAMUser:
		set, del = "iam:TagUser", "iam:UntagUser"
	case models.AssetIAMRole:
		set, del = "iam:TagRole", "iam:UntagRole"
	case models.AssetEC2Instance:
		set, del = "ec2:CreateTags", "ec2:DeleteTags"
	default:
		return nil
	}
	if removeOnly {
		return []string{del, set}
	}
	return []string{set}
}

func isTagAction(action string) bool {
	switch strings.ToLower(action) {
	case "iam:taguser", "iam:tagrole", "iam:untaguser", "iam:untagrole", "ec2:createtags", "ec2:deletetags":
		return true
	}
	return false
}

// tagRequestContext is the context of the call that moves the tags in gaps.
func tagRequestContext(base map[string]string, gaps []iamauth.TagGap) map[string]string {
	ctx := make(map[string]string, len(base)+len(gaps)+1)
	for k, v := range base {
		ctx[k] = v
	}
	for i, g := range gaps {
		want := g.Want
		if g.Remove {
			want = "cloudrift-changed" // a change to another value is as good as removal for a negated condition
		}
		ctx["aws:RequestTag/"+g.Key] = want
		if i == 0 {
			ctx["aws:TagKeys"] = g.Key
		}
	}
	return ctx
}

func describeChange(gaps []iamauth.TagGap) string {
	var parts []string
	for _, g := range gaps {
		if g.Remove {
			parts = append(parts, "remove the tag "+g.Key)
		} else {
			parts = append(parts, "set the tag "+g.Key+"="+g.Want)
		}
	}
	return strings.Join(parts, ", ")
}

// findTagEnabler looks for a principal the attacker controls that may move the target's tags so the blocked call becomes allowed.
// allowed says whether tagger may make the tagging call with the given context; recheck says whether the original request is
// allowed once the tags are in the state the gaps need. The result is nil unless both hold.
func findTagEnabler(target models.AssetNode, gaps []iamauth.TagGap, taggers []string, nameOf func(string) string, allowed func(tagger, action string, ctx map[string]string) bool, base map[string]string, recheck func(map[string]string) bool) *schema.TagEnabler {
	actions := tagActions(target, gaps)
	if len(actions) == 0 {
		return nil
	}
	after := make(map[string]string, len(base)+len(gaps))
	for k, v := range base {
		after[k] = v
	}
	for _, g := range gaps {
		if g.Remove {
			delete(after, "aws:ResourceTag/"+g.Key)
		} else {
			after["aws:ResourceTag/"+g.Key] = g.Want
		}
	}
	if !recheck(after) {
		return nil
	}
	tagCtx := tagRequestContext(base, gaps)
	for _, tagger := range taggers {
		for _, a := range actions {
			if allowed(tagger, a, tagCtx) {
				return &schema.TagEnabler{Tagger: tagger, TaggerName: nameOf(tagger), Action: a, Change: describeChange(gaps)}
			}
		}
	}
	return nil
}
