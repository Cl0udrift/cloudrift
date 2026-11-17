package iamauth

import "testing"

func tagReq(tags map[string]string) AuthorizationRequest {
	r := baseGet()
	r.Action = "ec2:StopInstances"
	r.ResourceARN = "arn:aws:ec2:us-east-1:111111111111:instance/i-0123456789abcdef0"
	r.Identity = statements("id", "A", "Allow", []string{"ec2:StopInstances"}, []string{"*"}, map[string]any{"StringNotEquals": map[string]any{"aws:ResourceTag/Name": "protected"}})
	r.ResourceTagsKnown = true
	r.RequestContext = map[string]string{}
	for k, v := range tags {
		r.RequestContext["aws:ResourceTag/"+k] = v
	}
	return r
}

func TestNegatedTagConditionAndTheRemovalGap(t *testing.T) {
	if d := Evaluate(tagReq(nil)); d.Status != StatusAllowed {
		t.Fatalf("a missing tag meets StringNotEquals: %s %s", d.Status, d.Reason)
	}
	if d := Evaluate(tagReq(map[string]string{"Name": "other"})); d.Status != StatusAllowed {
		t.Fatalf("another value meets StringNotEquals: %s", d.Status)
	}
	d := Evaluate(tagReq(map[string]string{"Name": "protected"}))
	if d.Status == StatusAllowed || len(d.TagGaps) != 1 || d.TagGaps[0] != (TagGap{Key: "Name", Remove: true}) {
		t.Fatalf("a tag that breaks the condition must be reported as a removal gap: %s %+v", d.Status, d.TagGaps)
	}
	unknown := tagReq(nil)
	unknown.ResourceTagsKnown = false
	if d := Evaluate(unknown); d.Status == StatusAllowed {
		t.Fatalf("when tags were not collected the condition stays unknown: %s", d.Status)
	}
}
