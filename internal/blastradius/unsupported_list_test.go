package blastradius

import (
	"context"
	"strings"
	"testing"
)

// The report tells the reader what the search does not model. A technique that is modeled must not be listed there.
func TestUnsupportedTechniquesDoNotNameModeledOnes(t *testing.T) {
	r := AnalyzeIdentityAttack(context.Background(), IdentityAttackRequest{ScanID: "s", InitialPrincipal: "arn:aws:iam::111111111111:role/A"})
	for _, u := range r.UnsupportedTechniques {
		for _, modeled := range []string{"ec2:RunInstances", "PassRole combined", "user-targeted", "AttachUserPolicy", "CreateAccessKey", "AddUserToGroup", "event source mapping"} {
			if strings.Contains(u, modeled) {
				t.Errorf("%q is modeled but listed as unsupported: %q", modeled, u)
			}
		}
	}
	if len(r.UnsupportedTechniques) == 0 {
		t.Fatal("the report must still list what it does not model")
	}
}
