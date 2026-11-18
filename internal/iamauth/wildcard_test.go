package iamauth

import (
	"math/rand"
	"regexp"
	"strings"
	"testing"
)

// regexWildcard is the previous implementation, kept as the reference the faster matcher must agree with.
func regexWildcard(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	var b strings.Builder
	b.WriteString("^")
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		case litStar:
			b.WriteString(`\*`)
		case litQuestion:
			b.WriteString(`\?`)
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	return err == nil && re.MatchString(value)
}

func TestWildcardMatchAgreesWithTheRegexReference(t *testing.T) {
	alphabet := []rune{'a', 'b', ':', '/', '*', '?', litStar, litQuestion, 'é'}
	valueAlphabet := []rune{'a', 'b', ':', '/', '*', '?', 'é'}
	rng := rand.New(rand.NewSource(7))
	gen := func(src []rune, max int) string {
		n := rng.Intn(max + 1)
		out := make([]rune, n)
		for i := range out {
			out[i] = src[rng.Intn(len(src))]
		}
		return string(out)
	}
	for i := 0; i < 200000; i++ {
		p, v := gen(alphabet, 7), gen(valueAlphabet, 9)
		if got, want := wildcardMatch(p, v), regexWildcard(p, v); got != want {
			t.Fatalf("pattern %q value %q: got %v, reference %v", p, v, got, want)
		}
	}
	for _, c := range [][2]string{{"s3:get*", "s3:getobject"}, {"s3:*object", "s3:getobject"}, {"arn:aws:s3:::b/*", "arn:aws:s3:::b/k/x"}, {"iam:*", "s3:get"}} {
		if wildcardMatch(c[0], c[1]) != regexWildcard(c[0], c[1]) {
			t.Fatalf("%v", c)
		}
	}
}
