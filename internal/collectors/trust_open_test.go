package collectors

import "testing"

func TestTrustsEveryone(t *testing.T) {
	yes := []string{
		`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]}`,
		`{"Statement":{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}}`,
		`{"Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::1:root","*"]},"Action":"sts:AssumeRole"}]}`,
	}
	no := []string{
		`{"Statement":[{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole"}]}`,
		`{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`,
		``,
	}
	for _, d := range yes {
		if !trustsEveryone(d) {
			t.Errorf("should collect %s", d)
		}
	}
	for _, d := range no {
		if trustsEveryone(d) {
			t.Errorf("should not collect %s", d)
		}
	}
}
