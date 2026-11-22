package handlers

import "testing"

func TestCSVCellDefusesFormulas(t *testing.T) {
	for in, want := range map[string]string{"=cmd()": "'=cmd()", "+1": "'+1", "-x": "'-x", "@SUM": "'@SUM", "plain": "plain", "": ""} {
		if got := csvCell(in); got != want {
			t.Errorf("%q -> %q want %q", in, got, want)
		}
	}
}
