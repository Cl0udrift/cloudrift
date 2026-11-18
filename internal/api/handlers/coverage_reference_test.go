package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Zero0x00/cloudrift/internal/referencecov"
)

func TestReferenceCoverageIsServedAndConsistent(t *testing.T) {
	rr := httptest.NewRecorder()
	GetReferenceCoverage().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/coverage/reference", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("%d", rr.Code)
	}
	r := referencecov.Load()
	if r.Totals.Paths == 0 || r.Totals.Paths != len(r.Paths) {
		t.Fatalf("totals must match the path list: %+v", r.Totals)
	}
	if r.Totals.Detected+r.Totals.Partial+r.Totals.NotDetected != r.Totals.Paths {
		t.Fatalf("every path has exactly one status: %+v", r.Totals)
	}
	for _, p := range r.Paths {
		if p.Status != referencecov.Detected && p.Reason == "" {
			t.Fatalf("%s is not detected and says nothing about why", p.ID)
		}
	}
}
