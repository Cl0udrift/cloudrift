package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestTrustApprovalsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	r := chi.NewRouter()
	r.Get("/trust/approvals", ListTrustApprovals(dir))
	r.Put("/trust/approvals/{accountID}", ApproveTrustAccount(dir))
	r.Delete("/trust/approvals/{accountID}", RemoveTrustApproval(dir))
	do := func(method, path, body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rr
	}
	if rr := do(http.MethodPut, "/trust/approvals/123456789012", `{"note":""}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("no note must be refused: %d", rr.Code)
	}
	if rr := do(http.MethodPut, "/trust/approvals/123456789012", `{"note":"Datadog"}`); rr.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rr.Code, rr.Body)
	}
	if rr := do(http.MethodGet, "/trust/approvals", ""); !strings.Contains(rr.Body.String(), "Datadog") {
		t.Fatalf("list: %s", rr.Body)
	}
	do(http.MethodDelete, "/trust/approvals/123456789012", "")
	if rr := do(http.MethodGet, "/trust/approvals", ""); strings.Contains(rr.Body.String(), "Datadog") {
		t.Fatalf("remove: %s", rr.Body)
	}
}
