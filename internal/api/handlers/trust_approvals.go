package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Zero0x00/cloudrift/internal/trustapprovals"
)

// ListTrustApprovals returns the outside accounts someone approved, with the note and date for each.
func ListTrustApprovals(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := trustapprovals.Load(outputDir)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "approvals_unreadable", err.Error(), nil)
			return
		}
		if list == nil {
			list = []trustapprovals.Approval{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": list, "note": "An approval applies from the next scan; findings already written keep their rating."})
	}
}

// ApproveTrustAccount records an approval. The note is required.
func ApproveTrustAccount(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Note string `json:"note"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_json", "invalid request JSON", nil)
			return
		}
		a, err := trustapprovals.Add(outputDir, chi.URLParam(r, "accountID"), body.Note, time.Now())
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_approval", err.Error(), nil)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"item": a})
	}
}

func RemoveTrustApproval(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := trustapprovals.Remove(outputDir, chi.URLParam(r, "accountID")); err != nil {
			writeError(w, http.StatusInternalServerError, "approvals_unwritable", err.Error(), nil)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"removed": chi.URLParam(r, "accountID")})
	}
}
