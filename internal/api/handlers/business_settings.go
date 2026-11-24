package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/Zero0x00/cloudrift/internal/business"
)

// GetBusinessSettings returns owners, fix deadlines and loss values: what AWS cannot tell us.
func GetBusinessSettings(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, err := business.Load(outputDir)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "settings_unreadable", err.Error(), nil)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"settings": s, "loss_configured": s.Loss.Configured()})
	}
}

// PutBusinessSettings replaces the settings. Loss values left empty keep every dollar figure off.
func PutBusinessSettings(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body business.Settings
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_json", "invalid request JSON", nil)
			return
		}
		if body.Owners == nil {
			body.Owners = map[string]string{}
		}
		saved, err := business.Save(outputDir, body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_settings", err.Error(), nil)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"settings": saved, "loss_configured": saved.Loss.Configured()})
	}
}
