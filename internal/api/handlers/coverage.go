package handlers

import (
	"net/http"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/coverage"
	"github.com/Zero0x00/cloudrift/internal/models"
	"github.com/Zero0x00/cloudrift/internal/scans"
)

// GetCoverage returns the module coverage report. scan_id is optional and defaults to the latest scan.
// A missing scan is not an error: the page still shows the registry and config state.
func GetCoverage(outputDir, configPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg, err := config.Load(configPath)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "config_unreadable", "The config file could not be read: "+err.Error(), nil)
			return
		}
		want := strings.TrimSpace(r.URL.Query().Get("scan_id"))
		if want == "" {
			want = "latest"
		}
		scanID, assets := "", []models.AssetNode(nil)
		if id, ok := scanIDFromPath(outputDir, want); ok {
			if loaded, err := scans.LoadAssets(outputDir, id); err == nil {
				scanID, assets = id, loaded
			}
		}
		writeJSON(w, http.StatusOK, coverage.Build(cfg, scanID, assets))
	}
}
