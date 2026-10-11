package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/inventory"
	"github.com/Zero0x00/cloudrift/internal/models"
)

func InventorySummary(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scanID, meta, assets, rels, findings, ok := loadInventoryScan(w, r, outputDir)
		if !ok {
			return
		}
		summary := inventory.Summarize(meta, assets, rels, findings, inventory.Filter{
			AccountID: strings.TrimSpace(r.URL.Query().Get("account_id")),
			Region:    strings.TrimSpace(r.URL.Query().Get("region")),
		})
		summary.ScanID = scanID
		writeJSON(w, http.StatusOK, summary)
	}
}

func InventoryResources(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scanID, _, assets, rels, findings, ok := loadInventoryScan(w, r, outputDir)
		if !ok {
			return
		}
		page, pageSize, err := parsePagination(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_pagination", err.Error(), nil)
			return
		}
		items := inventory.Build(assets, rels, findings, inventory.Filter{
			AccountID:    strings.TrimSpace(r.URL.Query().Get("account_id")),
			Region:       strings.TrimSpace(r.URL.Query().Get("region")),
			Service:      strings.TrimSpace(r.URL.Query().Get("service")),
			ResourceType: strings.TrimSpace(r.URL.Query().Get("resource_type")),
			Category:     strings.TrimSpace(r.URL.Query().Get("category")),
			Query:        strings.TrimSpace(r.URL.Query().Get("q")),
		})
		list := inventory.Page(items, strings.TrimSpace(r.URL.Query().Get("sort")), page, pageSize)
		list.ScanID = scanID
		writeJSON(w, http.StatusOK, list)
	}
}

func InventoryResource(outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scanID, _, assets, rels, findings, ok := loadInventoryScan(w, r, outputDir)
		if !ok {
			return
		}
		detail, found := inventory.Detail(scanID, r.URL.Query().Get("id"), assets, rels, findings)
		if !found {
			writeError(w, http.StatusNotFound, "resource_not_found", "resource was not in the inventory for this scan", nil)
			return
		}
		writeJSON(w, http.StatusOK, detail)
	}
}

func loadInventoryScan(w http.ResponseWriter, r *http.Request, outputDir string) (string, models.ScanSnapshot, []models.AssetNode, []models.Relationship, []models.Finding, bool) {
	scanID, assets, rels, ok := loadIdentityScan(w, r, outputDir)
	if !ok {
		return "", models.ScanSnapshot{}, nil, nil, nil, false
	}
	var meta models.ScanSnapshot
	if raw, err := os.ReadFile(filepath.Join(outputDir, scanID, "scan-metadata.json")); err == nil {
		_ = json.Unmarshal(raw, &meta)
	}
	meta.ScanID = scanID
	var findings []models.Finding
	if raw, err := os.ReadFile(filepath.Join(outputDir, scanID, "findings.json")); err == nil {
		_ = json.Unmarshal(raw, &findings)
	}
	return scanID, meta, assets, rels, findings, true
}
