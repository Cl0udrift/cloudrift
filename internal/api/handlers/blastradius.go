package handlers

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Zero0x00/cloudrift/internal/api/schema"
	"github.com/Zero0x00/cloudrift/internal/blastradius"
	"github.com/Zero0x00/cloudrift/internal/scans"
)

// BlastRadiusFindingSummary is GET /api/scans/{id}/findings/{fid}/blast-radius/summary
func BlastRadiusFindingSummary(svc *blastradius.Service, outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if svc == nil {
			svc = blastradius.NewService(nil, outputDir)
		}
		scanID, ok := scanIDFromPath(outputDir, chi.URLParam(r, "id"))
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid_scan_id", "invalid scan id", nil)
			return
		}
		fid := strings.TrimSpace(chi.URLParam(r, "fid"))
		if !isSafeFindingID(fid) {
			writeError(w, http.StatusBadRequest, "invalid_finding_id", "invalid finding id", nil)
			return
		}
		mode := blastModeOrDefault(r.URL.Query().Get("mode"))
		if _, _, err := scans.LoadScanArtifacts(outputDir, scanID); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				writeError(w, http.StatusNotFound, "scan_not_found", "scan not found", map[string]any{"scan_id": scanID})
				return
			}
			writeError(w, http.StatusInternalServerError, "scan_load_error", "failed to load scan artifacts", nil)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		sum, _, _, _ := svc.FindingBlast(ctx, scanID, fid, mode)
		writeJSON(w, http.StatusOK, sum)
	}
}

// BlastRadiusFindingExplorer is GET /api/scans/{id}/findings/{fid}/blast-radius/explorer
func BlastRadiusFindingExplorer(svc *blastradius.Service, outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if svc == nil {
			svc = blastradius.NewService(nil, outputDir)
		}
		scanID, ok := scanIDFromPath(outputDir, chi.URLParam(r, "id"))
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid_scan_id", "invalid scan id", nil)
			return
		}
		fid := strings.TrimSpace(chi.URLParam(r, "fid"))
		if !isSafeFindingID(fid) {
			writeError(w, http.StatusBadRequest, "invalid_finding_id", "invalid finding id", nil)
			return
		}
		mode := blastModeOrDefault(r.URL.Query().Get("mode"))
		if _, _, err := scans.LoadScanArtifacts(outputDir, scanID); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				writeError(w, http.StatusNotFound, "scan_not_found", "scan not found", map[string]any{"scan_id": scanID})
				return
			}
			writeError(w, http.StatusInternalServerError, "scan_load_error", "failed to load scan artifacts", nil)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		payload := svc.ExplorerFromFinding(ctx, scanID, fid, mode)
		writeJSON(w, http.StatusOK, payload)
	}
}

// BlastRadiusEntitySummary is GET /api/scans/{id}/blast-radius/entity/summary?entity_id=…
func BlastRadiusEntitySummary(svc *blastradius.Service, outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if svc == nil {
			svc = blastradius.NewService(nil, outputDir)
		}
		scanID, ok := scanIDFromPath(outputDir, chi.URLParam(r, "id"))
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid_scan_id", "invalid scan id", nil)
			return
		}
		eid := strings.TrimSpace(r.URL.Query().Get("entity_id"))
		if eid == "" {
			writeError(w, http.StatusBadRequest, "invalid_entity_id", "entity_id query is required", nil)
			return
		}
		if _, _, err := scans.LoadScanArtifacts(outputDir, scanID); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				writeError(w, http.StatusNotFound, "scan_not_found", "scan not found", map[string]any{"scan_id": scanID})
				return
			}
			writeError(w, http.StatusInternalServerError, "scan_load_error", "failed to load scan artifacts", nil)
			return
		}
		mode := blastModeOrDefault(r.URL.Query().Get("mode"))
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		sum, _, _ := svc.ExternalEntityBlast(ctx, scanID, eid, mode)
		writeJSON(w, http.StatusOK, sum)
	}
}

// BlastRadiusEntityExplorer is GET /api/scans/{id}/blast-radius/entity/explorer?entity_id=…
func BlastRadiusEntityExplorer(svc *blastradius.Service, outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if svc == nil {
			svc = blastradius.NewService(nil, outputDir)
		}
		scanID, ok := scanIDFromPath(outputDir, chi.URLParam(r, "id"))
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid_scan_id", "invalid scan id", nil)
			return
		}
		eid := strings.TrimSpace(r.URL.Query().Get("entity_id"))
		if eid == "" {
			writeError(w, http.StatusBadRequest, "invalid_entity_id", "entity_id query is required", nil)
			return
		}
		if _, _, err := scans.LoadScanArtifacts(outputDir, scanID); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				writeError(w, http.StatusNotFound, "scan_not_found", "scan not found", map[string]any{"scan_id": scanID})
				return
			}
			writeError(w, http.StatusInternalServerError, "scan_load_error", "failed to load scan artifacts", nil)
			return
		}
		mode := blastModeOrDefault(r.URL.Query().Get("mode"))
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		payload := svc.ExplorerFromEntity(ctx, scanID, eid, mode)
		writeJSON(w, http.StatusOK, payload)
	}
}

func blastModeOrDefault(s string) blastradius.BlastMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "attack_path":
		return blastradius.ModeAttackPath
	case "identity_exposure":
		return blastradius.ModeIdentityExposure
	case "permission_blast_radius":
		return blastradius.ModePermissionBlast
	default:
		return blastradius.ModeBlastRadius
	}
}

// BlastRadiusExplorerExpand is GET /api/scans/{id}/blast-radius/explorer/expand?node_id=...&mode=...&finding_id|entity_id|principal_id=...
func BlastRadiusExplorerExpand(svc *blastradius.Service, outputDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if svc == nil {
			svc = blastradius.NewService(nil, outputDir)
		}
		scanID, ok := scanIDFromPath(outputDir, chi.URLParam(r, "id"))
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid_scan_id", "invalid scan id", nil)
			return
		}
		if _, _, err := scans.LoadScanArtifacts(outputDir, scanID); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				writeError(w, http.StatusNotFound, "scan_not_found", "scan not found", map[string]any{"scan_id": scanID})
				return
			}
			writeError(w, http.StatusInternalServerError, "scan_load_error", "failed to load scan artifacts", nil)
			return
		}
		nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
		if nodeID == "" {
			writeError(w, http.StatusBadRequest, "invalid_node_id", "node_id query is required", nil)
			return
		}
		root, valid := expansionRootContextFromQuery(r)
		if !valid {
			writeError(w, http.StatusBadRequest, "invalid_root_context", "provide exactly one of finding_id, entity_id, or principal_id", nil)
			return
		}
		mode := blastModeOrDefault(r.URL.Query().Get("mode"))
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		resp := svc.ExplorerExpandOneHop(ctx, scanID, root, nodeID, mode)
		writeJSON(w, http.StatusOK, resp)
	}
}

func expansionRootContextFromQuery(r *http.Request) (blastradius.ExpansionRootContext, bool) {
	fid := strings.TrimSpace(r.URL.Query().Get("finding_id"))
	eid := strings.TrimSpace(r.URL.Query().Get("entity_id"))
	pid := strings.TrimSpace(r.URL.Query().Get("principal_id"))
	count := 0
	if fid != "" {
		count++
	}
	if eid != "" {
		count++
	}
	if pid != "" {
		count++
	}
	if count != 1 {
		return blastradius.ExpansionRootContext{}, false
	}
	switch {
	case fid != "":
		return blastradius.ExpansionRootContext{RootType: schema.BlastRootFinding, RootID: fid}, true
	case eid != "":
		return blastradius.ExpansionRootContext{RootType: schema.BlastRootExternalEntity, RootID: eid}, true
	default:
		return blastradius.ExpansionRootContext{RootType: schema.BlastRootPrincipal, RootID: pid}, true
	}
}
