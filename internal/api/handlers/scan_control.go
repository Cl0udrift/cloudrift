package handlers

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/go-chi/chi/v5"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/Zero0x00/cloudrift/internal/alerting"
	"github.com/Zero0x00/cloudrift/internal/api/schema"
	cloudriftaws "github.com/Zero0x00/cloudrift/internal/aws"
	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/graph"
	"github.com/Zero0x00/cloudrift/internal/pipeline"
	"github.com/Zero0x00/cloudrift/internal/scans"
)

const scanStartVersion = "0.1.0"
const runHistoryLimit = 10

// buildVersion is the tool version stamped into dashboard-initiated scans' scan-metadata.json.
// It defaults to scanStartVersion and is overridden once at startup via SetBuildVersion so a
// scan started from the dashboard records the same version as `cloudrift version` (the
// git-tag-injected build version) rather than a hardcoded constant.
var buildVersion = scanStartVersion

// SetBuildVersion sets the version stamped into dashboard-initiated scan metadata. Call once
// at process startup, before the server begins handling requests. Empty values are ignored.
func SetBuildVersion(v string) {
	if strings.TrimSpace(v) != "" {
		buildVersion = v
	}
}

type scanControlCenter struct {
	outputDir  string
	configPath string
	alertSvc   *alerting.Service

	mu      sync.RWMutex
	current schema.ScanRunStatusResponse
	history []schema.ScanRunHistoryItem
}

func NewScanControlCenter(outputDir, configPath string) *scanControlCenter {
	return &scanControlCenter{
		outputDir:  outputDir,
		configPath: configPath,
		current: schema.ScanRunStatusResponse{
			Status:  "idle",
			Stage:   "idle",
			Message: "no scan is running",
		},
		history: make([]schema.ScanRunHistoryItem, 0, runHistoryLimit),
	}
}

func (s *scanControlCenter) SetAlertService(svc *alerting.Service) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alertSvc = svc
}

func regionPlanNote(mode string, regions []string) string {
	switch mode {
	case config.RegionModeAuto:
		return "Automatic: after this scan starts, Cloudrift will discover enabled Regions separately for every assumed account. Discovery has not run yet."
	case config.RegionModeExplicit:
		return "Explicit: this scan will read only the configured Region allowlist (" + strings.Join(regions, ", ") + "). Regions outside that list are not scanned."
	default:
		return "Legacy: with CIEM off and no aws.regions list, regional workloads stay on us-east-1. That is not full enabled-Region coverage. Turning on CIEM for this run switches an empty list to automatic discovery."
	}
}

func scanModePlan(cfg *config.Config) (string, string) {
	mode, err := config.ResolveScanMode(cfg)
	if err != nil {
		return "", err.Error()
	}
	switch mode {
	case config.ScanModeOrganization:
		return mode, "Organization: lists the organization's accounts and assumes the audit role in each. The scan fails if this account is not in an organization."
	case config.ScanModeAccount:
		return mode, "Single account: scans only the account the credentials belong to. Organizations is not called."
	}
	return mode, "Auto: uses the organization when this account is in one. If it is not, only this account is scanned and the scan says so."
}

func (s *scanControlCenter) RuntimeStatus() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg, err := config.Load(s.configPath)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "config_load_error", "failed to load runtime config", nil)
			return
		}
		profiles := discoverAWSProfiles()
		mode, regions, modeErr := config.ResolveRegionMode(cfg)
		note := regionPlanNote(mode, regions)
		if modeErr != nil {
			mode = ""
			note = modeErr.Error()
		}
		if regions == nil {
			regions = []string{}
		}
		scanMode, scanModeNote := scanModePlan(cfg)
		resp := schema.RuntimeStatusResponse{
			AWSProfiles:      profiles,
			DefaultProfile:   defaultProfile(cfg),
			OpenAIConfigured: strings.TrimSpace(os.Getenv(strings.TrimSpace(cfg.Embeddings.OpenaiAPIKeyEnv))) != "",
			Neo4jConfigured:  neo4jConfigured(cfg),
			SlackConfigured:  strings.TrimSpace(os.Getenv("CLOUDRIFT_SLACK_WEBHOOK_URL")) != "",
			EmailConfigured:  strings.TrimSpace(os.Getenv("CLOUDRIFT_ALERT_EMAIL_TO")) != "",
			RegionMode:       mode,
			ExplicitRegions:  regions,
			CIEMConfigured:   cfg.Scan.IAMPolicyInventory,
			RegionPlanNote:   note,
			ScanMode:         scanMode,
			ScanModePlanNote: scanModeNote,
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

func (s *scanControlCenter) ValidateProfile() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg, err := config.Load(s.configPath)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "config_load_error", "failed to load runtime config", nil)
			return
		}
		var req schema.ValidateProfileRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_json", "invalid request JSON", nil)
			return
		}
		profile := strings.TrimSpace(req.Profile)
		if profile == "" {
			profile = defaultProfile(cfg)
		}
		resp, status := validateCredentialSource(r.Context(), profile)
		writeJSON(w, status, resp)
	}
}

func (s *scanControlCenter) StartScan() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg, err := config.Load(s.configPath)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "config_load_error", "failed to load runtime config", nil)
			return
		}
		var req schema.ScanStartRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_json", "invalid request JSON", nil)
			return
		}
		req.Profile = strings.TrimSpace(req.Profile)
		req.Module = strings.TrimSpace(req.Module)
		req.Provider = strings.TrimSpace(req.Provider)
		if req.Profile == "" {
			req.Profile = defaultProfile(cfg)
		}
		if req.Provider != "" && req.Provider != "openai" && req.Provider != "local" {
			writeError(w, http.StatusBadRequest, "invalid_provider", "provider must be openai|local when set", nil)
			return
		}
		if req.Module == "" {
			req.Module = "all"
		}
		if req.Module != "all" && req.Module != "orphaned_edge" && req.Module != "external_access" {
			writeError(w, http.StatusBadRequest, "invalid_module", "module must be all|orphaned_edge|external_access", nil)
			return
		}

		s.mu.Lock()
		if s.current.Status == "running" {
			s.mu.Unlock()
			writeError(w, http.StatusConflict, "scan_running", "a scan is already running", nil)
			return
		}
		runID := fmt.Sprintf("run-%d", time.Now().UTC().UnixNano())
		now := time.Now().UTC()
		s.current = schema.ScanRunStatusResponse{
			RunID:         runID,
			Status:        "running",
			Stage:         "starting",
			Message:       "validating profile and preparing scan",
			Profile:       req.Profile,
			Module:        req.Module,
			NoHTTP:        req.NoHTTP,
			Neo4j:         req.Neo4j,
			Provider:      req.Provider,
			StartedAt:     now,
			LastUpdatedAt: now,
		}
		s.mu.Unlock()

		go s.runScanAsync(req, cfg, runID)

		writeJSON(w, http.StatusAccepted, schema.ScanStartResponse{
			RunID:   runID,
			Status:  "running",
			Message: "scan started",
		})
	}
}

func (s *scanControlCenter) CurrentRunStatus() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		current := s.current
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, current)
	}
}

func (s *scanControlCenter) RunHistory() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		// Use a non-nil empty slice so JSON is [] not null (matches API shape-stability docs).
		items := append([]schema.ScanRunHistoryItem{}, s.history...)
		s.mu.RUnlock()
		writeJSON(w, http.StatusOK, schema.ScanRunHistoryResponse{Items: items})
	}
}

func (s *scanControlCenter) CurrentProgressEvent() schema.ScanProgressEvent {
	s.mu.RLock()
	current := s.current
	s.mu.RUnlock()
	return schema.ScanProgressEvent{
		EventType:         "progress",
		ScanID:            current.ScanID,
		Stage:             current.Stage,
		Message:           current.Message,
		CompletedAccounts: 0,
		TotalAccounts:     0,
		Timestamp:         time.Now().UTC(),
	}
}

func (s *scanControlCenter) runScanAsync(req schema.ScanStartRequest, cfg *config.Config, runID string) {
	s.updateRun(runID, "running", "validating_profile", "validating AWS profile")
	if resp, _ := validateCredentialSource(context.Background(), req.Profile); !resp.OK {
		s.failRun(runID, fmt.Sprintf("profile validation failed: %s", resp.Message))
		return
	}
	s.updateRun(runID, "running", "scanning", "running scan")

	// Honor the dashboard profile picker: the selected profile drives credential loading.
	if req.Profile != "" {
		cfg.AWS.ManagementProfile = req.Profile
	}
	if req.CIEM {
		config.EnableCIEM(cfg)
	}
	// Capture the coverage warning (if any) streamed by the pipeline so the final
	// completion message reflects partial coverage instead of a misleading "scan completed".
	var coverageWarning string
	scanOpts := pipeline.Options{
		NoHTTP: req.NoHTTP,
		Progress: func(stage, message string) {
			if stage == "coverage" {
				coverageWarning = message
			}
			// Warnings advance the run log but must not overwrite the active stage/message.
			if stage == "warning" {
				s.appendLog(runID, "warning: "+message)
				return
			}
			s.appendLog(runID, stage+": "+message)
			// Stream each stage live to the WS progress channel and /api/scan/status.
			s.updateRun(runID, "running", stage, message)
		},
	}
	if req.Module != "" && req.Module != "all" {
		scanOpts.Modules = []string{req.Module}
	}
	scanID, err := pipeline.Run(context.Background(), cfg, s.outputDir, buildVersion, pipeline.NewAWSSource(), scanOpts)
	if err != nil {
		s.failRun(runID, fmt.Sprintf("scan failed: %v", err))
		return
	}
	s.updateRunWithScanID(runID, "running", "scan_complete", "scan artifacts created", scanID)

	if req.Neo4j {
		s.updateRun(runID, "running", "neo4j_export", "exporting scan to Neo4j")
		if _, err := exportScanToNeo4j(context.Background(), cfg, filepath.Join(s.outputDir, scanID)); err != nil {
			s.failRun(runID, fmt.Sprintf("scan completed, but Neo4j export failed: %v", err))
			return
		}
	}

	s.mu.RLock()
	alertSvc := s.alertSvc
	s.mu.RUnlock()
	if alertSvc != nil {
		// Alerting failure should not fail scan completion path.
		_, _ = alertSvc.EvaluateEnabledRulesForScan(scanID)
	}

	completionMsg := "scan completed"
	if coverageWarning != "" {
		completionMsg = "scan completed - " + coverageWarning
	}
	s.finishRun(runID, scanID, completionMsg)
}

// scanLogLimit caps the per-run log so a large scan cannot grow the status payload without bound.
const scanLogLimit = 500

// appendLog adds a timestamped line to the current run's log (for dashboard diagnostics).
func (s *scanControlCenter) appendLog(runID, line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current.RunID != runID {
		return
	}
	entry := time.Now().UTC().Format("15:04:05") + " " + line
	s.current.Log = append(s.current.Log, entry)
	if len(s.current.Log) > scanLogLimit {
		s.current.Log = s.current.Log[len(s.current.Log)-scanLogLimit:]
	}
}

func (s *scanControlCenter) updateRun(runID, status, stage, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current.RunID != runID {
		return
	}
	s.current.Status = status
	s.current.Stage = stage
	s.current.Message = message
	s.current.LastUpdatedAt = time.Now().UTC()
}

func (s *scanControlCenter) updateRunWithScanID(runID, status, stage, message, scanID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current.RunID != runID {
		return
	}
	s.current.Status = status
	s.current.Stage = stage
	s.current.Message = message
	s.current.ScanID = scanID
	s.current.LastUpdatedAt = time.Now().UTC()
}

func (s *scanControlCenter) failRun(runID, message string) {
	// Log every scan failure so the reason is visible in the server logs, not only in the
	// /api/scan/status response. Without this, a failed dashboard scan produced no log line.
	slog.Error("scan run failed", "run_id", runID, "reason", message)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current.RunID != runID {
		return
	}
	now := time.Now().UTC()
	s.current.Status = "failed"
	s.current.Stage = "failed"
	s.current.Message = message
	s.current.FinishedAt = now
	s.current.LastUpdatedAt = now
	s.current.Log = append(s.current.Log, now.Format("15:04:05")+" FAILED: "+message)
	s.appendHistoryLocked(schema.ScanRunHistoryItem{
		RunID:      s.current.RunID,
		StartedAt:  s.current.StartedAt,
		FinishedAt: s.current.FinishedAt,
		Status:     s.current.Status,
		Profile:    s.current.Profile,
		Module:     s.current.Module,
		NoHTTP:     s.current.NoHTTP,
		Neo4j:      s.current.Neo4j,
		Message:    s.current.Message,
	})
}

func (s *scanControlCenter) finishRun(runID, scanID, message string) {
	slog.Info("scan run completed", "run_id", runID, "scan_id", scanID, "message", message)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current.RunID != runID {
		return
	}
	now := time.Now().UTC()
	s.current.Status = "completed"
	s.current.Stage = "completed"
	s.current.Message = message
	s.current.ScanID = scanID
	s.current.FinishedAt = now
	s.current.LastUpdatedAt = now
	s.current.Log = append(s.current.Log, now.Format("15:04:05")+" DONE: "+message)
	s.appendHistoryLocked(schema.ScanRunHistoryItem{
		RunID:      s.current.RunID,
		StartedAt:  s.current.StartedAt,
		FinishedAt: s.current.FinishedAt,
		Status:     s.current.Status,
		Profile:    s.current.Profile,
		Module:     s.current.Module,
		NoHTTP:     s.current.NoHTTP,
		Neo4j:      s.current.Neo4j,
		Message:    s.current.Message,
	})
}

func (s *scanControlCenter) appendHistoryLocked(item schema.ScanRunHistoryItem) {
	// Newest first for operator UX; bounded ring behavior via truncation.
	s.history = append([]schema.ScanRunHistoryItem{item}, s.history...)
	if len(s.history) > runHistoryLimit {
		s.history = s.history[:runHistoryLimit]
	}
}

func validateCredentialSource(ctx context.Context, profile string) (schema.ValidateProfileResponse, int) {
	profile = strings.TrimSpace(profile)
	loadOpts := []func(*awsconfig.LoadOptions) error{awsconfig.WithDefaultRegion("us-east-1")}
	if profile != "" {
		loadOpts = append(loadOpts, awsconfig.WithSharedConfigProfile(profile))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		resp := schema.ValidateProfileResponse{OK: false, Profile: profile, Message: "could not resolve credentials/config from selected source"}
		if cloudriftaws.IsSSOExpiredError(err) {
			resp.Message = ssoExpiredMessage(profile)
			resp.SSOLoginRequired = true
			resp.SSOCommand = cloudriftaws.SSOLoginCommand(profile)
			return resp, http.StatusOK
		}
		return resp, http.StatusBadRequest
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err = sts.NewFromConfig(cfg).GetCallerIdentity(cctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		resp := schema.ValidateProfileResponse{OK: false, Profile: profile, Message: "credential source resolved, but caller identity check failed"}
		if cloudriftaws.IsSSOExpiredError(err) {
			resp.Message = ssoExpiredMessage(profile)
			resp.SSOLoginRequired = true
			resp.SSOCommand = cloudriftaws.SSOLoginCommand(profile)
			return resp, http.StatusOK
		}
		return resp, http.StatusBadRequest
	}
	msg := "profile is valid and credentials are usable"
	if profile == "" {
		msg = "ambient credential source is valid (env/role/shared config)"
	}
	return schema.ValidateProfileResponse{OK: true, Profile: profile, Message: msg}, http.StatusOK
}

func ssoExpiredMessage(profile string) string {
	if profile == "" {
		return "AWS SSO session expired"
	}
	return fmt.Sprintf("AWS SSO session expired for profile %q", profile)
}

func (s *scanControlCenter) SSOLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req schema.SSOLoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_json", "invalid request JSON", nil)
			return
		}
		profile := strings.TrimSpace(req.Profile)
		ssoCmd := cloudriftaws.SSOLoginCommand(profile)
		started, err := cloudriftaws.TriggerSSOLogin(profile)
		if !started {
			writeJSON(w, http.StatusOK, schema.SSOLoginResponse{
				Started: false,
				Message: "aws CLI not found; run manually: " + ssoCmd,
				Command: ssoCmd,
			})
			return
		}
		if err != nil {
			writeJSON(w, http.StatusOK, schema.SSOLoginResponse{
				Started: false,
				Message: "failed to start aws sso login; run manually: " + ssoCmd,
				Command: ssoCmd,
			})
			return
		}
		writeJSON(w, http.StatusOK, schema.SSOLoginResponse{
			Started: true,
			Message: "browser opened for SSO authentication; validate the profile once login completes",
			Command: ssoCmd,
		})
	}
}

func defaultProfile(cfg *config.Config) string {
	if fromEnv := strings.TrimSpace(os.Getenv("AWS_PROFILE")); fromEnv != "" {
		return fromEnv
	}
	return strings.TrimSpace(cfg.AWS.ManagementProfile)
}

func neo4jConfigured(cfg *config.Config) bool {
	if strings.TrimSpace(cfg.Neo4j.URI) == "" || strings.TrimSpace(cfg.Neo4j.Username) == "" {
		return false
	}
	// Password may come from an env var, an inline value, or a file (see Neo4jPassword).
	return cfg.Neo4jPassword() != ""
}

func discoverAWSProfiles() []string {
	paths := awsProfileFilePaths()

	seen := map[string]struct{}{}
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			ln := scanner.Text()
			ln = strings.TrimSpace(ln)
			if !strings.HasPrefix(ln, "[") || !strings.HasSuffix(ln, "]") {
				continue
			}
			section := strings.TrimSuffix(strings.TrimPrefix(ln, "["), "]")
			section = strings.TrimSpace(section)
			section = strings.TrimPrefix(section, "profile ")
			section = strings.TrimSpace(section)
			if section == "" {
				continue
			}
			seen[section] = struct{}{}
		}
		_ = f.Close()
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func awsProfileFilePaths() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	base := filepath.Join(home, ".aws")
	paths := []string{
		filepath.Join(base, "config"),
		filepath.Join(base, "credentials"),
	}
	if cfg, ok := safeAWSConfigPathFromEnv("AWS_CONFIG_FILE", base); ok {
		paths[0] = cfg
	}
	if creds, ok := safeAWSConfigPathFromEnv("AWS_SHARED_CREDENTIALS_FILE", base); ok {
		paths[1] = creds
	}
	return paths
}

func safeAWSConfigPathFromEnv(envName, allowedDir string) (string, bool) {
	raw := strings.TrimSpace(os.Getenv(envName))
	if raw == "" {
		return "", false
	}
	clean := filepath.Clean(raw)
	if clean == "" {
		return "", false
	}
	if !filepath.IsAbs(clean) {
		return "", false
	}
	rel, err := filepath.Rel(allowedDir, clean)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return "", false
	}
	return clean, true
}

type neo4jExportResponse struct {
	ScanID    string `json:"scan_id"`
	Status    string `json:"status"`
	Neo4j     bool   `json:"neo4j"`
	Clustered bool   `json:"clustered"`
}

// ExportToNeo4j projects an existing on-disk scan into Neo4j on demand, without re-running
// a scan. It is the standalone counterpart to the post-scan export in runScanAsync — it lets
// the dashboard populate the graph from any scan already in output_dir (including demo data),
// so the blast-radius explorer and graph queries have something to traverse.
func (s *scanControlCenter) ExportToNeo4j() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg, err := config.Load(s.configPath)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "config_load_error", "failed to load runtime config", nil)
			return
		}
		if !neo4jConfigured(cfg) {
			writeError(w, http.StatusBadRequest, "neo4j_not_configured", "Neo4j is not configured (set neo4j.uri, neo4j.username, and the neo4j.password_env variable)", nil)
			return
		}
		scanID, ok := scanIDFromPath(s.outputDir, chi.URLParam(r, "id"))
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid_scan_id", "invalid or unknown scan id", nil)
			return
		}
		// Graph projection + best-effort embeddings can take a little while; bound it.
		ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
		defer cancel()
		clustered, err := exportScanToNeo4j(ctx, cfg, filepath.Join(s.outputDir, scanID))
		if err != nil {
			writeError(w, http.StatusBadGateway, "neo4j_export_failed", "failed to export scan to Neo4j", map[string]any{"detail": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, neo4jExportResponse{ScanID: scanID, Status: "exported", Neo4j: true, Clustered: clustered})
	}
}

// exportScanToNeo4j projects an on-disk scan into Neo4j and, best-effort, runs GDS
// clustering + centrality. The returned clustered flag is true only when GDS actually wrote
// community/centrality properties (GDS plugin present); a missing plugin yields clustered=false
// with no error, since the projection itself succeeded.
func exportScanToNeo4j(ctx context.Context, cfg *config.Config, scanPath string) (clustered bool, err error) {
	uri := strings.TrimSpace(cfg.Neo4j.URI)
	user := strings.TrimSpace(cfg.Neo4j.Username)
	if uri == "" || user == "" {
		return false, errors.New("neo4j configuration is incomplete")
	}
	pass := cfg.Neo4jPassword()
	if pass == "" {
		return false, errors.New("neo4j password is not set (configure password_env, password, or password_file)")
	}
	driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(user, pass, ""))
	if err != nil {
		return false, err
	}
	defer driver.Close(ctx)
	ex := graph.NewDriverExecer(driver, "")
	outDir, scanID := filepath.Dir(scanPath), filepath.Base(scanPath)
	meta, findings, err := scans.LoadScanArtifacts(outDir, scanID)
	if err != nil {
		return false, err
	}
	if meta == nil {
		return false, errors.New("scan metadata missing")
	}
	// Include assets + relationships so the projected graph is traversable (blast-radius /
	// attack paths). Previously these were passed empty, yielding a findings-only graph.
	assets, err := scans.LoadAssets(outDir, scanID)
	if err != nil {
		return false, err
	}
	rels, err := scans.LoadRelationships(outDir, scanID)
	if err != nil {
		return false, err
	}
	// Generate embeddings (best-effort) so the vector index is populated for RAG / query.
	graph.AttachEmbeddingsBestEffort(ctx, cfg, meta, findings)
	for _, ddl := range graph.SchemaStatements() {
		if err := ex.Run(ctx, ddl, nil); err != nil {
			return false, err
		}
	}
	if err := graph.WriteScan(ctx, ex, *meta, assets, rels, findings); err != nil {
		return false, err
	}
	// Best-effort GDS clustering (Louvain) + centrality (PageRank), written back as the
	// `community` / `centrality` node properties. Never fails the export: a missing GDS plugin
	// or analytics error returns ErrGDSUnavailable, which we treat as clustered=false.
	if gerr := graph.RunGDS(ctx, ex, scanID); gerr != nil {
		return false, nil
	}
	return true, nil
}
