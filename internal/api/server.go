package api

import (
	"context"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/Zero0x00/cloudrift/internal/alerting"
	"github.com/Zero0x00/cloudrift/internal/api/handlers"
	"github.com/Zero0x00/cloudrift/internal/blastradius"
	"github.com/Zero0x00/cloudrift/internal/config"
	"github.com/Zero0x00/cloudrift/internal/queryv2"
)

func NewRouter(outputDir, configPath string, staticFS fs.FS) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(requestLogger)
	r.Use(middleware.Recoverer)
	r.Use(securityHeaders)

	// Optional auth: when CLOUDRIFT_API_TOKEN is set, gate the whole server (API + UI) behind
	// HTTP Basic auth. Unset → no auth (safe because the server defaults to a loopback bind).
	if token := strings.TrimSpace(os.Getenv(APITokenEnv)); token != "" {
		r.Use(basicAuthGate(token))
	}

	r.Mount("/api", apiRouter(outputDir, configPath))
	r.Mount("/", staticRouter(staticFS))
	return r
}

func apiRouter(outputDir, configPath string) http.Handler {
	r := chi.NewRouter()
	cfg, _ := config.Load(configPath)
	connCtx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	neo := blastradius.TryConnect(connCtx, cfg)
	cancel()
	blast := blastradius.NewService(neo, outputDir)

	alertSvc := alerting.NewService(outputDir, strings.TrimSpace(os.Getenv("CLOUDRIFT_APP_BASE_URL")), blast)
	querySvc := queryv2.NewService(outputDir, cfg, blast)
	queryHandler := handlers.NewQueryHandler(querySvc)
	control := handlers.NewScanControlCenter(outputDir, configPath)
	control.SetAlertService(alertSvc)
	alertingHandler := handlers.NewAlertingHandler(outputDir, alertSvc)
	r.Get("/scans", handlers.ListScans(outputDir))
	r.Get("/scans/{id}/summary", handlers.GetScanSummary(outputDir))
	r.Get("/scans/{id}/external-entities", handlers.ListExternalEntities(outputDir))
	r.Get("/scans/{id}/findings", handlers.ListFindings(outputDir))
	r.Get("/scans/{id}/remediation-groups", handlers.ListRemediationGroups(outputDir))
	r.Get("/scans/{id}/top-fixes", handlers.ListTopFixes(outputDir))
	r.Get("/scans/{id}/findings/{fid}", handlers.GetFinding(outputDir))
	r.Get("/scans/{id}/findings/{fid}/blast-radius/summary", handlers.BlastRadiusFindingSummary(blast, outputDir))
	r.Get("/scans/{id}/findings/{fid}/blast-radius/explorer", handlers.BlastRadiusFindingExplorer(blast, outputDir))
	r.Get("/scans/{id}/blast-radius/entity/summary", handlers.BlastRadiusEntitySummary(blast, outputDir))
	r.Get("/scans/{id}/blast-radius/entity/explorer", handlers.BlastRadiusEntityExplorer(blast, outputDir))
	r.Get("/scans/{id}/principals/blast-radius/summary", handlers.BlastRadiusPrincipalSummary(blast, outputDir))
	r.Get("/scans/{id}/principals/blast-radius/explorer", handlers.BlastRadiusPrincipalExplorer(blast, outputDir))
	r.Get("/scans/{id}/blast-radius/explorer/expand", handlers.BlastRadiusExplorerExpand(blast, outputDir))
	r.Get("/scans/{id}/accounts", handlers.ListAccounts(outputDir))
	r.Get("/scans/{id}/identities", handlers.ListIdentities(outputDir))
	r.Get("/scans/{id}/identities/profile", handlers.GetIdentityProfile(outputDir))
	r.Get("/scans/{id}/workloads", handlers.ListWorkloads(outputDir))
	r.Get("/scans/{id}/inventory/summary", handlers.InventorySummary(outputDir))
	r.Get("/scans/{id}/inventory/resources", handlers.InventoryResources(outputDir))
	r.Get("/scans/{id}/inventory/resource", handlers.InventoryResource(outputDir))
	r.Post("/scans/{id}/neo4j-export", control.ExportToNeo4j())
	r.Get("/diff", handlers.DiffScans(outputDir))
	r.Get("/scan/progress", handlers.ScanProgressWS(control))
	r.Get("/runtime/status", control.RuntimeStatus())
	r.Post("/runtime/validate-profile", control.ValidateProfile())
	r.Post("/runtime/sso-login", control.SSOLogin())
	r.Post("/scan/start", control.StartScan())
	r.Get("/scan/status", control.CurrentRunStatus())
	r.Get("/scan/history", control.RunHistory())
	r.Get("/alerts/catalog", alertingHandler.Catalog())
	r.Get("/alerts/routing", alertingHandler.GetRoutingCatalog())
	r.Put("/alerts/routing", alertingHandler.PutRoutingCatalog())
	r.Get("/alerts/rules", alertingHandler.ListRules())
	r.Get("/alerts/rules/{ruleID}", alertingHandler.GetRule())
	r.Post("/alerts/rules", alertingHandler.CreateRule())
	r.Put("/alerts/rules/{ruleID}", alertingHandler.UpdateRule())
	r.Post("/alerts/rules/{ruleID}/enable", alertingHandler.EnableRule(true))
	r.Post("/alerts/rules/{ruleID}/disable", alertingHandler.EnableRule(false))
	r.Post("/alerts/rules/{ruleID}/preview", alertingHandler.PreviewRule())
	r.Post("/alerts/rules/{ruleID}/test", alertingHandler.TestRule())
	r.Get("/alerts/events", alertingHandler.ListEvents())
	r.Post("/query", queryHandler.Query())
	return r
}

func StartServer(host string, port int, outputDir, configPath string, staticFS fs.FS) error {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	return http.ListenAndServe(addr, NewRouter(outputDir, configPath, staticFS))
}

// SetBuildVersion sets the tool version stamped into dashboard-initiated scans so it matches
// the binary's `cloudrift version`. Call once at startup before serving (empty is ignored).
func SetBuildVersion(v string) {
	handlers.SetBuildVersion(v)
}

func staticRouter(staticFS fs.FS) http.Handler {
	r := chi.NewRouter()
	if staticFS == nil {
		r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		})
		return r
	}

	fileServer := http.FileServer(http.FS(staticFS))
	r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		reqPath := path.Clean("/" + strings.TrimPrefix(r.URL.Path, "/"))
		if reqPath != "/" {
			trimmed := strings.TrimPrefix(reqPath, "/")
			if info, err := fs.Stat(staticFS, trimmed); err == nil && !info.IsDir() {
				// Hashed assets (JS/CSS in /assets/) are content-addressed: cache forever.
				// Everything else (fonts, icons, etc.) gets a short TTL.
				if strings.HasPrefix(reqPath, "/assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				} else {
					w.Header().Set("Cache-Control", "public, max-age=3600")
				}
				fileServer.ServeHTTP(w, r)
				return
			}
		}
		index, err := fs.ReadFile(staticFS, "index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		// index.html must never be cached: it references hashed bundle filenames that
		// change on every rebuild. A stale cached index.html causes blank pages.
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(index)
	})
	return r
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// script-src is locked to 'self' (no inline scripts — the Vite bundle is external), which
		// is the meaningful XSS hardening. style-src keeps 'unsafe-inline' because the UI's
		// CSS-in-JS (tremor/drei) injects inline <style>; worker-src allows the blast-explorer
		// blob worker (troika text). connect-src 'self' covers same-origin REST + the progress WS.
		w.Header().Set(
			"Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; font-src 'self' data:; connect-src 'self'; "+
				"worker-src 'self' blob:; frame-ancestors 'none'; base-uri 'self'",
		)
		next.ServeHTTP(w, r)
	})
}
