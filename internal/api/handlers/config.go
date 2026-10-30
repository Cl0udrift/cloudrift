package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"

	"github.com/Zero0x00/cloudrift/internal/config"
)

// ConfigField is one editable setting with its current and default value.
type ConfigField struct {
	config.Field
	Value   any    `json:"value"`
	Default any    `json:"default"`
	Source  string `json:"source"` // default or custom
}

// ConfigResponse is the settings page payload. Secret values are never included.
type ConfigResponse struct {
	Path            string               `json:"path"`
	Exists          bool                 `json:"exists"`
	Fields          []ConfigField        `json:"fields"`
	Secrets         []config.SecretState `json:"secrets"`
	RestartRequired bool                 `json:"restart_required,omitempty"`
	Backup          string               `json:"backup,omitempty"`
	Note            string               `json:"note"`
}

const configNote = "Saving rewrites the config file from these settings and keeps the previous file as a .bak copy. Comments in the old file are not kept. Settings marked restart are read when the server starts."

func buildConfigResponse(path string) (ConfigResponse, *config.Config, error) {
	path = config.ResolvePath(path)
	cfg, err := config.Load(path)
	if err != nil {
		return ConfigResponse{}, nil, err
	}
	def := config.Default()
	_, statErr := os.Stat(path)
	resp := ConfigResponse{Path: path, Exists: statErr == nil, Secrets: config.Secrets(cfg), Note: configNote}
	for _, f := range config.Schema() {
		v, d := config.Get(cfg, f.Key), config.Get(def, f.Key)
		source := "default"
		if !reflect.DeepEqual(v, d) {
			source = "custom"
		}
		resp.Fields = append(resp.Fields, ConfigField{Field: f, Value: v, Default: d, Source: source})
	}
	return resp, cfg, nil
}

// GetConfig returns the editable settings.
func GetConfig(configPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp, _, err := buildConfigResponse(configPath)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "config_unreadable", "The config file could not be read: "+err.Error(), nil)
			return
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// sameOrigin rejects browser requests that come from another origin. The server has no login by
// default, so a page on another site must not be able to change settings.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	return err == nil && strings.EqualFold(u.Host, r.Host)
}

// PutConfig validates and saves a set of changed settings.
func PutConfig(configPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !sameOrigin(r) {
			writeError(w, http.StatusForbidden, "cross_origin", "Settings can only be changed from the dashboard itself.", nil)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			writeError(w, http.StatusUnsupportedMediaType, "bad_content_type", "Send the settings as application/json.", nil)
			return
		}
		var body struct {
			Values map[string]any `json:"values"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil || len(body.Values) == 0 {
			writeError(w, http.StatusBadRequest, "bad_request", "Send {\"values\": {\"key\": value}} with at least one setting.", nil)
			return
		}
		before, cfg, err := buildConfigResponse(configPath)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "config_unreadable", "The config file could not be read: "+err.Error(), nil)
			return
		}
		errs := map[string]any{}
		restart := false
		apply := map[string]string{}
		for _, f := range before.Fields {
			apply[f.Key] = f.Apply
		}
		for key, raw := range body.Values {
			if err := config.Set(cfg, key, raw); err != nil {
				errs[key] = err.Error()
				continue
			}
			if apply[key] == "restart" {
				restart = true
			}
		}
		if len(errs) == 0 {
			if err := config.ValidateCross(cfg); err != nil {
				errs["_"] = err.Error()
			}
		}
		if len(errs) > 0 {
			writeError(w, http.StatusBadRequest, "invalid_settings", "Some settings were not valid. Nothing was saved.", errs)
			return
		}
		backup, err := config.Save(configPath, cfg)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "config_unwritable", "The config file could not be written: "+err.Error(), nil)
			return
		}
		resp, _, err := buildConfigResponse(configPath)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "config_unreadable", err.Error(), nil)
			return
		}
		resp.RestartRequired, resp.Backup = restart, backup
		writeJSON(w, http.StatusOK, resp)
	}
}
