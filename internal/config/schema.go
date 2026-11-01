package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"
)

// Field describes one setting the portal may edit. Secrets (inline Neo4j password and password file)
// are never listed here: the portal can neither read nor change them.
type Field struct {
	Key         string   `json:"key"`
	Group       string   `json:"group"`
	Label       string   `json:"label"`
	Description string   `json:"description"`
	Kind        string   `json:"kind"` // string, int, float, bool, list, enum
	Enum        []string `json:"enum,omitempty"`
	Min         *float64 `json:"min,omitempty"`
	Max         *float64 `json:"max,omitempty"`
	// Apply is next_scan when the next scan reads the value, or restart when the server read it at startup.
	Apply string `json:"apply"`

	check func(string) error
}

func num(v float64) *float64 { return &v }

var (
	envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	regionRe  = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]$`)
	accountRe = regexp.MustCompile(`^[0-9]{12}$`)
	roleRe    = regexp.MustCompile(`^[A-Za-z0-9+=,.@_-]{1,64}$`)
)

func noControl(s string) error {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("must not contain control characters")
		}
	}
	if len(s) > 512 {
		return fmt.Errorf("must be at most 512 characters")
	}
	return nil
}

// Schema lists every editable setting in display order.
func Schema() []Field {
	f := []Field{
		{Key: "output.output_dir", Group: "Storage", Label: "Output directory", Description: "Where scans are written and read. Relative paths resolve from where the server runs.", Kind: "string", Apply: "restart",
			check: func(s string) error {
				if strings.TrimSpace(s) == "" {
					return fmt.Errorf("must not be empty")
				}
				return noControl(s)
			}},

		{Key: "aws.org_role_name", Group: "AWS access", Label: "Org audit role name", Description: "Role assumed in each member account for org-wide scans. Empty means no-assume mode: scan only the caller's own account.", Kind: "string", Apply: "next_scan",
			check: func(s string) error {
				if s != "" && !roleRe.MatchString(s) {
					return fmt.Errorf("must be an IAM role name (letters, digits and +=,.@_-)")
				}
				return nil
			}},
		{Key: "aws.management_profile", Group: "AWS access", Label: "AWS profile", Description: "AWS profile or credentials used to start the scan.", Kind: "string", Apply: "next_scan", check: noControl},
		{Key: "aws.region_discovery", Group: "AWS access", Label: "Region discovery", Description: "auto discovers enabled Regions, explicit uses the list below, legacy_default stays on us-east-1 and is not full coverage. Default follows the scan type.", Kind: "enum", Enum: []string{"", "auto", "explicit", "legacy_default"}, Apply: "next_scan"},
		{Key: "aws.regions", Group: "AWS access", Label: "Region allowlist", Description: "When set, only these Regions are collected. Cannot be combined with region discovery = auto.", Kind: "list", Apply: "next_scan",
			check: func(s string) error {
				if !regionRe.MatchString(s) {
					return fmt.Errorf("%q is not a Region name such as us-east-1", s)
				}
				return nil
			}},

		{Key: "scan.iam_policy_inventory", Group: "Collection", Label: "IAM role policies (core CIEM data)", Description: "Collect every IAM role and its policy documents. The permission matrix, the evaluator and the attack search depend on it. Turn off only to keep the older scan that reads just roles trusting an external account. A scan started with the CIEM option collects it regardless.", Kind: "bool", Apply: "next_scan"},
		{Key: "scan.resource_policies", Group: "Collection", Label: "Resource policies (opt-in)", Description: "Collect Secrets Manager and KMS resource policies, Lambda policies and RDS instances. Never reads secret values. Needs extra read permissions.", Kind: "bool", Apply: "next_scan"},
		{Key: "scan.service_last_accessed", Group: "Collection", Label: "Service last-accessed (opt-in)", Description: "Collect IAM access advisor data per role. Needs two extra IAM read actions.", Kind: "bool", Apply: "next_scan"},
		{Key: "scan.service_last_accessed_granularity", Group: "Collection", Label: "Last-accessed granularity", Description: "service, or action for the few services AWS tracks at action level.", Kind: "enum", Enum: []string{"", "service", "action"}, Apply: "next_scan"},
		{Key: "scan.service_last_accessed_concurrency", Group: "Collection", Label: "Last-accessed concurrency", Description: "Parallel access-advisor jobs. 0 uses the default of 8. Maximum 16.", Kind: "int", Min: num(0), Max: num(16), Apply: "next_scan"},
		{Key: "scan.service_last_accessed_skip_service_linked", Group: "Collection", Label: "Skip service-linked roles", Description: "Reduce scope by skipping AWS-owned service-linked roles in last-accessed collection.", Kind: "bool", Apply: "next_scan"},
		{Key: "scan.service_last_accessed_timeout_seconds", Group: "Collection", Label: "Last-accessed time budget", Description: "Total seconds per account. 0 means no limit. Roles not finished are recorded as not collected.", Kind: "int", Min: num(0), Max: num(86400), Apply: "next_scan"},

		{Key: "scan.http_probe_concurrency", Group: "Performance", Label: "HTTP probe concurrency", Description: "Parallel HTTP probes against edge resources.", Kind: "int", Min: num(1), Max: num(500), Apply: "next_scan"},
		{Key: "scan.role_assumption_concurrency", Group: "Performance", Label: "Account concurrency", Description: "Member accounts scanned in parallel.", Kind: "int", Min: num(1), Max: num(100), Apply: "next_scan"},
		{Key: "scan.http_timeout_seconds", Group: "Performance", Label: "HTTP timeout (seconds)", Description: "Timeout for each HTTP probe.", Kind: "int", Min: num(1), Max: num(120), Apply: "next_scan"},
		{Key: "scan.user_agent", Group: "Performance", Label: "HTTP user agent", Description: "User agent sent by HTTP probes.", Kind: "string", Apply: "next_scan",
			check: func(s string) error {
				if strings.TrimSpace(s) == "" {
					return fmt.Errorf("must not be empty")
				}
				return noControl(s)
			}},

		{Key: "trust.approved_external_accounts", Group: "Trust policy", Label: "Approved external accounts", Description: "AWS account IDs treated as approved cross-account principals.", Kind: "list", Apply: "next_scan",
			check: func(s string) error {
				if !accountRe.MatchString(s) {
					return fmt.Errorf("%q is not a 12-digit account ID", s)
				}
				return nil
			}},
		{Key: "trust.stale_threshold_days", Group: "Trust policy", Label: "Stale after (days)", Description: "A role unused this long is reported as stale.", Kind: "int", Min: num(1), Max: num(3650), Apply: "next_scan"},
		{Key: "trust.ghost_threshold_days", Group: "Trust policy", Label: "Ghost after (days)", Description: "A role unused this long is reported as a ghost.", Kind: "int", Min: num(1), Max: num(3650), Apply: "next_scan"},

		{Key: "cost.currency", Group: "Cost", Label: "Currency", Description: "Currency label for cost figures.", Kind: "string", Apply: "next_scan",
			check: func(s string) error {
				if !regexp.MustCompile(`^[A-Z]{3}$`).MatchString(s) {
					return fmt.Errorf("must be a three-letter code such as USD")
				}
				return nil
			}},
		{Key: "cost.risk_multiplier_reclaimable", Group: "Cost", Label: "Reclaimable risk multiplier", Description: "Multiplier applied to reclaimable-asset cost when computing risk cost.", Kind: "float", Min: num(0), Max: num(100), Apply: "next_scan"},
		{Key: "cost.risk_multiplier_dangling", Group: "Cost", Label: "Dangling risk multiplier", Description: "Multiplier applied to dangling-resource cost when computing risk cost.", Kind: "float", Min: num(0), Max: num(100), Apply: "next_scan"},
		{Key: "cost.use_cur", Group: "Cost", Label: "Use Cost Explorer data", Description: "Enrich cost figures with Cost Explorer data. Off means estimates only.", Kind: "bool", Apply: "next_scan"},

		{Key: "neo4j.uri", Group: "Graph database", Label: "Neo4j URI", Description: "Optional graph store for Blast Explorer and query.", Kind: "string", Apply: "restart",
			check: func(s string) error {
				for _, p := range []string{"bolt://", "bolt+s://", "bolt+ssc://", "neo4j://", "neo4j+s://", "neo4j+ssc://"} {
					if strings.HasPrefix(s, p) && len(s) > len(p) {
						return nil
					}
				}
				return fmt.Errorf("must start with bolt:// or neo4j://")
			}},
		{Key: "neo4j.username", Group: "Graph database", Label: "Neo4j username", Description: "Database user.", Kind: "string", Apply: "restart", check: noControl},
		{Key: "neo4j.password_env", Group: "Graph database", Label: "Neo4j password variable", Description: "Name of the environment variable that holds the password. Passwords are never entered here.", Kind: "string", Apply: "restart",
			check: func(s string) error {
				if s != "" && !envNameRe.MatchString(s) {
					return fmt.Errorf("must be an environment variable name")
				}
				return nil
			}},

		{Key: "embeddings.provider", Group: "Query and AI", Label: "Embeddings provider", Description: "openai is the only operational provider today. local is a placeholder that always fails.", Kind: "enum", Enum: []string{"openai", "local"}, Apply: "restart"},
		{Key: "embeddings.openai_api_key_env", Group: "Query and AI", Label: "OpenAI key variable", Description: "Name of the environment variable that holds the API key.", Kind: "string", Apply: "restart",
			check: func(s string) error {
				if !envNameRe.MatchString(s) {
					return fmt.Errorf("must be an environment variable name")
				}
				return nil
			}},
		{Key: "synthesis.provider", Group: "Query and AI", Label: "Answer provider", Description: "Provider for natural-language answers in query.", Kind: "enum", Enum: []string{"anthropic"}, Apply: "restart"},
		{Key: "synthesis.model", Group: "Query and AI", Label: "Answer model", Description: "Model name sent to the answer provider.", Kind: "string", Apply: "restart",
			check: func(s string) error {
				if strings.TrimSpace(s) == "" {
					return fmt.Errorf("must not be empty")
				}
				return noControl(s)
			}},
		{Key: "synthesis.api_key_env", Group: "Query and AI", Label: "Answer key variable", Description: "Name of the environment variable that holds the API key. Answers run only when it is set.", Kind: "string", Apply: "restart",
			check: func(s string) error {
				if !envNameRe.MatchString(s) {
					return fmt.Errorf("must be an environment variable name")
				}
				return nil
			}},
		{Key: "synthesis.max_tokens", Group: "Query and AI", Label: "Answer length cap", Description: "Maximum tokens in a synthesized answer.", Kind: "int", Min: num(1), Max: num(100000), Apply: "restart"},
	}
	return f
}

// lookup finds the struct field whose toml tags spell key, such as scan.http_timeout_seconds.
func lookup(cfg *Config, key string) (reflect.Value, bool) {
	section, name, ok := strings.Cut(key, ".")
	if !ok {
		return reflect.Value{}, false
	}
	root := reflect.ValueOf(cfg).Elem()
	rt := root.Type()
	for i := 0; i < rt.NumField(); i++ {
		if rt.Field(i).Tag.Get("toml") != section {
			continue
		}
		sec := root.Field(i)
		st := sec.Type()
		for j := 0; j < st.NumField(); j++ {
			if st.Field(j).Tag.Get("toml") == name {
				return sec.Field(j), true
			}
		}
	}
	return reflect.Value{}, false
}

func fieldByKey(key string) (Field, bool) {
	for _, f := range Schema() {
		if f.Key == key {
			return f, true
		}
	}
	return Field{}, false
}

// Get returns the current value of a schema key.
func Get(cfg *Config, key string) any {
	v, ok := lookup(cfg, key)
	if !ok {
		return nil
	}
	if v.Kind() == reflect.Slice {
		out := make([]string, 0, v.Len())
		for i := 0; i < v.Len(); i++ {
			out = append(out, v.Index(i).String())
		}
		return out
	}
	return v.Interface()
}

// Set validates raw (a decoded JSON value) for key and stores it in cfg.
func Set(cfg *Config, key string, raw any) error {
	f, ok := fieldByKey(key)
	if !ok {
		return fmt.Errorf("unknown setting")
	}
	v, ok := lookup(cfg, key)
	if !ok {
		return fmt.Errorf("unknown setting")
	}
	switch f.Kind {
	case "bool":
		b, ok := raw.(bool)
		if !ok {
			return fmt.Errorf("must be true or false")
		}
		v.SetBool(b)
	case "int", "float":
		n, ok := toFloat(raw)
		if !ok {
			return fmt.Errorf("must be a number")
		}
		if f.Kind == "int" && n != float64(int64(n)) {
			return fmt.Errorf("must be a whole number")
		}
		if f.Min != nil && n < *f.Min || f.Max != nil && n > *f.Max {
			return fmt.Errorf("must be between %s and %s", strconv.FormatFloat(*f.Min, 'f', -1, 64), strconv.FormatFloat(*f.Max, 'f', -1, 64))
		}
		if f.Kind == "int" {
			v.SetInt(int64(n))
		} else {
			v.SetFloat(n)
		}
	case "enum":
		s, ok := raw.(string)
		if !ok {
			return fmt.Errorf("must be text")
		}
		for _, e := range f.Enum {
			if e == s {
				v.SetString(s)
				return nil
			}
		}
		return fmt.Errorf("must be one of %q", f.Enum)
	case "list":
		items, ok := raw.([]any)
		if !ok {
			return fmt.Errorf("must be a list")
		}
		out := make([]string, 0, len(items))
		for _, it := range items {
			s, ok := it.(string)
			if !ok {
				return fmt.Errorf("list items must be text")
			}
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if f.check != nil {
				if err := f.check(s); err != nil {
					return err
				}
			}
			out = append(out, s)
		}
		v.Set(reflect.ValueOf(out))
	default:
		s, ok := raw.(string)
		if !ok {
			return fmt.Errorf("must be text")
		}
		s = strings.TrimSpace(s)
		if f.check != nil {
			if err := f.check(s); err != nil {
				return err
			}
		}
		v.SetString(s)
	}
	return nil
}

func toFloat(raw any) (float64, bool) {
	switch n := raw.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

// ValidateCross checks rules that span settings.
func ValidateCross(cfg *Config) error {
	if _, _, err := ResolveRegionMode(cfg); err != nil {
		return err
	}
	return nil
}

// SecretState says whether a secret is set, without revealing it.
type SecretState struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	State string `json:"state"`
	Note  string `json:"note"`
}

// Secrets reports the settings the portal never shows or edits.
func Secrets(cfg *Config) []SecretState {
	state := func(set bool) string {
		if set {
			return "set"
		}
		return "unset"
	}
	return []SecretState{
		{"neo4j.password", "Neo4j inline password", state(strings.TrimSpace(cfg.Neo4j.Password) != ""), "Stored in the config file in plain text. Prefer the password variable above and remove this value by hand."},
		{"neo4j.password_file", "Neo4j password file", state(strings.TrimSpace(cfg.Neo4j.PasswordFile) != ""), "A path to a file holding the password. Edit it in the config file."},
	}
}

var writeMu sync.Mutex

// ResolvePath returns the config file the server reads and writes.
func ResolvePath(path string) string {
	if path != "" {
		return path
	}
	return resolveDefaultPath()
}

// Save writes cfg to path atomically and keeps the previous file as path + ".bak".
// Only values that differ from the built-in defaults are written, so a default that changes in a
// later release still reaches users who never set it. Comments in the old file are not preserved. The file is private to the owner because it can
// hold an inline password.
func Save(path string, cfg *Config) (backup string, err error) {
	writeMu.Lock()
	defer writeMu.Unlock()
	path = ResolvePath(path)
	if old, rerr := os.ReadFile(path); rerr == nil {
		backup = path + ".bak"
		if err := os.WriteFile(backup, old, 0o600); err != nil {
			return "", fmt.Errorf("write backup: %w", err)
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".cloudrift-config-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return "", err
	}
	if err := toml.NewEncoder(tmp).Encode(nonDefault(cfg)); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	return backup, os.Rename(tmp.Name(), path)
}

// nonDefault returns the sections and keys of cfg that differ from Default(), keyed by toml names.
func nonDefault(cfg *Config) map[string]map[string]any {
	def := reflect.ValueOf(Default()).Elem()
	cur := reflect.ValueOf(cfg).Elem()
	out := map[string]map[string]any{}
	for i := 0; i < cur.NumField(); i++ {
		section := cur.Type().Field(i).Tag.Get("toml")
		if section == "" {
			continue
		}
		cs, ds := cur.Field(i), def.Field(i)
		for j := 0; j < cs.NumField(); j++ {
			name := cs.Type().Field(j).Tag.Get("toml")
			a, b := cs.Field(j), ds.Field(j)
			if name == "" || (a.Kind() == reflect.Slice && a.Len() == 0 && b.Len() == 0) || reflect.DeepEqual(a.Interface(), b.Interface()) {
				continue
			}
			if out[section] == nil {
				out[section] = map[string]any{}
			}
			out[section][name] = a.Interface()
		}
	}
	return out
}
