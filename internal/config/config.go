package config

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

type Config struct {
	AWS struct {
		OrgRoleName       string   `toml:"org_role_name"`
		ManagementProfile string   `toml:"management_profile"`
		Regions           []string `toml:"regions"`
	} `toml:"aws"`
	Scan struct {
		HTTPProbeConcurrency      int    `toml:"http_probe_concurrency"`
		RoleAssumptionConcurrency int    `toml:"role_assumption_concurrency"`
		HTTPTimeoutSeconds        int    `toml:"http_timeout_seconds"`
		UserAgent                 string `toml:"user_agent"`
		// IAMPolicyInventory collects every IAM role and its inline and managed
		// policy documents. External-access findings still come only from roles
		// that trust an external principal. Default false preserves the
		// external-trust collection path.
		IAMPolicyInventory bool `toml:"iam_policy_inventory"`
	} `toml:"scan"`
	Cost struct {
		Currency                  string  `toml:"currency"`
		RiskMultiplierReclaimable float64 `toml:"risk_multiplier_reclaimable"`
		RiskMultiplierDangling    float64 `toml:"risk_multiplier_dangling"`
		UseCUR                    bool    `toml:"use_cur"`
	} `toml:"cost"`
	Trust struct {
		ApprovedExternalAccounts []string `toml:"approved_external_accounts"`
		StaleThresholdDays       int      `toml:"stale_threshold_days"`
		GhostThresholdDays       int      `toml:"ghost_threshold_days"`
	} `toml:"trust"`
	Output struct {
		DefaultFormat string `toml:"default_format"`
		OutputDir     string `toml:"output_dir"`
	} `toml:"output"`
	Neo4j struct {
		URI      string `toml:"uri"`
		Username string `toml:"username"`
		// Password resolution order (first non-empty wins): the env var named by
		// PasswordEnv, then the inline Password, then the contents of PasswordFile.
		// PasswordEnv is preferred; Password/PasswordFile let credentials persist across
		// restarts without re-exporting an env var each session.
		PasswordEnv  string `toml:"password_env"`
		Password     string `toml:"password"`
		PasswordFile string `toml:"password_file"`
	} `toml:"neo4j"`
	// Embeddings (Phase 3) — IMPORTANT:
	//
	//   • The DEFAULT in Default() is provider "openai". That is the only operational
	//     embedding path today (OpenAI text-embedding-3-small with dimensions=384 for Neo4j).
	//
	//   • provider "local" is NOT supported yet: it is a planned hook for future on-box
	//     all-MiniLM-L6-v2 / ONNX. Selecting local returns a provider whose Embed always
	//     fails with a clear error until that work lands.
	//
	//   • Future vector retrieval must stay gated on provider readiness (see graph package
	//     comments on retrieval integration).
	Embeddings struct {
		Provider        string `toml:"provider"`           // default "openai" — only operational value today
		LocalModel      string `toml:"local_model"`        // planned local model name (no runtime yet)
		OpenaiAPIKeyEnv string `toml:"openai_api_key_env"` // env var holding OpenAI API key (default OPENAI_API_KEY)
	} `toml:"embeddings"`
	// Synthesis (RAG answer layer over retrieval). When an API key is present for the
	// configured provider, `cloudrift query` synthesizes a grounded natural-language
	// answer from the retrieved findings; otherwise it degrades to retrieval-only.
	// Pluggable: "anthropic" is the operational provider today; others can be added.
	Synthesis struct {
		Provider  string `toml:"provider"`    // default "anthropic"
		Model     string `toml:"model"`       // default "claude-opus-4-8"
		APIKeyEnv string `toml:"api_key_env"` // env var holding the provider API key (default ANTHROPIC_API_KEY)
		MaxTokens int    `toml:"max_tokens"`  // answer length cap (default 2048)
	} `toml:"synthesis"`
}

func Default() *Config {
	c := &Config{}
	c.AWS.OrgRoleName = "CloudriftAuditRole"
	c.AWS.ManagementProfile = "default"
	c.Scan.HTTPProbeConcurrency = 50
	c.Scan.RoleAssumptionConcurrency = 10
	c.Scan.HTTPTimeoutSeconds = 10
	c.Scan.UserAgent = "github.com/Zero0x00/cloudrift/0.1"
	c.Cost.Currency = "USD"
	c.Cost.RiskMultiplierReclaimable = 5.0
	c.Cost.RiskMultiplierDangling = 3.0
	c.Trust.StaleThresholdDays = 90
	c.Trust.GhostThresholdDays = 365
	c.Output.DefaultFormat = "table"
	c.Output.OutputDir = "./cloudrift-output"
	c.Neo4j.URI = "bolt://localhost:7687"
	c.Neo4j.Username = "neo4j"
	c.Neo4j.PasswordEnv = "CLOUDRIFT_NEO4J_PASSWORD"
	// Explicit default: OpenAI is the only operational embeddings provider in this release.
	c.Embeddings.Provider = "openai"
	c.Embeddings.LocalModel = "all-MiniLM-L6-v2"
	c.Embeddings.OpenaiAPIKeyEnv = "OPENAI_API_KEY"
	// Synthesis defaults: Anthropic Claude. Only runs when the API key env var is set;
	// otherwise the query path stays retrieval-only.
	c.Synthesis.Provider = "anthropic"
	c.Synthesis.Model = "claude-opus-4-8"
	c.Synthesis.APIKeyEnv = "ANTHROPIC_API_KEY"
	c.Synthesis.MaxTokens = 2048
	return c
}

// EnableCIEM turns on IAM policy inventory plus the read-only CIEM evidence
// collectors: permissions-boundary documents and organization SCP/RCP documents.
// Legacy scans stay unchanged until this is selected with --ciem or by setting
// scan.iam_policy_inventory. Session policies are still not collected from STS.
// A denied Organizations call is not treated as proof that no SCP or RCP exists.
func EnableCIEM(cfg *Config) {
	if cfg == nil {
		return
	}
	cfg.Scan.IAMPolicyInventory = true
}

// Neo4jPassword resolves the Neo4j password from the first available source: the env var
// named by PasswordEnv, then the inline Password, then the contents of PasswordFile.
// Returns "" when none are set/readable.
func (c *Config) Neo4jPassword() string {
	if envName := strings.TrimSpace(c.Neo4j.PasswordEnv); envName != "" {
		if v := strings.TrimSpace(os.Getenv(envName)); v != "" {
			return v
		}
	}
	if p := strings.TrimSpace(c.Neo4j.Password); p != "" {
		return p
	}
	if f := strings.TrimSpace(c.Neo4j.PasswordFile); f != "" {
		if b, err := os.ReadFile(f); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		path = resolveDefaultPath()
	}
	if _, err := os.Stat(path); err != nil {
		return cfg, nil
	}
	_, err := toml.DecodeFile(path, cfg)
	return cfg, err
}

func resolveDefaultPath() string {
	if env := os.Getenv("CLOUDRIFT_CONFIG"); env != "" {
		return env
	}
	if _, err := os.Stat("./cloudrift.toml"); err == nil {
		return "./cloudrift.toml"
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "./cloudrift.toml"
	}
	return filepath.Join(home, ".config", "cloudrift", "config.toml")
}
