# Cloudrift

Cloudrift is a CLI and embedded dashboard for discovering orphaned AWS edge assets (DNS, S3 websites, CloudFront) and risky cross-account IAM trust relationships. It scans your AWS accounts - org-wide via a shared audit role, or a single account directly with your own credentials - writes findings as local JSON (no database required), and provides evidence-backed severity scoring.

**Key points:**
- Calls AWS APIs to inventory edge, IAM-trust, and S3 resource-policy exposure across your org
- Writes findings to local JSON per scan - read via dashboard, CLI reports, or your own tooling
- Dashboard provides interactive exploration and a scan control center
- `cloudrift demo generate` populates the UI with sample data (no AWS needed)
- Neo4j is optional for advanced graph features (blast-radius, vector search, `cloudrift query`)

---

## Documentation

All guides now live in one place - pick the format you prefer:

| Where | What |
| --- | --- |
| **[docs.html](docs.html)** | **Start here** - the full interactive docs site (open in a browser). Audience views (Operator / Security reviewer / Developer), grouped sidebar, search, and light/dark theme. Self-contained, works offline. |
| [docs/cloudrift-docs.md](docs/cloudrift-docs.md) | The same content as a single Markdown file (GitHub-renderable) with a table of contents - Overview, Getting Started, Architecture, CLI, Configuration, Security Coverage, IAM Setup, API & Technical Reference, Contributing. |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution quick-reference (full guide is in the docs). |

> The previous per-topic files under `docs/` were consolidated into `docs/cloudrift-docs.md` and rendered into `docs.html`.

---

## Current implementation status

| Feature | Status | Notes |
| --- | --- | --- |
| `cloudrift scan` | Complete | Runs the full pipeline: collects org accounts, per-account inventory (DNS/Route53, S3, CloudFront, IAM trust, role activity, S3 bucket policies), validates DNS/HTTP, scores, and persists findings as JSON |
| `cloudrift demo generate` | Complete | Deterministic populated scan for learning the UI |
| Dashboard + REST API | Complete | Works from JSON on disk; Neo4j optional |
| `cloudrift report` | Complete | Export findings as table, JSON, CSV, markdown, Excel, or SARIF |
| `cloudrift query` | Complete | Vector search over Neo4j; optional LLM answer synthesis when a synthesis provider is configured |
| Neo4j integration | Optional | Adds blast-radius explorer, graph relationships, vector index. Populate it on demand from the dashboard ("Export latest scan to Neo4j") or `POST /api/scans/{id}/neo4j-export`. With the Neo4j GDS plugin installed, export also writes Louvain `community` + PageRank `centrality` (auto clustering); degrades cleanly without it |
| Local embeddings | Stub | `provider=local` will error until implemented |

**Try immediately (no AWS):** `cloudrift demo generate && cloudrift dashboard --open`. A live scan (`cloudrift scan`) runs against a real AWS organization with credentials configured.

---

## Installation

### Option 1 - Pre-built binary (recommended)

Download the latest release for your platform:

```bash
# Linux / macOS (example for linux_amd64)
curl -sSL https://github.com/Cl0udrift/cloudrift/releases/latest/download/cloudrift_0.3.0_linux_arm64.tar.gz | tar -xz
sudo mv cloudrift /usr/local/bin/
cloudrift version
```

Verify the checksum:

```bash
sha256sum -c checksums.txt --ignore-missing
```

### Option 2 - `go install`

Requires Go 1.24+. The pre-built dashboard UI is committed to the repo (`dashboard/dist`) and embedded into the binary, so `go install` and a plain `go build` produce a working UI without an npm step.

```bash
go install github.com/Cl0udrift/cloudrift/cmd/cloudrift@latest
cloudrift version
```

### Option 3 - Build from source

Requires Go 1.24+ (Node.js 20+ only if you want to rebuild the UI from source):

```bash
git clone https://github.com/Cl0udrift/cloudrift.git
cd cloudrift
make build
sudo mv cloudrift /usr/local/bin/
cloudrift version
```

---

## What it solves

- **Orphaned edge:** DNS hostnames that resolve but point to deleted/misconfigured S3 buckets, CloudFront origins, or ELBs - with a verdict (reclaimable, dangling, etc.)
- **External trust:** IAM roles trusting external AWS accounts or principals, scored by last-used date, admin privileges, and risk profile
- **Resource-policy exposure:** S3 bucket policies granting cross-account or public access - exposure that IAM role-trust scanning misses
- **Visibility:** Self-hosted dashboard and CLI reports over the same HTTP server - no cloud dependency

---

## Requirements

### AWS

- **AWS credentials** for the management account (or delegated audit role) that can assume org member roles
- See [docs/cloudrift-docs.md → IAM Setup](docs/cloudrift-docs.md#iam-setup) for org setup and StackSet deployment

### Optional

- **Neo4j 5+** - for blast-radius exploration, relationship graphs, and vector search (`cloudrift query`). The dashboard and core workflows degrade cleanly without it (JSON-only mode).

### Build-time only

- Go 1.24+ and Node.js 20+ (to build from source; not needed for pre-built binaries)

---

## AWS access and scan modes

Cloudrift can scan in one of two modes, chosen by `[aws].org_role_name` in `cloudrift.toml`:

- **Org-wide (default):** `org_role_name = "CloudriftAuditRole"` (or your role name). Cloudrift lists the organization's accounts and assumes that role in each member account. This is the classic pattern for scanning a whole org from a management/security account, and requires the audit role deployed to each account (see [IAM Setup](docs/cloudrift-docs.md#iam-setup)).
- **No-assume (single account):** `org_role_name = ""`. Cloudrift scans only the caller's own account using the selected credentials directly - no cross-account role to deploy and no `Organizations:ListAccounts` call. Use this when your identity already has read access to the account you care about.

### Credential selection

**Dashboard:** Exposes a profile picker on the Scan Control page; the selected profile drives credential loading for that scan.

**CLI:** Does not have a `--profile` flag. Credentials come from (in order):

1. `[aws].management_profile` in `cloudrift.toml` (default: `"default"`)
2. `AWS_PROFILE` environment variable (if `management_profile` is empty)
3. AWS default profile chain (env vars, SSO, instance role, etc.)

Expired AWS SSO sessions are detected automatically: the CLI reopens `aws sso login` inline, and the dashboard surfaces a re-authentication prompt.

---

## Build commands

```bash
make build    # Rebuild the dashboard UI from source, then compile (requires npm + go)
make dev      # Compile only, no npm step (embeds the committed dashboard/dist UI)
make test     # Run all tests
```

The version string comes from the latest git tag. Tagged releases (e.g. `v0.2.0`) are injected; untagged builds show `dev`.

---

## Configuration

Optional TOML file (defaults work without it). Search order: `CLOUDRIFT_CONFIG` env var, then `./cloudrift.toml`.

Key sections:

- `[aws]` - `org_role_name` (empty string = no-assume single-account mode), `management_profile`, regions to scan
- `[scan]` - HTTP concurrency, role-assumption concurrency, timeouts
- `[cost]` - `use_cur` flag for Cost Explorer enrichment
- `[trust]` - approved external accounts, thresholds for stale/ghost roles
- `[output]` - scan output directory (default: `./cloudrift-output`)
- `[neo4j]` - `uri`, `username`, and one of `password_env` / `password` / `password_file` (optional)
- `[embeddings]` - embedding provider (default: `openai`, local stub)
- `[synthesis]` - optional LLM answer synthesis for `query` (`provider` default `anthropic`, `model` default `claude-opus-4-8`, `api_key_env` default `ANTHROPIC_API_KEY`). Synthesis only runs when the API key env var is set; otherwise `query` is retrieval-only.

Environment:

- `CLOUDRIFT_APP_BASE_URL` - base URL for alert links in Slack (e.g. `https://your-host:8080`); defaults to `http://127.0.0.1:8080`
- `CLOUDRIFT_API_TOKEN` - when set, gates the dashboard/API server (API + UI) behind HTTP Basic auth
- `ANTHROPIC_API_KEY` - provider API key for `query` LLM synthesis (env var name configurable via `[synthesis].api_key_env`)

---

## Commands

Global option: `--config <path>` to specify a TOML config file.

| Command | Purpose | Key flags |
| --- | --- | --- |
| `scan` | Scan AWS org for edge + IAM + resource-policy findings | `--output-dir`, `--neo4j`, `--no-http`, `--concurrency` |
| `demo generate` | Create deterministic sample scan | `--output-dir`, `--neo4j`, `--dense` |
| `report` | Export findings to table/JSON/CSV/markdown/excel/sarif | `--scan-id`, `--format`, `--output` |
| `query` | Search findings via vector retrieval (Neo4j required); optional LLM synthesis | `--scan-id`, `--query`, `--format` |
| `dashboard` | Start the web UI and REST API | `--port`, `--host`, `--open`, `--output-dir` |
| `version` | Print version string | - |

---

## Dashboard UI

Start the dashboard:

```bash
cloudrift dashboard --port 8080 --open
```

Open `http://127.0.0.1:8080` in your browser (or use `?scan_id=<id>` to load a specific scan).

### Serving and security

The server binds `127.0.0.1` (loopback) by default. Use `--host` to opt into a non-loopback bind (e.g. `--host 0.0.0.0` to expose on the network). When binding to a non-loopback address, set `CLOUDRIFT_API_TOKEN` to gate the whole server (API + UI) behind HTTP Basic auth - the dashboard prints a warning reminding you to do so. With `CLOUDRIFT_API_TOKEN` unset, the server runs without auth (acceptable on loopback only).

| Page | Purpose |
| --- | --- |
| Overview | Summary, high-signal findings, operations view |
| Scan Control | Start scans, validate AWS profile, runtime status, and a live per-run scan log (stage progress + collector warnings) so failures are diagnosable in the browser |
| Findings | Paginated findings table with filters and sorting |
| Triage | Findings in triage/review mode |
| Accounts | Per-account risk breakdown |
| Diff | Compare two scans side-by-side |
| Trust Report | IAM trust findings, external principals |
| External Entities | Entity-centric view with blast actions |
| Blast Explorer | 3D graph visualization of risk paths (Neo4j required) |
| Alerting | Slack webhooks, alert rules, event history |

Light and dark themes available; preference stored in browser localStorage.

---

## Neo4j (optional graph tier)

### Setup

1. Run Neo4j 5+ with Bolt accessible from your machine
2. Create a database user and add to `cloudrift.toml`:

```toml
[neo4j]
uri = "bolt://127.0.0.1:7687"
username = "neo4j"
# Password resolution order (first non-empty wins):
password_env = "CLOUDRIFT_NEO4J_PASSWORD"   # 1. name of an env var holding the password (preferred)
# password = "your-neo4j-password"          # 2. inline value (persists across restarts; protect this file)
# password_file = "/path/to/neo4j-password" # 3. path to a file containing the password
```

The password no longer has to be re-exported every session: set it once via `password` or `password_file` and the Neo4j badge stays configured across restarts.

3. Export a scan: `cloudrift scan --neo4j` or `cloudrift demo generate --neo4j --dense`

### Local Docker setup

```bash
export CLOUDRIFT_NEO4J_PASSWORD='dev-password-only'
docker run --name cloudrift-neo4j -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/${CLOUDRIFT_NEO4J_PASSWORD} \
  -d neo4j:5
```

### Example queries

```cypher
MATCH (s:ScanSnapshot) RETURN s.scan_id, s.finding_count LIMIT 25;
MATCH (f:Finding) WHERE f.scan_id = $scan RETURN f.id, f.title, f.severity LIMIT 50;
```

### Graceful degradation

Neo4j is optional. When unconfigured or unreachable, the dashboard and API still work with JSON-only findings (no blast-radius explorer or vector search).

---

## API overview

All endpoints under `/api`, request/response as JSON:

```
GET  /api/scans
GET  /api/scans/{id}/summary
GET  /api/scans/{id}/findings
GET  /api/scans/{id}/external-entities
GET  /api/scans/{id}/accounts
GET  /api/diff?old=<scan>&new=<scan>

POST /api/runtime/validate-profile
POST /api/scan/start
GET  /api/scan/status
GET  /api/scan/history
GET  /api/scan/progress (WebSocket)

GET  /api/alerts/catalog
GET  /api/alerts/rules
POST /api/alerts/rules/{ruleID}/test
```

Full reference: [docs/cloudrift-docs.md → API & Technical Reference](docs/cloudrift-docs.md#api--technical-reference)

---

## Scan output structure

```
cloudrift-output/
└── <scan-id>/
    ├── scan-metadata.json
    ├── findings.json
    ├── relationships.json    (optional)
    └── assets/               (optional)
        └── *.json
```

`scan-metadata.json` also records scan coverage: discovered/scanned account counts, the IDs of accounts that failed to scan, and a `coverage_complete` flag. Incomplete coverage downgrades absence-based verdicts (e.g. "reclaimable" orphaned-edge findings) since a bucket may be owned by an unscanned account.

Latest scan resolves by timestamp in `scan-metadata.json` (newest first); directory name used as tiebreak.

---

## Org setup

For multi-account scanning, set up an audit role via CloudFormation StackSet:

See [docs/cloudrift-docs.md → IAM Setup](docs/cloudrift-docs.md#iam-setup) and `iam/stackset-template.yaml`

---

## Contributing

Code contributions welcome. Guidelines:

- Keep AWS I/O in `collectors/`, business logic in `scorers/`/`validators/`, HTTP handlers in `internal/api/`
- Tests: `go test ./...` covers handlers, scorers, and fakes
- Frontend: React 18, Vite 5, Tailwind CSS, TanStack Query. `npm run dev` in `dashboard/` proxies `/api` to `http://127.0.0.1:8080` by default

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## Version and license

Current version: injected from git tag (`git describe`). See [tech-spec-v2.md](tech-spec-v2.md) for historical context and design notes.
