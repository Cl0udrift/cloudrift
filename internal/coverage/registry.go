// Package coverage is the single list of what Cloudrift covers, what it does not, and how far each
// part has been verified. The coverage page renders it. Counts that can be derived from code
// (evaluated actions, attack techniques) are computed at request time, not written here.
package coverage

// Status values.
const (
	StatusReady   = "ready"   // works, tested, on by default
	StatusOptIn   = "opt_in"  // works, off by default
	StatusPartial = "partial" // works with significant known gaps
	StatusGraphDB = "needs_graph_db"
	StatusPlanned = "planned" // not built
)

// Area groups modules by pipeline stage.
const (
	AreaCollect     = "Collect"
	AreaEvaluate    = "Evaluate"
	AreaInvestigate = "Investigate"
	AreaOperate     = "Operate"
	AreaRoadmap     = "Roadmap"
)

// Module is one capability of the product.
type Module struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Area        string   `json:"area"`
	Status      string   `json:"status"`
	Summary     string   `json:"summary"`
	Covers      []string `json:"covers"`
	Limitations []string `json:"limitations"`
	// ConfigKeys are settings on the config page that control this module.
	ConfigKeys []string `json:"config_keys,omitempty"`
	// Permissions are extra read-only AWS actions the module needs.
	Permissions []string `json:"permissions,omitempty"`
	Page        string   `json:"page,omitempty"` // dashboard route
	Docs        string   `json:"docs,omitempty"` // path in the repository
	Evidence    []string `json:"evidence,omitempty"`
	// Collectors are inventory collector names whose last-scan status applies to the module.
	Collectors []string `json:"collectors,omitempty"`
	// AssetTypes are asset types whose count in the selected scan shows data is present.
	AssetTypes []string `json:"asset_types,omitempty"`
	Live       *Live    `json:"live,omitempty"`
}

// Live is what the selected scan and config say about a module right now.
type Live struct {
	Enabled *bool  `json:"enabled,omitempty"`
	State   string `json:"state"` // completed, partial, failed, data_present, no_data, not_recorded, unknown
	Detail  string `json:"detail,omitempty"`
}

// Modules returns the registry in display order.
func Modules() []Module {
	return []Module{
		{
			ID: "inventory", Name: "Resource inventory", Area: AreaCollect, Status: StatusReady,
			Summary:     "Discovers accounts and the resources in them.",
			Covers:      []string{"AWS Organizations accounts, or the caller's own account in no-assume mode", "EC2, Lambda, ECS, EKS, S3, Route 53, CloudFront", "Region discovery per account"},
			Limitations: []string{"Services outside that list are not inventoried", "A partial regional collector keeps supported inventory marked partial", "Org-wide scans need the audit role in every member account"},
			ConfigKeys:  []string{"aws.scan_mode", "aws.org_role_name", "aws.management_profile", "aws.region_discovery", "aws.regions", "scan.role_assumption_concurrency"},
			Page:        "/inventory", Docs: "docs/audits/phase-4f-b2-live-validation.md",
			Collectors: []string{"region_discovery", "ec2", "lambda", "ecs", "eks", "iam", "s3", "route53", "cloudfront"},
			Evidence:   []string{"Live collection checked on one account on 2026-10-12 (conditional go)"},
		},
		{
			ID: "iam-inventory", Name: "IAM roles and policies", Area: AreaCollect, Status: StatusReady,
			Summary:     "Collects roles, trust policies, and inline and managed policy documents.",
			Covers:      []string{"Every IAM role with its policies when policy inventory is on", "Trust policies and trust relationships", "Permissions boundaries", "Policy retrieval status, so missing documents are never read as no access"},
			Limitations: []string{"Session policies are not collected from STS", "Turning the setting off returns to the older scan that reads only roles trusting an external account"},
			ConfigKeys:  []string{"scan.iam_policy_inventory"},
			Page:        "/identities", AssetTypes: []string{"iam_role", "iam_policy"},
		},
		{
			ID: "org-controls", Name: "Organization controls (SCP and RCP)", Area: AreaCollect, Status: StatusPartial,
			Summary:     "Collects service and resource control policies that can override identity policies.",
			Covers:      []string{"SCP and RCP documents and their attachments"},
			Limitations: []string{"A denied Organizations call is not treated as proof that no SCP or RCP exists", "Needs access to the management account", "Without them, decisions stay UNKNOWN instead of allowed"},
			Page:        "/identities",
		},
		{
			ID: "resource-policies", Name: "Resource policies", Area: AreaCollect, Status: StatusOptIn,
			Summary:     "Reads Secrets Manager and KMS policies, Lambda function policies and RDS instances, never secret values.",
			Covers:      []string{"Secret metadata and resource policies", "KMS customer-managed key policies and grants, including grant constraints", "VPC endpoint policies", "Lambda function policies", "RDS DB instances"},
			Limitations: []string{"A KMS grant with an encryption-context constraint gives a conditional result, since the request context is unknown", "VPC endpoint policies are collected and shown but not used in decisions, because whether a request travels through an endpoint cannot be seen", "Secret replicas in other Regions are not collected"},
			ConfigKeys:  []string{"scan.resource_policies"},
			Permissions: []string{"secretsmanager:ListSecrets", "secretsmanager:GetResourcePolicy", "kms:ListKeys", "kms:DescribeKey", "kms:GetKeyPolicy", "kms:ListAliases", "kms:ListGrants", "lambda:GetPolicy", "rds:DescribeDBInstances", "ec2:DescribeVpcEndpoints"},
			Docs:        "docs/audits/resource-policy-collection.md", AssetTypes: []string{"secret", "kms_key", "rds_instance", "vpc_endpoint"},
			Evidence: []string{"Mocked API tests only"},
		},
		{
			ID: "role-activity", Name: "Role last used", Area: AreaCollect, Status: StatusReady,
			Summary:     "Records when each role was last used, to find stale and idle roles.",
			Covers:      []string{"Last-used date and Region per role"},
			Limitations: []string{"Day-level only, with no caller, IP or session name", "AWS keeps this for a limited window"},
			ConfigKeys:  []string{"trust.stale_threshold_days", "trust.ghost_threshold_days"}, Page: "/identities",
		},
		{
			ID: "service-access", Name: "Service last-accessed", Area: AreaCollect, Status: StatusOptIn,
			Summary:     "Reads IAM access advisor data to show which granted services a role actually used.",
			Covers:      []string{"Per-role service last-accessed", "Action level for the few services AWS tracks that way"},
			Limitations: []string{"Large accounts take time; the budget setting bounds it", "Action-level data exists only for some services"},
			ConfigKeys:  []string{"scan.service_last_accessed", "scan.service_last_accessed_granularity", "scan.service_last_accessed_concurrency", "scan.service_last_accessed_skip_service_linked", "scan.service_last_accessed_timeout_seconds"},
			Permissions: []string{"iam:GenerateServiceLastAccessedDetails", "iam:GetServiceLastAccessedDetails"},
			Docs:        "docs/audits/service-last-accessed.md", Page: "/identities",
		},
		{
			ID: "workloads", Name: "Workload to role mapping", Area: AreaCollect, Status: StatusPartial,
			Summary:     "Connects EC2, Lambda, ECS and EKS workloads to the roles they run as.",
			Covers:      []string{"EC2 instance profiles, Lambda execution roles, ECS task roles", "EKS workload attachment where collected"},
			Limitations: []string{"Attachment is shown only where the API exposes it", "A service trust is not evidence that a workload uses the role"},
			Page:        "/identities", Collectors: []string{"ecs", "eks", "lambda", "ec2"},
		},
		{
			ID: "evaluator", Name: "Effective-permission evaluator", Area: AreaEvaluate, Status: StatusPartial,
			Summary:     "Decides allowed, denied, conditional or unknown for one action on one resource, with the reason.",
			Covers:      []string{"Identity, resource, trust, boundary, session, SCP and RCP policies together", "Explicit deny wins; unknown is never treated as deny", "Policy variables and extended condition operators", "Plain-language explanation for every decision"},
			Limitations: []string{"Only the actions in the catalog are evaluated", "VPC endpoint policies are shown but not applied, and KMS grants with an encryption-context constraint give a conditional result", "S3 ACLs and Block Public Access unless declared", "API-level checks such as termination protection"},
			Docs:        "docs/audits/resource-policy-collection.md", Page: "/blast-explorer",
			Evidence: []string{"38-case golden corpus with a zero-false-allow gate", "Synthetic dataset check: 27 of 27 administrative roles found, no false escalations", "No production-account validation yet (documented no-go)"},
		},
		{
			ID: "attack-paths", Name: "Attack and privilege-escalation search", Area: AreaEvaluate, Status: StatusPartial,
			Summary:     "From an assumed role session, finds role hops, privilege escalations and the data reachable.",
			Covers:      []string{"Role assumption chains", "Policy grants, trust rewrites, policy version edits", "PassRole chains to Lambda, CloudFormation, Glue and Data Pipeline", "Existing Lambda code edits", "User and group policy grants, joining a group, and taking over a user with an access key or console password", "Reads of S3 objects and secrets"},
			Limitations: []string{"Joining a group is reported as an escalation only when the group has administrative policies", "Creating an access key is checked for other users only; a key a user makes for itself is not an escalation", "EC2 RunInstances and DynamoDB-triggered Lambda are not modeled", "The search is bounded, and hitting the bound downgrades the result to not assessed", "None found means none found in the modeled techniques only"},
			Docs:        "docs/audits/privilege-escalation-techniques.md", Page: "/blast-explorer",
			Evidence: []string{"Unit tests per technique including negative cases"},
		},
		{
			ID: "entitlements", Name: "Declared permissions and exposure findings", Area: AreaEvaluate, Status: StatusReady,
			Summary:     "Reads policy documents for broad or sensitive grants and raises findings.",
			Covers:      []string{"Administrative wildcards", "IAM policy modification", "Condition and resource breadth", "User console access without MFA and stale access keys", "Administrative access held by a user, directly or through a group", "A weak user credential that can assume an administrative role", "Workloads that run as an administrative role", "VPC endpoints with an open policy"},
			Limitations: []string{"A declared grant is not proof of effective access", "Unsupported statements are listed, not guessed", "A user whose credential report was not collected raises no credential finding", "The weak-credential finding rests on stored policies, and is High instead of Critical when SCPs and RCPs were not collected"},
			Page:        "/findings", Docs: "docs/audits/phase-4f-final-entitlement-hardening.md",
		},
		{
			ID: "trust", Name: "Trust and external access", Area: AreaEvaluate, Status: StatusReady,
			Summary:     "Finds roles that trust other accounts, federated identities or everyone.",
			Covers:      []string{"Cross-account, federated, service and wildcard trust", "Approved external accounts", "Stale and privileged external roles"},
			Limitations: []string{"Conditions beyond a supported set are reported as unsupported", "The other account's side of a cross-account call is not visible"},
			ConfigKeys:  []string{"trust.approved_external_accounts", "trust.stale_threshold_days", "trust.ghost_threshold_days"},
			Page:        "/external-entities",
		},
		{
			ID: "findings", Name: "Findings and risk cost", Area: AreaInvestigate, Status: StatusReady,
			Summary:     "Ranks findings by severity and estimated monthly risk.",
			Covers:      []string{"Severity, remediation guidance, top fixes", "Risk-adjusted cost"},
			Limitations: []string{"Cost is an estimate from multipliers unless Cost Explorer enrichment is turned on", "No ownership, ticketing or remediation tracking by design"},
			ConfigKeys:  []string{"cost.currency", "cost.risk_multiplier_reclaimable", "cost.risk_multiplier_dangling", "cost.use_cur"}, Page: "/findings",
		},
		{
			ID: "identities", Name: "Identities and permission matrix", Area: AreaInvestigate, Status: StatusReady,
			Summary:     "Per-role and per-account view of declared permissions, last use and missing evidence.",
			Covers:      []string{"Account by permission matrix", "Role profile with decisions and the reason for each", "Which users and roles can assume a role, and which workloads run as it", "Which controls are missing evidence"},
			Limitations: []string{"Declared permissions are not evaluated access", "Who can assume a role comes from stored policies, not CloudTrail; accounts that were not scanned and federated principals are not listed", "The account matrix is for roles; users have their own table beside it"}, Page: "/identities",
		},
		{
			ID: "blast", Name: "Blast Explorer", Area: AreaInvestigate, Status: StatusGraphDB,
			Summary:     "Graph view of what a finding, role or external entity can reach.",
			Covers:      []string{"Topology, identity exposure, attack path and permission impact modes"},
			Limitations: []string{"The graph and permission-impact view need Neo4j", "Without Neo4j only summaries are shown"},
			ConfigKeys:  []string{"neo4j.uri", "neo4j.username", "neo4j.password_env"}, Page: "/blast-explorer",
		},
		{
			ID: "diff", Name: "Changes between scans", Area: AreaInvestigate, Status: StatusReady,
			Summary:     "Shows what is new, resolved or changed between two scans.",
			Covers:      []string{"New and resolved findings", "Risk drift"},
			Limitations: []string{"Compares findings, not every configuration change", "Needs at least two scans"}, Page: "/diff",
		},
		{
			ID: "alerting", Name: "Alerting", Area: AreaOperate, Status: StatusReady,
			Summary:     "Posts to Slack when a scan produces something worth attention.",
			Covers:      []string{"Scan completion, new critical findings, reclaimable threshold, stale external privileged roles", "Routing by account", "Cooldown and preview"},
			Limitations: []string{"Alerts follow scans, so they are not real time", "Slack only"}, Page: "/alerting",
		},
		{
			ID: "query", Name: "Natural-language query", Area: AreaOperate, Status: StatusGraphDB,
			Summary:     "Searches findings by meaning and can write a grounded answer.",
			Covers:      []string{"Vector search over findings", "Optional LLM answer from the retrieved findings"},
			Limitations: []string{"Needs Neo4j and an embeddings key", "Answers run only when the answer key is set"},
			ConfigKeys:  []string{"embeddings.provider", "embeddings.openai_api_key_env", "synthesis.provider", "synthesis.model", "synthesis.api_key_env", "synthesis.max_tokens"}, Page: "/query",
		},
		{
			ID: "scan-control", Name: "Scan control and settings", Area: AreaOperate, Status: StatusReady,
			Summary:     "Starts scans, shows progress and history, and edits settings from the dashboard.",
			Covers:      []string{"Start and watch scans", "Edit non-secret settings with validation and a backup of the old file"},
			Limitations: []string{"Secrets are never shown or entered here", "Saving does not keep comments from the old config file"}, Page: "/scan-control",
		},
		{
			ID: "accuracy", Name: "Accuracy validation", Area: AreaOperate, Status: StatusPartial,
			Summary:     "Checks that decisions agree with known answers.",
			Covers:      []string{"Golden corpus with a zero-false-allow gate", "Labeled synthetic dataset check", "A checker against the IAM policy simulator"},
			Limitations: []string{"The simulator checker exists but is not wired into a command", "Synthetic data only; no production account validation", "The simulator ignores resource policies, SCPs and RCPs"},
			Docs:        "docs/audits/phase-4f-final-entitlement-hardening.md",
		},

		{
			ID: "cloudtrail", Name: "AssumeRole activity from CloudTrail", Area: AreaRoadmap, Status: StatusPlanned,
			Summary: "Would show who actually assumed a role, from which account, for after-the-fact detection.",
			Covers:  []string{}, Limitations: []string{"Not built. Today nothing records the AssumeRole call itself"},
		},
		{
			ID: "users-groups", Name: "IAM users and groups", Area: AreaCollect, Status: StatusPartial,
			Summary:     "Collects users and groups with their inline and managed policies, memberships and permissions boundaries.",
			Covers:      []string{"Which policies apply to each user, directly or through a group", "Console access, MFA and access key age and use from the credential report", "Users in the account permission table", "Group membership", "User permissions boundaries", "An explicit Deny in any source overriding an Allow in another"},
			Limitations: []string{"Needs iam:GetAccountAuthorizationDetails; if denied the scan continues without users and groups", "Credential data comes from the IAM credential report; if it is denied the users are still collected without it", "Root account keys and MFA are not assessed", "Hardware key and virtual MFA device details are not collected, only whether MFA is active"},
			Permissions: []string{"iam:GetAccountAuthorizationDetails", "iam:GenerateCredentialReport", "iam:GetCredentialReport"},
			ConfigKeys:  []string{"scan.iam_policy_inventory"}, Collectors: []string{"iam_users_groups", "iam_credential_report"}, AssetTypes: []string{"iam_user", "iam_group"}, Page: "/principals",
			Evidence: []string{"Tested with fakes for three cases: group plus own inline policy, managed plus inline, and an inline Deny over an Allow", "Not yet run against a real AWS account"},
		},
		{
			ID: "other-clouds", Name: "Other clouds", Area: AreaRoadmap, Status: StatusPlanned,
			Summary: "Azure and GCP.", Covers: []string{}, Limitations: []string{"Not built. AWS only"},
		},
	}
}
