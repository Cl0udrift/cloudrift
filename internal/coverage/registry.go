// Package coverage is the single list of what Cloudrift covers, what it does not, and how far each
// part has been verified. The coverage page renders it. Counts that can be derived from code
// (evaluated actions, attack techniques) are computed at request time, not written here.
package coverage

import (
	"fmt"

	"github.com/Zero0x00/cloudrift/internal/verified"
)

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
			Covers:      []string{"AWS Organizations accounts, or the caller's own account in no-assume mode", "EC2, Lambda, ECS, EKS, S3, Route 53, CloudFront", "Region discovery per account", "Inventory page: filter by service, severity, findings and internet exposure; owner from configurable tag keys; resources added or removed since the previous scan; CSV export of the filtered list"},
			Limitations: []string{"Services outside that list are not inventoried", "A partial regional collector keeps supported inventory marked partial", "Org-wide scans need the audit role in every member account", "Owner comes from tags only, so a resource without an owner tag has none; tags are collected for EC2, security groups, load balancers and RDS, not for IAM roles or S3 buckets", "Change since the previous scan covers resources added or removed, not a resource whose configuration changed", "The CSV export defuses cells that start with = + - or @ so a spreadsheet does not run them"},
			ConfigKeys:  []string{"aws.scan_mode", "aws.org_role_name", "aws.management_profile", "aws.region_discovery", "aws.regions", "scan.role_assumption_concurrency", "inventory.owner_tag_keys"},
			Page:        "/inventory", Docs: "docs/audits/phase-4f-b2-live-validation.md",
			Collectors: []string{"region_discovery", "ec2", "lambda", "ecs", "eks", "iam", "s3", "route53", "cloudfront"},
			Evidence:   []string{"Live collection checked on one account on 2026-10-12 (conditional go)"},
		},
		{
			ID: "network-resources", Name: "Network exposure", Area: AreaCollect, Status: StatusReady,
			Summary:     "Reads security groups, load balancers and RDS instances, and how they reach EC2 instances, to say which workloads can be reached from the internet.",
			Covers:      []string{"Security groups with their inbound rules and the addresses each rule allows", "Application and Network Load Balancers with scheme, security groups, targets and tags", "RDS instances with the public flag, security groups and tags", "An EC2 instance is called reachable only with a public IP and a rule open to every address (0.0.0.0/0 or ::/0), or behind an internet-facing load balancer whose group is open to every address; open only to named addresses is reported as such, with the addresses", "Private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) are not counted as internet entries"},
			Limitations: []string{"Only EC2 instances are followed from rule to workload; Lambda function URLs, API Gateway, public endpoints of other services and VPC peering are not checked, and the role page says not checked, never not reachable", "Network ACLs, route tables, internet gateways, host firewalls and AWS Network Firewall are not read, so an open rule is the door, not proof traffic arrives", "A public flag or scheme without an open rule is not reported as reachable", "A security group rule is read at the time of the scan", "At most 100 inbound rules are kept per group, 50 target groups per load balancer"},
			ConfigKeys:  []string{"scan.network_resources"},
			Permissions: []string{"ec2:DescribeSecurityGroups", "elasticloadbalancing:DescribeLoadBalancers", "elasticloadbalancing:DescribeTargetGroups", "elasticloadbalancing:DescribeTargetHealth", "elasticloadbalancing:DescribeTags", "rds:DescribeDBInstances"},
			Page:        "/inventory", Collectors: []string{"security_groups", "elbv2", "rds"}, AssetTypes: []string{"ec2_security_group", "load_balancer", "rds_instance"},
			Evidence: []string{"Checked live on the CloudGoat rce_web_app scenario: an instance behind a load balancer and a security group open to one address was reported as open to that address only, not as reachable and not as closed", "A rule open to every address is covered by unit tests only, not by a live scan"},
		},
		{
			ID: "iam-inventory", Name: "IAM roles and policies", Area: AreaCollect, Status: StatusReady,
			Summary:     "Collects roles, trust policies, and inline and managed policy documents.",
			Covers:      []string{"Every IAM role with its policies when policy inventory is on", "Trust policies and trust relationships", "Permissions boundaries", "Role tags and customer managed policy descriptions, as free text written in IAM", "Policy retrieval status, so missing documents are never read as no access"},
			Limitations: []string{"Session policies are not collected from STS", "Older versions of a customer managed policy are read only for policies some principal can switch with iam:SetDefaultPolicyVersion, at most 200 policies; without iam:ListPolicyVersions the result is UNKNOWN, never clean", "Tags and descriptions come from the same iam:GetAccountAuthorizationDetails call, so a denied call leaves them empty; AWS managed policy descriptions are not collected", "Turning the setting off returns to the older scan that reads only roles trusting an external account"},
			ConfigKeys:  []string{"scan.iam_policy_inventory"},
			Permissions: []string{"iam:ListPolicyVersions"},
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
			ID: "identity-center", Name: "IAM Identity Center", Area: AreaCollect, Status: StatusOptIn,
			Summary:     "Reads single sign-on permission sets, who is assigned to which account, and users and groups, for the Identity Center page.",
			Covers:      []string{"Permission sets with their managed policies, inline policy and session length", "User and group assignments per account, with group membership", "Which permission sets are administrative, and the IAM role each becomes in an account"},
			Limitations: []string{"Visible only from the organization management account or the delegated administrator; from another account the scan records no instance", "Administrative means AdministratorAccess or an inline policy that allows * on *; other broad policies, and customer managed policies (names only), are not judged", "Permission boundaries on a permission set and the resulting role's effective permissions are not combined", "Identity Center roles are not searched for escalation paths yet"},
			ConfigKeys:  []string{"scan.identity_center"},
			Permissions: []string{"sso:ListInstances", "sso:ListPermissionSets", "sso:DescribePermissionSet", "sso:ListManagedPoliciesInPermissionSet", "sso:ListCustomerManagedPolicyReferencesInPermissionSet", "sso:GetInlinePolicyForPermissionSet", "sso:ListAccountsForProvisionedPermissionSet", "sso:ListAccountAssignments", "identitystore:DescribeUser", "identitystore:DescribeGroup", "identitystore:ListGroupMemberships"},
			Docs:        "docs/audits/service-resource-collection.md", Page: "/identity-center", Collectors: []string{"identity_center"},
		},
		{
			ID: "assume-activity", Name: "Who assumed each role", Area: AreaCollect, Status: StatusOptIn,
			Summary:     "Reads the CloudTrail event history to show which callers actually assumed a role, next to who is allowed to.",
			Covers:      []string{"AssumeRole calls in the last 1 to 90 days (default 30): caller, role, count, first and last seen, and up to 10 distinct source addresses per caller", "Callers outside the scan (other accounts, services) are listed too", "A caller seen assuming a role that stored policy does not allow today is not dropped"},
			Limitations: []string{"Management event history only, at most 90 days, per Region; LookupEvents allows 2 requests per second, so the read is bounded by an event cap (5,000 per Region) and a time budget, and a Region that hits either is reported as partial", "It shows a call was made. It never changes an allow or deny decision, and no record does not show a call never happened", "A role session is matched to its role by name because the session ARN has no path", "Only AssumeRole is read. Once a workload holds a role's credentials, calls it makes with them are other events that are not read, so an instance role shows the service's own calls and not the instance's", "Source addresses are kept for scans made after this was added; older scans show none, and a service caller reports a service name, not an address"},
			ConfigKeys:  []string{"scan.assume_role_activity", "scan.assume_role_activity_days", "scan.assume_role_activity_seconds"},
			Permissions: []string{"cloudtrail:LookupEvents"},
			Docs:        "docs/audits/service-resource-collection.md", Page: "/identities", Collectors: []string{"assume_activity"},
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
			Summary:     "Connects EC2, Lambda, ECS and EKS workloads, and existing CloudFormation stacks, CodeBuild projects and Step Functions state machines, to the roles they run as.",
			Covers:      []string{"EC2 instance profiles, Lambda execution roles, ECS task roles", "EKS workload attachment where collected", "CloudFormation stacks with a service role, CodeBuild projects, Step Functions state machines, Glue development endpoints, Batch job definitions, App Runner services, SageMaker notebooks, Bedrock AgentCore runtimes, code interpreters and browsers, launch templates used by an Auto Scaling group, and CodeDeploy groups that target tagged EC2 instances, per region"},
			Limitations: []string{"Attachment is shown only where the API exposes it", "A service trust is not evidence that a workload uses the role", "A region where the audit role lacks the new read actions (cloudformation:DescribeStacks, codebuild:ListProjects and BatchGetProjects, states:ListStateMachines and DescribeStateMachine) reports a failed collector, and those resources are not searched there", "Stack policies and stack state, project source restrictions, what a state machine's role can do through integrations, notebook and endpoint state, Batch job queues, and App Runner sources are not checked", "A launch template is followed only when an Auto Scaling group launches from $Default or $Latest, and a CodeDeploy group only through EC2 tag filters (Auto Scaling group targets are not followed)"},
			ConfigKeys:  []string{"scan.service_resources"},
			Permissions: []string{"cloudformation:DescribeStacks", "codebuild:ListProjects", "codebuild:BatchGetProjects", "states:ListStateMachines", "states:DescribeStateMachine", "glue:GetDevEndpoints", "batch:DescribeJobDefinitions", "apprunner:ListServices", "apprunner:DescribeService", "sagemaker:ListNotebookInstances", "sagemaker:DescribeNotebookInstance", "bedrock-agentcore:ListAgentRuntimes", "bedrock-agentcore:GetAgentRuntime", "bedrock-agentcore:ListCodeInterpreters", "bedrock-agentcore:GetCodeInterpreter", "bedrock-agentcore:ListBrowsers", "bedrock-agentcore:GetBrowser", "ec2:DescribeLaunchTemplates", "ec2:DescribeLaunchTemplateVersions", "autoscaling:DescribeAutoScalingGroups", "codedeploy:ListApplications", "codedeploy:ListDeploymentGroups", "codedeploy:BatchGetDeploymentGroups"},
			Docs:        "docs/audits/service-resource-collection.md",
			Page:        "/identities", Collectors: []string{"ecs", "eks", "lambda", "ec2", "cloudformation", "codebuild", "stepfunctions", "glue", "batch", "apprunner", "sagemaker", "agentcore", "launch_templates", "codedeploy"},
		},
		{
			ID: "evaluator", Name: "Effective-permission evaluator", Area: AreaEvaluate, Status: StatusPartial,
			Summary:     "Decides allowed, denied, conditional or unknown for one action on one resource, with the reason.",
			Covers:      []string{"Identity, resource, trust, boundary, session, SCP and RCP policies together", "Explicit deny wins; unknown is never treated as deny", "Policy variables and extended condition operators", "Tag conditions (aws:ResourceTag, aws:PrincipalTag) from the collected tags of users, roles and EC2 instances; a call blocked only by a tag is reported as possible after the tag is set, changed or removed, by whichever principal on the path may do it", "Plain-language explanation for every decision", "Credentials taken from a workload (an instance or function role) are evaluated as carrying no session policy"},
			Limitations: []string{"Only the actions in the catalog are evaluated", "Tag-based escalation covers StringEquals, StringLike and their negations on aws:ResourceTag for users, roles and EC2 instances, with iam:TagUser/UntagUser/TagRole/UntagRole and ec2:CreateTags/DeleteTags; other tagged resources, tag-policy and SCP tag rules, and aws:RequestTag conditions on the target call are not modeled", "VPC endpoint policies are shown but not applied, and KMS grants with an encryption-context constraint give a conditional result", "S3 ACLs and Block Public Access unless declared", "API-level checks such as termination protection"},
			Docs:        "docs/audits/resource-policy-collection.md", Page: "/blast-explorer",
			Evidence: []string{fmt.Sprintf("Golden corpus of %d hand-written cases tied to AWS documentation, with a zero-false-allow gate", verified.Load().GoldenCases), "Synthetic dataset check: 27 of 27 administrative roles found, no false escalations", fmt.Sprintf("%d generated combinations of principal type, account, resource policy, boundary, session policy and SCP, with expected results taken from the AWS evaluation-logic pages: no false allow", verified.Load().FlowCases), "No production-account validation yet (documented no-go)"},
		},
		{
			ID: "attack-paths", Name: "Attack and privilege-escalation search", Area: AreaEvaluate, Status: StatusPartial,
			Summary:     "From an assumed role session, finds role hops, privilege escalations and the data reachable.",
			Covers:      []string{"At scan time: every user and role is searched and each validated direct escalation becomes a finding (one per principal, technique and target), so a new path between scans shows in Diff and can fire an alert", "Role assumption chains", "Policy grants, trust rewrites, policy version edits", "PassRole chains to 45 service variants (Lambda, CloudFormation, Glue, Data Pipeline, EC2, ECS, Batch, SageMaker, CodeBuild, Step Functions, EMR, Bedrock AgentCore and others), each from one record in iamauth.PassRoleServices", "Existing Lambda code edits", "Reaching the role of a collected EC2 instance or ECS task through SSM Session Manager or SendCommand, EC2 Instance Connect, a user-data swap, or ECS Exec", "Reaching the role of an existing CloudFormation stack (UpdateStack, or a change set), CodeBuild project (StartBuild, StartBuildBatch) or Step Functions state machine (UpdateStateMachine plus StartExecution), and the same for Glue development endpoints, Batch job definitions, App Runner services, SageMaker notebooks, AgentCore runtimes, interpreters and browsers, launch templates and CodeDeploy groups", "User and group policy grants, joining a group, and taking over a user with an access key or console password", "Reads of S3 objects and secrets"},
			Limitations: []string{"Joining a group is reported as an escalation only when the group has administrative policies", "Creating an access key is checked for other users only; a key a user makes for itself is not an escalation", "Taking over a user needs that user's credential report: two keys need iam:DeleteAccessKey too, a login profile must (not) exist, and without the report the result is UNKNOWN", "PassRole chains use a fixed resource name and Region per call (the right resource type where the types differ); a policy scoped to other names gives UNKNOWN", "Sessions the attacker opens after the first (assuming a role, passing a role to a service) are modeled as carrying no session policy, because the attacker chooses what to pass; the starting session's policy comes from the caller", "Scan-time findings are direct escalations, plus one extra role hop where a tag change by the starting principal opens a hop for a role it can assume (two principals, one path); other paths that pass through another role stay in Blast Explorer, so a role many principals can assume does not copy its findings onto them", "The scan-time search assumes the session carries no session policy, and is limited by a time budget; principals it does not reach are counted in the scan coverage, never reported as clean", "A principal that reaches more than 25 targets by one technique gets one rolled-up finding", "Switching a policy to an older version is reported when a stored version grants administrative access; a version that is broader without being administrative is not yet detected", "An escalation finding on a role lists who can assume it (users and roles in the scan, weak credentials first) and is raised one level when a user with a weak credential can; callers in unscanned accounts, federated principals and callers of callers are not listed, and a new caller changes the evidence, not the finding ID, and Diff lists it under Changed", "Workload paths state what Cloudrift cannot see (SSM agent online, ECS Exec enabled, instance reachable) as not verified, never as met", "A service trust with a condition counts only when it holds for the source account and source ARN the service presents; other conditions (such as an external ID) do not match", "The search is bounded, and hitting the bound downgrades the result to not assessed", "None found means none found in the modeled techniques only"},
			Docs:        "docs/audits/privilege-escalation-techniques.md", Page: "/blast-explorer",
			Evidence:   []string{"Unit tests per technique including negative cases"},
			ConfigKeys: []string{"scan.escalation_search_seconds"},
		},
		{
			ID: "entitlements", Name: "Declared permissions and exposure findings", Area: AreaEvaluate, Status: StatusReady,
			Summary:     "Reads policy documents for broad or sensitive grants and raises findings.",
			Covers:      []string{"Administrative wildcards", "IAM policy modification", "Condition and resource breadth", "User console access without MFA and stale access keys", "Administrative access held by a user, directly or through a group", "A weak user credential that can assume an administrative role", "Workloads that run as an administrative role", "VPC endpoints with an open policy", "Users that can read the whole IAM configuration", "Each identity finding is tagged a toxic combination or a posture issue", "Identity findings show the attack path (user, edge, role), why the severity was chosen, and fix options by strategy"},
			Limitations: []string{"Paths, severity reasons and fix options exist only on scans made after this was added; rescan older ones", "A declared grant is not proof of effective access", "Unsupported statements are listed, not guessed", "A user whose credential report was not collected raises no credential finding", "The weak-credential finding rests on stored policies, and is High instead of Critical when SCPs and RCPs were not collected"},
			Page:        "/findings", Docs: "docs/audits/phase-4f-final-entitlement-hardening.md",
		},
		{
			ID: "orphaned-edge", Name: "Takeover risk (DNS, buckets, origins)", Area: AreaEvaluate, Status: StatusPartial,
			Summary:     "Finds names and references that point at something that is gone and could be registered by someone else: DNS records, S3 buckets named by your resources, and CloudFront origins.",
			Covers:      []string{"Every Route 53 record in public zones except SOA and NS, checked by DNS lookup and an HTTP probe", "Deleted S3 website buckets (reclaimable when no scanned account owns the bucket)", "Names that point at a deleted Elastic Beanstalk environment (reclaimable), load balancer, API Gateway endpoint or CloudFront distribution (dangling)", "NS delegations below a zone apex to name servers that do not serve the zone (reclaimable when they are Route 53 servers)", "Unclaimed pages on 18 third-party services (GitHub Pages, Heroku, Shopify, Fastly, Zendesk, Bitbucket, Surge, Ghost, Tumblr, Pantheon, Readme, Helpjuice, Help Scout, UserVoice, WordPress.com, Intercom, Agile CRM, Campaign Monitor), each matched on the page text and the record's target together", "A CloudFront target whose alias is not on the distribution", "Names that do not resolve", "S3 buckets that a CloudFront origin, IAM policy statement, or other collected resource names but no account holds, checked with an anonymous request to S3 (reclaimable; critical when a distribution serves from it)", "CloudFront origins whose AWS endpoint was deleted", "Roles whose trust policy still holds the unique ID of a deleted principal (Low, not a takeover: IAM never reuses the ID)", "A record that points at an EC2 address, API Gateway custom domain or Cognito domain that no scanned account holds, and certificate validation records left behind for certificates that no longer exist (Low)", "Each finding names what is affected and gives the command that fixes it"},
			Limitations: []string{"Bucket references are read from the properties of collected resources (IAM policy statements, CloudFront origins, CodeBuild, CloudFormation and so on); anything not collected, such as application code or Terraform, is not seen", "At most 150 distinct bucket names are checked per scan", "The bucket check needs HTTP probing on and reaches s3.amazonaws.com from the machine running the scan; a bucket whose state cannot be read is skipped", "Records in private zones are not probed, because they only resolve inside their VPC", "Checks that rest on absence (released address, unheld custom domain or Cognito domain) are raised only when every account was scanned and the collector succeeded in every Region; otherwise they are skipped, never guessed", "An address counts as EC2 only when its reverse DNS name says so; a record pointing at another provider is never called released", "Not checked: Azure, Google Cloud and other non-AWS targets that fail by DNS alone; ECR and SQS names, which are scoped to an account and cannot be claimed through a name", "The third-party page texts follow a public list and have not been tried against live accounts; a service that changes its error page stops matching", "A delegation check reaches name servers on UDP port 53 from the machine running the scan; a server it cannot reach is reported as unknown, not lame", "A record with a routing policy (weighted, latency, failover) gets no ready-made delete command, because the scan does not store its routing fields", "Only the first value of a multi-value record is probed", "Checked at scan time only; a name that becomes claimable later is seen on the next scan", "Seen working on synthetic data only: the one live account has no Route 53 records"},
			ConfigKeys:  []string{"scan.network_resources", "scan.http_probe_concurrency", "scan.http_timeout_seconds"},
			Permissions: []string{"route53:ListHostedZones", "route53:ListResourceRecordSets", "cloudfront:ListDistributions", "s3:ListAllMyBuckets", "ec2:DescribeAddresses", "ec2:DescribeNetworkInterfaces", "acm:ListCertificates", "acm:DescribeCertificate", "apigateway:GET (domain names only)", "cognito-idp:ListUserPools", "cognito-idp:DescribeUserPool"},
			Page:        "/findings?module=orphaned_edge", Collectors: []string{"route53", "cloudfront", "public_addresses", "acm", "apigateway", "cognito"}, AssetTypes: []string{"dns_record", "cloudfront_dist"},
			Evidence: []string{"Unit tests for classification, the delete command, each fingerprint rule, deleted targets and lame delegation (with the network replaced)", "No live finding yet: the lab account has no hosted zones"},
		},
		{
			ID: "trust", Name: "Trust and external access", Area: AreaEvaluate, Status: StatusReady,
			Summary:     "Finds roles that trust other accounts, federated identities or everyone.",
			Covers:      []string{"Cross-account, federated and service trust", "A role anyone can assume (Principal \"*\"): Critical with no condition, High with only MFA or an address, Medium behind an external ID, Low behind an organization or named-principal condition", "Whether an outside account is guarded: an external ID, organization or named-principal condition lowers an unapproved account to Medium; an approved account with none is raised to Medium", "An outside account can be approved from its finding, with a note and the date; the approval counts from the next scan", "Accounts in your own AWS Organization are treated as internal, not as unknown vendors (when the scan could list the organization)", "OpenID Connect provider trusts with no condition naming the subject (any repository on a shared CI service); High, Critical for an administrator role", "Approved external accounts", "Stale and privileged external roles", "Role page: each trust statement in plain words, naming the outside account and the conditions that limit it (external ID, MFA, organization, source), with a specific review suggestion for an open or outside trust", "Finding titles say why the trust matters instead of a verdict code (scans made after this was added)"},
			Limitations: []string{"Conditions beyond a supported set are reported as unsupported", "A guard is judged by its key, not its value: an organization or external ID condition is credited even if its value is not the one you meant", "SAML provider trusts are not checked for conditions", "How recently the role was used no longer decides alone: a role with no last-used data is rated unknown, not stale, and a stale role behind an external ID, organization or named-principal condition is capped at Medium", "There is no record of who approved an account, because the dashboard has no sign-in", "The other account's side of a cross-account call is not visible"},
			ConfigKeys:  []string{"trust.approved_external_accounts", "trust.stale_threshold_days", "trust.ghost_threshold_days"},
			Page:        "/external-entities",
		},
		{
			ID: "findings", Name: "Findings and risk cost", Area: AreaInvestigate, Status: StatusReady,
			Summary:     "Ranks findings by severity, with a small boost from the evidence each kind of finding records.",
			Covers:      []string{"Severity, remediation guidance, top fixes", "Priority is severity first; each kind of finding adds at most 15 points for its own evidence (takeover state, trust signals, a running workload), so no kind outranks another at the same severity", "Optional: the account's 30-day spend on the service behind an orphaned-edge finding, as context", "Unused resources that cost money to hold, each with its monthly cost from the AWS list price for its size and Region: unattached EBS volumes, load balancers with no targets, hosted zones with no records. The total is shown as what removing them saves", "Owner of each finding: the owner tag, else the owner you set for the account; findings with no owner are counted", "Age of each finding and whether it is past a fix deadline you set; median days to fix from recent scans", "What an administrator can reach, as money: the account's actual spend last month from Cost Explorer (needs \"attach account spend\")", "Actual cost of an unused resource over the last 14 days, replacing the list-price estimate, when resource-level data is switched on in Cost Explorer", "An optional planning estimate of yearly loss, shown folded, from loss values you enter (what a data store or hostname breach costs, and the chance a finding is used). Off until you enter them"},
			Limitations: []string{"Unused-resource prices are list-price estimates (storage and fixed hourly charges); discounts, traffic, provisioned IOPS and snapshots change the real bill, and a resource that cannot be priced is listed without a cost", "Idle is judged from what the scan can read (no volume attachment, no registered targets, no records); there are no traffic or utilization metrics, so a quiet but connected resource is not called unused", "The Cost and Usage Report is not read: it needs a report, S3 access and a query engine set up by the customer. Cost Explorer resource-level data gives actual cost for the same resources without that, but it is opt-in and covers only the last 14 days", "Account spend is the whole account's billing, not the cost of the resources one identity can reach, so it is shown only for administrator-level identities", "Elastic IP addresses are not priced: the AWS Price List API does not return a public IPv4 price for the Regions checked, and a price is never typed in from memory", "Dollar cost is not a risk measure here. At AWS list price an orphaned DNS record, S3 bucket, CloudFront distribution or public ACM certificate has no standing per-asset fee, so the modeled cost of these findings is $0 and it does not affect priority", "Identity, entitlement, trust, escalation and exposure findings carry no dollar figure", "Cost Explorer reports spend per account and service, not per resource, so its figure is shown as the whole service's spend and never as the finding's cost", "Cost Explorer needs ce:GetCostAndUsage, which the audit role template does not grant; it is read with the management profile", "Settings for currency and the two risk multipliers were removed because nothing read them", "Demo scans still carry made-up dollar figures on some findings", "No ticketing or remediation tracking by design. Owners are per account unless a resource carries an owner tag", "The loss range is only as good as the values entered; Cloudrift supplies what an identity can reach, never what it is worth. It values administrator access (by the data stores in the account), public buckets and takeover risks, and leaves other findings out and counted", "Age counts from the first stored scan that held the finding, so it is a minimum; time to fix counts only findings whose resource is still there"},
			ConfigKeys:  []string{"cost.use_cur"}, Page: "/findings",
		},
		{
			ID: "identities", Name: "Identities and permission matrix", Area: AreaInvestigate, Status: StatusReady,
			Summary:     "Per-role and per-account view of what each role can do, who can become it, how it is exposed and what to change.",
			Covers:      []string{"Roles listed riskiest first (worst finding, then internet exposure, then broad permissions); AWS-managed roles hidden by default; filters for findings, internet exposure, outside trust, and powerful and idle roles", "Role page: what it can do per service from every attached policy, exposure with the way in, owner and tags, what the resources it can reach are by name, who can assume it, whether it is used, and suggested changes", "Account by permission matrix", "Role profile with decisions and the reason for each", "Which users and roles can assume a role, and which workloads run as it", "Access Explorer: which users and roles can perform a role-assumption or identity-changing action on a chosen target, or read, write or delete objects in a bucket, read a secret or decrypt with a key; ready questions built from the scan; callers ranked with specific grants before administrators; optionally who can reach a role through other roles, up to three steps", "Same-account trust that names a user or role counts as enough on its own, as in AWS", "Which controls are missing evidence"},
			Limitations: []string{"Declared permissions are not evaluated access", "Who can assume a role comes from stored policies, not CloudTrail; accounts that were not scanned and federated principals are not listed", "The account matrix is for roles; users have their own table beside it", "What a role can do is read from policy text per service; explicit denies are not applied, and a resource count is every resource of that kind the scan collected in the account, so it is the most the policy grants, not proof of access", "Reach is counted for S3 buckets, EC2 instances, RDS instances and Lambda functions only; a bucket is flagged as possibly holding logs from its name alone, since the scan does not read which bucket a trail writes to", "Exposure follows EC2 instances only; other workload types show not checked", "The stolen-credentials counts cover sensitive actions (IAM changes, role assumption, secrets, keys); S3 objects are checked only when the S3 object inventory is on", "Severity reasoning is not recorded with the finding, so the page cannot say what would raise it", "Access Explorer on a bucket asks about objects anywhere in it, so access limited to a prefix, and access the bucket policy gives to accounts outside the scan, are not listed. Where the bucket's ACL and public-access-block settings were not collected, a caller its own policy allows is shown as likely, not certain, and callers with no allow stay undecided because an ACL could still grant them access", "Access Explorer chains follow sts:AssumeRole only, to three steps and 150 role expansions; hitting the bound is reported. The account index (who each identity is, the ready questions) is computed once per scan, about a second for 3,000 identities, then cached", "Whether an instance enforces IMDSv2 is not collected"}, Page: "/identities",
		},
		{
			ID: "blast", Name: "Blast Explorer", Area: AreaInvestigate, Status: StatusReady,
			Summary:     "If an identity's credentials are stolen, what can it take over and reach, from the stored policies.",
			Covers:      []string{"Start from any user or role (searchable, riskiest first), a resource (bucket, certificate, DNS record, CloudFront distribution, load balancer and so on) or a finding; a finding about a resource opens the resource answer", "For a resource: what it is connected to (DNS names pointing at it, the distribution that fronts it, the certificate it uses), takeover risk when an orphaned-edge finding names it, who can read, write or delete a bucket, read a secret or decrypt with a key, and the findings on it, as plain statements with a copyable summary", "A plain answer first (full control of IAM, which users it can take over, which roles it can assume or change), then each route as boxes, what it can reach by name, what gives it the access, a suggested change, and a copyable summary", "Three questions: how it can escalate, what it can reach, and its connections", "Steps into AWS service-linked roles are skipped, because AWS does not let anyone rewrite or grant on them", "One route per kind and target, even when two API calls enable it"},
			Limitations: []string{"The route answer and what it can reach are computed from the stored scan and need no graph database; only the Connections picture needs Neo4j, and without it that view says so", "An administrator always hits the search limit, so for it the routes are a sample and the page says so", "Only steps the starting identity takes itself are listed as routes; what other identities could do once taken over is counted, and listed under technical details", "Chains follow the modeled techniques only; none found means none found in those techniques", "Suggested change names the policy that gives administrator access or IAM write; it does not compute which single change closes the most routes in a non-administrator case", "No comparison with the previous scan for a route", "A resource answer uses only the relationships the scan collected (DNS to target, CloudFront to origin, certificate use); where a collector did not record one, the answer does not mention it and does not say it is absent", "Takeover risk is stated only when an orphaned-edge finding names the resource; it was covered by a unit test and not seen on real data, because none of the sample scans has an orphaned-edge finding that matches a collected resource", "For a bucket, access limited to a prefix and access its policy gives to accounts outside the scan are not listed"},
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
			Covers:      []string{"Scan digest (what changed), new critical findings, new internet-reachable resources, new takeover risks, new public buckets, new escalation paths, console users without MFA, key issues, administrators, reclaimable and stale external trust", "Routing by account", "Cooldown and preview"},
			Limitations: []string{"Alerts follow scans, so they are not real time", "Slack only", "Rules that look for something new need a previous scan; the first scan only reports totals"}, Page: "/alerting",
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
			Covers:      []string{"Golden corpus with a zero-false-allow gate", "Labeled synthetic dataset check", "`cloudrift verify authz`: compares identity-only IAM decisions with iam:SimulatePrincipalPolicy and reports agreement, disagreement, conservative answers and what was not comparable"},
			Limitations: []string{"The simulator check covers identity-only IAM actions on identity policies and boundaries; callers with SCP/RCP in the scan are reported as not comparable, and it needs a live AWS account", "Synthetic data only; no production account validation", "The simulator ignores resource policies, SCPs and RCPs"},
			Docs:        "docs/audits/phase-4f-final-entitlement-hardening.md",
		},

		{
			ID: "cloudtrail", Name: "API activity from CloudTrail", Area: AreaRoadmap, Status: StatusPlanned,
			Summary: "Would show what a role did, and from which address, beyond assuming it: calls made with an instance role's credentials and S3 data events, for after-the-fact detection.",
			Covers:  []string{}, Limitations: []string{"Not built. AssumeRole calls are covered under Who assumed each role; other API calls and S3 data events are not read, and the trail Cloudrift's account writes is not read back"},
		},
		{
			ID: "users-groups", Name: "IAM users and groups", Area: AreaCollect, Status: StatusPartial,
			Summary:     "Collects users and groups with their inline and managed policies, memberships and permissions boundaries.",
			Covers:      []string{"Which policies apply to each user, directly or through a group", "Console access, MFA and access key age and use from the credential report, with last use refreshed from IAM at scan time (the credential report alone can be up to four hours behind)", "Users in the account permission table", "Group membership", "User permissions boundaries", "IAM tags on users (a Team or Owner tag fills the finding's team)", "An explicit Deny in any source overriding an Allow in another"},
			Limitations: []string{"Needs iam:GetAccountAuthorizationDetails; if denied the scan continues without users and groups", "Credential data comes from the IAM credential report; if it is denied the users are still collected without it", "Root account keys and MFA are not assessed", "Group tags are not collected", "The IAM credential report is cached by AWS for up to four hours, so a user created after it has no credential data until it refreshes; the scan records the report time and the Users and Groups page says so", "Hardware key and virtual MFA device details are not collected, only whether MFA is active", "Live last use (scan.live_key_last_used) asks IAM per active key and per console user, up to a call budget per account; users beyond it, or a refused call, keep the report's dates and the collection is marked partial. AWS itself updates key last-used roughly hourly, so a use in the last hour may still be missing. A key is matched to its report slot by creation time", "With live last use off, last-used dates, last sign-in and the never-used and unused-key findings are as of the credential report's time, and the page says so"},
			Permissions: []string{"iam:GetAccountAuthorizationDetails", "iam:GenerateCredentialReport", "iam:GetCredentialReport", "iam:ListAccessKeys", "iam:GetAccessKeyLastUsed", "iam:GetUser"},
			ConfigKeys:  []string{"scan.iam_policy_inventory", "scan.live_key_last_used", "scan.live_key_last_used_max_calls"}, Collectors: []string{"iam_users_groups", "iam_credential_report"}, AssetTypes: []string{"iam_user", "iam_group"}, Page: "/principals",
			Evidence: []string{"Tested with fakes for three cases: group plus own inline policy, managed plus inline, and an inline Deny over an Allow", "Not yet run against a real AWS account"},
		},
		{
			ID: "other-clouds", Name: "Other clouds", Area: AreaRoadmap, Status: StatusPlanned,
			Summary: "Azure and GCP.", Covers: []string{}, Limitations: []string{"Not built. AWS only"},
		},
	}
}
