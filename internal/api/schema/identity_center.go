package schema

// IdentityCenterResponse is the IAM Identity Center view: permission sets, the people and groups assigned to them in each
// account, and which of those reach an account with administrative permissions.
type IdentityCenterResponse struct {
	ScanID string `json:"scan_id"`
	// State is collected, partial, failed, no_instance or not_collected. Only collected and partial carry data.
	State string `json:"state"`
	// Detail says why, in the words of the collection record.
	Detail string `json:"detail"`
	// ConfigKey is the setting that turns collection on; set when State is not_collected.
	ConfigKey      string                        `json:"config_key,omitempty"`
	Instances      []IdentityCenterInstance      `json:"instances"`
	PermissionSets []IdentityCenterPermissionSet `json:"permission_sets"`
	Principals     []IdentityCenterPrincipal     `json:"principals"`
	Accounts       []IdentityCenterAccount       `json:"accounts"`
	Notes          []string                      `json:"notes"`
}

type IdentityCenterInstance struct {
	ARN             string `json:"arn"`
	Name            string `json:"name"`
	IdentityStoreID string `json:"identity_store_id"`
	OwnerAccountID  string `json:"owner_account_id"`
	Status          string `json:"status"`
}

type IdentityCenterPolicyRef struct {
	Name string `json:"name"`
	ARN  string `json:"arn,omitempty"`
}

type IdentityCenterPermissionSet struct {
	ARN             string `json:"arn"`
	Name            string `json:"name"`
	Description     string `json:"description"`
	SessionDuration string `json:"session_duration"`
	// Administrative is true when the set grants every action on every resource: the AdministratorAccess managed policy, or an
	// inline policy with an unconditional Allow on * for *. AdminReason names which.
	Administrative  bool                      `json:"administrative"`
	AdminReason     string                    `json:"admin_reason,omitempty"`
	Managed         []IdentityCenterPolicyRef `json:"managed_policies"`
	CustomerManaged []IdentityCenterPolicyRef `json:"customer_managed_policies"`
	HasInline       bool                      `json:"has_inline_policy"`
	Accounts        []string                  `json:"accounts"`
	// Roles are the IAM roles this set created in those accounts (AWSReservedSSO_<name>_*), when the role inventory has them.
	Roles       []string `json:"roles"`
	Assignments int      `json:"assignments"`
	ReadStatus  string   `json:"read_status"`
	ReadError   string   `json:"read_error,omitempty"`
}

type IdentityCenterAssignment struct {
	AccountID        string `json:"account_id"`
	PermissionSet    string `json:"permission_set"`
	PermissionSetARN string `json:"permission_set_arn"`
	Administrative   bool   `json:"administrative"`
	// Via is "direct" or "group: <name>".
	Via string `json:"via"`
}

type IdentityCenterPrincipal struct {
	ARN         string   `json:"arn"`
	Kind        string   `json:"kind"` // user or group
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name,omitempty"`
	NameRead    bool     `json:"name_read"`
	Groups      []string `json:"groups"`
	Members     int      `json:"members"`
	// Assignments are the account and permission set pairs this principal holds. For a user they include those held through groups.
	Assignments      []IdentityCenterAssignment `json:"assignments"`
	AdministrativeIn []string                   `json:"administrative_in"`
}

type IdentityCenterAccount struct {
	AccountID                string `json:"account_id"`
	PermissionSets           int    `json:"permission_sets"`
	Principals               int    `json:"principals"`
	AdministrativePrincipals int    `json:"administrative_principals"`
}
