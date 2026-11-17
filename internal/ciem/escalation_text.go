package ciem

import (
	"strings"

	"github.com/Zero0x00/cloudrift/internal/models"
)

type escText struct {
	edge           string
	impact         string
	recommendation string
	options        []RemediationOption
	title          func(principal, target string) string
	command        func(p models.AssetNode, target string) string
}

// escalationTextFor is escalationText, except for the technique whose meaning the kind alone does not say: an escalation
// to the principal itself is a "self policy grant" by kind, but here it is a switch to an older policy version.
func escalationTextFor(kind, technique string) escText {
	if technique != "SET_DEFAULT_POLICY_VERSION" {
		return escalationText(kind)
	}
	return escText{
		edge:           "can switch to an administrative version of a policy that applies to",
		impact:         "This principal may make an older version of a policy the default, and a stored version of that policy grants administrative access.",
		recommendation: "Remove iam:SetDefaultPolicyVersion, and delete the old versions that grant more than the current one.",
		options: []RemediationOption{
			{"Remove the permission", "Stops the switch.", []string{"Remove iam:SetDefaultPolicyVersion from the principal's policies"}},
			{"Delete the old versions", "Leaves nothing broader to switch to.", []string{"Delete the non-default versions that grant more than the current one (iam:DeletePolicyVersion)"}},
		},
		title: func(p, t string) string {
			if p == t {
				return p + " can switch to an administrative version of its own policy"
			}
			return p + " can switch to an administrative version of a policy that applies to " + t
		},
		command: func(_ models.AssetNode, t string) string {
			return "aws iam list-policy-versions --policy-arn <POLICY_ARN>\naws iam get-policy-version --policy-arn <POLICY_ARN> --version-id <VERSION>\n# Delete a broader old version:\n# aws iam delete-policy-version --policy-arn <POLICY_ARN> --version-id <VERSION>"
		},
	}
}

// escalationText is the wording and fix options for one escalation kind. The fix is always the same shape: remove the
// permission that makes the path work, or stop the target from being usable that way.
func escalationText(kind string) escText {
	switch {
	case kind == "SELF_POLICY_GRANT":
		return escText{
			edge:           "can change its own policies",
			impact:         "This principal may attach or write a policy that applies to itself, so it can give itself any permission, including administrative access.",
			recommendation: "Remove the permission to change its own policies, or limit it with a permissions boundary.",
			options: []RemediationOption{
				{"Remove the permission", "Nothing else needs to change.", []string{"Remove iam:AttachUserPolicy, iam:PutUserPolicy, iam:AttachRolePolicy, iam:PutRolePolicy or iam:CreatePolicyVersion on itself from its policies"}},
				{"Add a permissions boundary", "Caps what it can grant itself.", []string{"Attach a boundary that excludes administrative actions", "Deny changing the boundary itself"}},
			},
			title: func(p, _ string) string { return p + " can grant itself more permissions" },
			command: func(p models.AssetNode, _ string) string {
				return "aws iam list-attached-" + noun(p) + "-policies --" + noun(p) + "-name " + p.Name + "\naws iam list-" + noun(p) + "-policies --" + noun(p) + "-name " + p.Name +
					"\n# Detach or narrow the policy that allows the change, then re-scan."
			},
		}
	case kind == "SELF_GROUP_JOIN":
		return escText{
			edge:           "can add itself to",
			impact:         "This user may add itself to a group that holds administrative policies, which gives it administrative access.",
			recommendation: "Remove iam:AddUserToGroup for that group, or move the administrative policies out of the group.",
			options: []RemediationOption{
				{"Remove the permission", "Stops the join.", []string{"Remove iam:AddUserToGroup on the group from the user's policies"}},
				{"Remove administrative policies from the group", "Makes the group harmless to join.", []string{"Detach the administrative policy from the group and use a role with MFA instead"}},
			},
			title: func(p, t string) string { return p + " can add itself to administrative group " + t },
			command: func(p models.AssetNode, t string) string {
				return "aws iam list-attached-group-policies --group-name " + nameOf(t) + "\naws iam list-groups-for-user --user-name " + p.Name
			},
		}
	case kind == "TRUST_REWRITE":
		return escText{
			edge:           "can rewrite the trust of",
			impact:         "This principal may change the trust policy of a role so that it trusts the principal, then assume the role and use its permissions.",
			recommendation: "Remove iam:UpdateAssumeRolePolicy on that role, and protect the role's trust policy with a Deny that only break-glass principals are exempt from.",
			options: []RemediationOption{
				{"Remove the permission", "Stops the rewrite.", []string{"Remove iam:UpdateAssumeRolePolicy on the role from the principal's policies"}},
				{"Protect the role", "Keeps the trust policy from being changed by others.", []string{"Add a service control policy or boundary that denies iam:UpdateAssumeRolePolicy except for a named administrator role"}},
			},
			title: func(p, t string) string { return p + " can rewrite the trust policy of role " + t },
			command: func(_ models.AssetNode, t string) string {
				return "aws iam get-role --role-name " + nameOf(t) + " --query Role.AssumeRolePolicyDocument"
			},
		}
	case kind == "GRANT_ON_REACHABLE_ROLE":
		return escText{
			edge:           "can attach a policy to",
			impact:         "This principal can assume a role and may attach or write a policy on it, so it can give that role any permission.",
			recommendation: "Remove the permission to attach or write policies on that role.",
			options: []RemediationOption{
				{"Remove the permission", "Stops the grant.", []string{"Remove iam:AttachRolePolicy and iam:PutRolePolicy on the role from the principal's policies"}},
				{"Narrow who can assume the role", "Removes the route.", []string{"Edit the role's trust policy so only principals that need it are listed"}},
			},
			title: func(p, t string) string { return p + " can attach a policy to role " + t },
			command: func(_ models.AssetNode, t string) string {
				return "aws iam list-attached-role-policies --role-name " + nameOf(t) + "\naws iam get-role --role-name " + nameOf(t)
			},
		}
	case kind == "USER_TAKEOVER":
		return escText{
			edge:           "can create credentials for",
			impact:         "This principal may create an access key or console password for another user, then act as that user.",
			recommendation: "Remove iam:CreateAccessKey, iam:CreateLoginProfile and iam:UpdateLoginProfile on other users.",
			options: []RemediationOption{
				{"Remove the permission", "Stops the takeover.", []string{"Remove iam:CreateAccessKey, iam:CreateLoginProfile and iam:UpdateLoginProfile on the user from the principal's policies"}},
				{"Limit it to itself", "Keeps self-service key rotation.", []string{"Scope the permission to ${aws:username}"}},
			},
			title: func(p, t string) string { return p + " can create credentials for user " + t },
			command: func(_ models.AssetNode, t string) string {
				return "aws iam list-access-keys --user-name " + nameOf(t) + "\naws iam get-login-profile --user-name " + nameOf(t)
			},
		}
	case strings.HasPrefix(kind, "PASS_ROLE_"):
		return escText{
			edge:           "can pass a role and run code as",
			impact:         "This principal may pass a role to an AWS service and then make the calls that run its code, so the code runs with that role's permissions.",
			recommendation: "Limit iam:PassRole to the roles it needs, with an iam:PassedToService condition, or remove the calls that run code.",
			options: []RemediationOption{
				{"Narrow iam:PassRole", "The most direct fix.", []string{"Scope iam:PassRole to the specific role ARNs it needs", "Add a condition on iam:PassedToService for the one service"}},
				{"Remove the service calls", "Without them the passed role cannot be used.", []string{"Remove the create or start actions for the service from the principal's policies"}},
				{"Tighten the role's trust", "Stops the service from using the role.", []string{"Remove the service from the role's trust policy if nothing needs it"}},
			},
			title: func(p, t string) string { return p + " can pass role " + t + " to a service and run code as it" },
			command: func(_ models.AssetNode, t string) string {
				return "aws iam get-role --role-name " + nameOf(t) + " --query Role.AssumeRolePolicyDocument\naws iam list-attached-role-policies --role-name " + nameOf(t)
			},
		}
	case strings.HasPrefix(kind, "WORKLOAD_"):
		return escText{
			edge:           "can run code on a workload that runs as",
			impact:         "This principal may run commands or code on an EC2 instance or ECS task, and so use the credentials of the role it runs as.",
			recommendation: "Remove the permission to run commands on that workload, or give the workload a narrower role.",
			options: []RemediationOption{
				{"Remove the permission", "Stops access to the workload.", []string{"Remove ssm:StartSession, ssm:SendCommand, ec2-instance-connect:SendSSHPublicKey, ec2:ModifyInstanceAttribute or ecs:ExecuteCommand on it from the principal's policies"}},
				{"Narrow the workload's role", "Limits what running code there gives.", []string{"Replace the role the workload runs as with one scoped to what it needs"}},
			},
			title: func(p, t string) string { return p + " can run code on a workload that runs as role " + t },
			command: func(_ models.AssetNode, t string) string {
				return "aws iam list-attached-role-policies --role-name " + nameOf(t) + "\n# Review who may run commands on workloads that use this role."
			},
		}
	case kind == "EDIT_LAMBDA_CODE":
		return escText{
			edge:           "can edit code that runs as",
			impact:         "This principal may replace the code of a Lambda function, which then runs with the function's execution role.",
			recommendation: "Remove lambda:UpdateFunctionCode on that function, or narrow the function's execution role.",
			options: []RemediationOption{
				{"Remove the permission", "Stops the code change.", []string{"Remove lambda:UpdateFunctionCode on the function from the principal's policies"}},
				{"Narrow the execution role", "Limits what the changed code can do.", []string{"Replace the execution role with one scoped to the function"}},
			},
			title: func(p, t string) string { return p + " can edit Lambda code that runs as role " + t },
			command: func(_ models.AssetNode, t string) string {
				return "aws iam list-attached-role-policies --role-name " + nameOf(t)
			},
		}
	}
	return escText{
		edge: "can escalate to", impact: "This principal has a validated path that gives it more access than it started with.",
		recommendation: "Remove the permission that makes the path work.",
		title:          func(p, t string) string { return p + " can escalate privileges (" + kind + ") on " + t },
		command:        func(models.AssetNode, string) string { return "" },
	}
}

func noun(p models.AssetNode) string {
	if p.AssetType == models.AssetIAMUser {
		return "user"
	}
	return "role"
}
