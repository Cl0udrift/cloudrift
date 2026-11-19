#!/usr/bin/env bash
# Deletes everything up.sh created (all named cr-dec-*) and then lists anything left. Safe to run twice.
set -uo pipefail
export AWS_PAGER=""
REGION="${LAB_REGION:-us-east-1}"; export AWS_DEFAULT_REGION="$REGION"
ACCT="$(aws sts get-caller-identity --query Account --output text)"
aws autoscaling delete-auto-scaling-group --auto-scaling-group-name cr-dec-asg --force-delete 2>/dev/null
for t in cr-dec-lt-pinned cr-dec-lt-unused; do aws ec2 delete-launch-template --launch-template-name "$t" >/dev/null 2>&1; done
for s in cr-dec-stack cr-dec-stack-ro cr-dec-stack-norole; do aws cloudformation delete-stack --stack-name "$s" 2>/dev/null; done
for p in cr-dec-build cr-dec-build-ro; do aws codebuild delete-project --name "$p" 2>/dev/null; done
SM="$(aws stepfunctions list-state-machines --query "stateMachines[?name=='cr-dec-sm'].stateMachineArn" --output text)"
[ -n "$SM" ] && aws stepfunctions delete-state-machine --state-machine-arn "$SM"
for u in cr-dec-true cr-dec-wrongarn cr-dec-deny cr-dec-boundary cr-dec-partial cr-dec-lt cr-dec-condition cr-dec-lowtarget; do
  aws iam delete-user-policy --user-name "$u" --policy-name p 2>/dev/null; aws iam delete-user-permissions-boundary --user-name "$u" 2>/dev/null; aws iam delete-user --user-name "$u" 2>/dev/null
done
aws iam remove-role-from-instance-profile --instance-profile-name cr-dec-profile --role-name cr-dec-target 2>/dev/null
aws iam delete-instance-profile --instance-profile-name cr-dec-profile 2>/dev/null
aws iam detach-role-policy --role-name cr-dec-target --policy-arn arn:aws:iam::aws:policy/AdministratorAccess 2>/dev/null
aws iam detach-role-policy --role-name cr-dec-readonly --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess 2>/dev/null
aws iam delete-role --role-name cr-dec-target 2>/dev/null; aws iam delete-role --role-name cr-dec-readonly 2>/dev/null
aws iam delete-policy --policy-arn "arn:aws:iam::$ACCT:policy/cr-dec-boundary" 2>/dev/null
sleep 25
echo "--- left over (should be empty):"
aws iam list-users --query "Users[?starts_with(UserName,'cr-dec')].UserName" --output text
aws iam list-roles --query "Roles[?starts_with(RoleName,'cr-dec')].RoleName" --output text
aws iam list-policies --scope Local --query "Policies[?starts_with(PolicyName,'cr-dec')].PolicyName" --output text
aws iam list-instance-profiles --query "InstanceProfiles[?starts_with(InstanceProfileName,'cr-dec')].InstanceProfileName" --output text
aws cloudformation list-stacks --query "StackSummaries[?starts_with(StackName,'cr-dec') && StackStatus!='DELETE_COMPLETE'].StackName" --output text
aws codebuild list-projects --query "projects[?starts_with(@,'cr-dec')]" --output text
aws stepfunctions list-state-machines --query "stateMachines[?starts_with(name,'cr-dec')].name" --output text
aws autoscaling describe-auto-scaling-groups --query "AutoScalingGroups[?starts_with(AutoScalingGroupName,'cr-dec')].AutoScalingGroupName" --output text
aws ec2 describe-launch-templates --query "LaunchTemplates[?starts_with(LaunchTemplateName,'cr-dec')].LaunchTemplateName" --output text
