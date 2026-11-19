#!/usr/bin/env bash
# Creates a small lab in the account your AWS credentials point at: resources that run as roles, one control user who really can
# reach them, and decoy users who look able to but are not. Everything is named cr-dec-*. Nothing costs money while idle (an Auto
# Scaling group at size 0, a state machine and a build project that never run, IAM, CloudFormation stacks with a wait handle).
# Run it only in an account where creating and deleting IAM users and roles is acceptable, then run down.sh.
set -euo pipefail
export AWS_PAGER=""
REGION="${LAB_REGION:-us-east-1}"; export AWS_DEFAULT_REGION="$REGION"
ACCT="$(aws sts get-caller-identity --query Account --output text)"
AMI="$(aws ssm get-parameter --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 --query Parameter.Value --output text)"
SUBNET="$(aws ec2 describe-subnets --filters Name=default-for-az,Values=true --query 'Subnets[0].SubnetId' --output text)"
[ "$SUBNET" != "None" ] || { echo "no default subnet in $REGION; set LAB_REGION to a Region that has one"; exit 1; }
echo "account $ACCT, region $REGION"

TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":["cloudformation.amazonaws.com","codebuild.amazonaws.com","states.amazonaws.com","ec2.amazonaws.com"]},"Action":"sts:AssumeRole"}]}'
role() { aws iam create-role --role-name "$1" --assume-role-policy-document "$TRUST" --description "Cloudrift precision lab, safe to delete" >/dev/null; aws iam attach-role-policy --role-name "$1" --policy-arn "$2"; }
role cr-dec-target arn:aws:iam::aws:policy/AdministratorAccess
role cr-dec-readonly arn:aws:iam::aws:policy/ReadOnlyAccess
aws iam create-instance-profile --instance-profile-name cr-dec-profile >/dev/null
aws iam add-role-to-instance-profile --instance-profile-name cr-dec-profile --role-name cr-dec-target
BP="$(aws iam create-policy --policy-name cr-dec-boundary --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}' --query Policy.Arn --output text)"

user() { aws iam create-user --user-name "$1" ${3:+--permissions-boundary "$3"} >/dev/null; aws iam put-user-policy --user-name "$1" --policy-name p --policy-document "$2"; }
# Control: holds the calls that really reach the administrative role. Must be found.
user cr-dec-true '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["cloudformation:UpdateStack","codebuild:StartBuild","states:UpdateStateMachine","states:StartExecution"],"Resource":"*"}]}'
# Decoys: each looks able to, and is not, for a different reason.
user cr-dec-wrongarn '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudformation:UpdateStack","Resource":"arn:aws:cloudformation:'$REGION':'$ACCT':stack/cr-dec-stack-norole/*"},{"Effect":"Allow","Action":"codebuild:StartBuild","Resource":"arn:aws:codebuild:'$REGION':'$ACCT':project/does-not-exist"}]}'
user cr-dec-deny '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"codebuild:StartBuild","Resource":"*"},{"Effect":"Deny","Action":"codebuild:StartBuild","Resource":"*"}]}'
user cr-dec-boundary '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["states:UpdateStateMachine","states:StartExecution","cloudformation:UpdateStack","codebuild:StartBuild"],"Resource":"*"}]}' "$BP"
user cr-dec-partial '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["states:UpdateStateMachine","cloudformation:CreateChangeSet","batch:DescribeJobDefinitions","codebuild:BatchGetProjects"],"Resource":"*"}]}'
user cr-dec-lt '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["ec2:CreateLaunchTemplateVersion","ec2:ModifyLaunchTemplate"],"Resource":"*"}]}'
user cr-dec-condition '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["codebuild:StartBuild","states:UpdateStateMachine","states:StartExecution"],"Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}'
# Reaches a read-only role only: a real but small escalation, expected at Medium and never at the administrative role.
user cr-dec-lowtarget '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudformation:UpdateStack","Resource":"arn:aws:cloudformation:'$REGION':'$ACCT':stack/cr-dec-stack-ro/*"},{"Effect":"Allow","Action":"codebuild:StartBuild","Resource":"arn:aws:codebuild:'$REGION':'$ACCT':project/cr-dec-build-ro"}]}'
sleep 12 # IAM propagation

TEMPLATE='{"Resources":{"H":{"Type":"AWS::CloudFormation::WaitConditionHandle"}}}'
aws cloudformation create-stack --stack-name cr-dec-stack --role-arn "arn:aws:iam::$ACCT:role/cr-dec-target" --template-body "$TEMPLATE" >/dev/null
aws cloudformation create-stack --stack-name cr-dec-stack-ro --role-arn "arn:aws:iam::$ACCT:role/cr-dec-readonly" --template-body "$TEMPLATE" >/dev/null
aws cloudformation create-stack --stack-name cr-dec-stack-norole --template-body "$TEMPLATE" >/dev/null # runs as its caller: no role to reach
project() { aws codebuild create-project --name "$1" --source 'type=NO_SOURCE,buildspec=version: 0.2\nphases:\n  build:\n    commands:\n      - echo hi' --artifacts type=NO_ARTIFACTS --environment type=LINUX_CONTAINER,image=aws/codebuild/standard:7.0,computeType=BUILD_GENERAL1_SMALL --service-role "arn:aws:iam::$ACCT:role/$2" >/dev/null; }
project cr-dec-build cr-dec-target
project cr-dec-build-ro cr-dec-readonly
aws stepfunctions create-state-machine --name cr-dec-sm --role-arn "arn:aws:iam::$ACCT:role/cr-dec-target" --definition '{"StartAt":"P","States":{"P":{"Type":"Pass","End":true}}}' >/dev/null
LT='{"ImageId":"'$AMI'","InstanceType":"t3.micro","IamInstanceProfile":{"Name":"cr-dec-profile"}}'
aws ec2 create-launch-template --launch-template-name cr-dec-lt-pinned --launch-template-data "$LT" >/dev/null # its group is pinned to version 1
aws ec2 create-launch-template --launch-template-name cr-dec-lt-unused --launch-template-data "$LT" >/dev/null # no group uses it
aws autoscaling create-auto-scaling-group --auto-scaling-group-name cr-dec-asg --launch-template LaunchTemplateName=cr-dec-lt-pinned,Version=1 --min-size 0 --max-size 0 --desired-capacity 0 --vpc-zone-identifier "$SUBNET"
echo "lab is up. Scan it, then: scripts/precision-lab/score.py <scan directory>, then scripts/precision-lab/down.sh"
