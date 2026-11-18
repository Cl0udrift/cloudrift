Example SCPs and RCPs copied unchanged from AWS's own sample repositories (MIT-0 licensed):

- https://github.com/aws-samples/service-control-policy-examples (linked from the Organizations user guide, "Service control policy examples")
- https://github.com/aws-samples/resource-control-policy-examples (linked from "Resource control policy examples")

Placeholders such as `${Account}`, `[PRIVILEGED_ROLE]` and `[BUCKET_TO_PROTECT]` are replaced in `aws_examples_test.go`.
The repositories do not state expected results, so each case's expectation is derived from the documented evaluation rules
(deny list strategy: FullAWSAccess allows everything, an explicit Deny wins). SCP cases are also checked against
iam:SimulateCustomPolicy by `cloudrift verify scp-examples`.
