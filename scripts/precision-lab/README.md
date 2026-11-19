# Precision lab

A live check that Cloudrift does not report paths that do not exist. It builds a small lab in the AWS account your credentials point
at (everything named `cr-dec-*`, nothing that costs money while idle), scans it, and counts what was reported:

- **cr-dec-true** holds the calls that really reach an administrative role through a CloudFormation stack, a CodeBuild project and a
  Step Functions state machine. It must be found (recall).
- **Seven decoys** each look able to and are not: a policy scoped to the wrong resource, an explicit Deny, a permissions boundary,
  a missing second call, a condition that cannot be decided, launch templates that no Auto Scaling group follows, and a stack that has
  no role. Each must produce no escalation finding (precision). `cr-dec-lowtarget` reaches only a read-only role and may be reported
  there at Medium, never at the administrative role.

```bash
export AWS_PROFILE=<a profile allowed to create and delete IAM users and roles>
scripts/precision-lab/up.sh
cloudrift scan --ciem --output-dir ./lab-out      # in single-account mode
scripts/precision-lab/score.py ./lab-out
scripts/precision-lab/down.sh
```

Run it only in an account where creating and deleting IAM users and roles is acceptable. It does not give a rate for your own account:
it tests that these named situations are handled, not that nothing else is wrong.
