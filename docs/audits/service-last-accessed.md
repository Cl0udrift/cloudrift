# Service last-accessed collection (opt-in)

Status: implemented, **default off**, tested only with mocked IAM clients. It has not been run against AWS.

## What it collects
For each IAM role, IAM access advisor reports the services the role's permissions allow and when each was last authenticated. Cloudrift uses `SERVICE_LEVEL` granularity only. It does not show which actions were used, who used them, or anything about permissions on resources outside IAM's tracking window (about 400 days).

Dashboard meaning for a declared permission (Identities, candidate card):
| Chip | Meaning |
|---|---|
| Service used `<date>` | IAM reported an authentication to that service |
| Service not used in IAM window | IAM listed the service and reported no access in its window. This is the only "possibly unused" signal |
| Service not listed by IAM | IAM did not list that service for the role. No conclusion is drawn |
| Service use unknown | Collection was partial, failed or not collected for the role |
| Action used `<date>` | Action-level mode: IAM tracked that exact action and reported a time |
| (no chip) | Collection was not requested for the scan, or the category spans every service (administrative wildcard) |

"Not used" is never a safety claim and is not a reason to remove a permission. Recent use, rare jobs and break-glass roles are all possible.

## Enable
```toml
[scan]
service_last_accessed = true
```
Default is `false`. When off, no IAM client is created and no call is made.

## Exact IAM permissions needed (not added to `iam/auditing-role-policy.json`)
| Action | Purpose | Resource |
|---|---|---|
| `iam:GenerateServiceLastAccessedDetails` | Starts a per-role access advisor report job | `arn:aws:iam::*:role/*` |
| `iam:GetServiceLastAccessedDetails` | Reads the job result (paginated) | `arn:aws:iam::*:role/*` |

`iam:ListRoles` is already required. Before granting, confirm in the IAM service authorization reference that both actions are read-only for your policy review. Report generation starts a job on the AWS side but changes no resource. This was not verified against AWS here.

Suggested statement, for you to review and apply:
```json
{
  "Sid": "IamServiceLastAccessed",
  "Effect": "Allow",
  "Action": [
    "iam:GenerateServiceLastAccessedDetails",
    "iam:GetServiceLastAccessedDetails"
  ],
  "Resource": "arn:aws:iam::*:role/*"
}
```

## Options (all under `[scan]`)
| Key | Default | Effect |
|---|---|---|
| `service_last_accessed` | `false` | Master switch |
| `service_last_accessed_granularity` | `"service"` | `"action"` also requests IAM tracked actions (for example `iam:PassRole`, `iam:AttachRolePolicy`). S3 object and STS actions are not tracked by AWS and stay service-level |
| `service_last_accessed_concurrency` | `8` | In-flight Generate calls (Get calls use twice that). Capped at 16 |
| `service_last_accessed_skip_service_linked` | `false` | Optional scope reduction. Skipped roles are recorded as `skipped_service_linked`, never as "no access". Off by default, so every role is collected |
| `service_last_accessed_timeout_seconds` | `0` (none) | Optional total budget per account. Nothing is dropped unless you set it. Roles not finished are `not_collected` |

The dashboard idle threshold for role last-used is selectable (30, 60, 90, 180, 365 days) and is stored in the URL as `idle_days`.

## How the cost and time problem is addressed
Each role needs its own access advisor job, so cost is one Generate plus one or more Get calls per role. Wall-clock time was the real problem.

- **Before:** each worker held a slot for the whole life of its job, sleeping between polls, so total time was roughly roles / workers x job time.
- **Now:** a role waits for its job outside any slot. Only the API calls themselves use slots, so jobs run on AWS in parallel and total time approaches the slowest job plus submission time.
- **Adaptive polling:** first poll after 1 s, then 1.5x backoff up to 5 s, instead of a fixed interval. This also lowers the number of Get calls.
- **Throttling:** Throttling, RequestLimitExceeded and ServiceUnavailable errors are retried up to 5 times with jittered backoff. Other errors are not retried.
- **No silent loss:** a job that outlives its 5-minute limit is recorded `partial`; a role whose call failed is `not_collected`. The Identities matrix shows "collected for X of Y roles".

Measured with the simulated-latency benchmark (`BenchmarkServiceAccessScheduling`, 160 roles, 8 workers, call 3 ms, job 60 ms, poll 30 ms): about 1518 ms and 640 API calls before, about 135 ms and 480 calls after. This is a simulation of scheduling, not AWS. Real gains depend on AWS job latency and account API rate limits, which were not measured.

## Behaviour and bounds
- Per-role states: `complete`, `partial`, `failed`, `not_collected`, `skipped_service_linked`. Results are paged up to 20 pages per job (more is `partial`).
- A role with no result is `not_collected`, never "unused".
- Still one job per role: very large accounts still make thousands of calls. This cannot be avoided with the access advisor API.

## Not done
Still true:
- Not run against AWS. Action-level behaviour in particular is from the SDK shape and mocks, not observed responses.
- IAM's roughly 400 day tracking window, and service-level (or limited action-level) detail, are AWS limits that Cloudrift cannot change.
- No IAM policy file change, and no per-account matrix column for unused services.
