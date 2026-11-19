#!/usr/bin/env python3
"""Scores a Cloudrift scan of the precision lab. Usage: score.py <scan output directory or a scan directory inside it>

Expected, from how the lab was built:
  cr-dec-true      must be reported reaching cr-dec-target through all three of CloudFormation, CodeBuild and Step Functions
  cr-dec-lowtarget may be reported, only against cr-dec-readonly, and never above Medium
  every other cr-dec-* user must have no escalation finding at all
Exit status is non-zero on a miss or a false positive."""
import glob, json, os, sys

root = sys.argv[1] if len(sys.argv) > 1 else "."
dirs = [root] if os.path.exists(os.path.join(root, "findings.json")) else sorted(glob.glob(os.path.join(root, "*", "findings.json")))
if not dirs:
    sys.exit("no scan found under " + root)
path = dirs[-1] if dirs[-1].endswith("findings.json") else os.path.join(dirs[-1], "findings.json")
data = json.load(open(path))
findings = data if isinstance(data, list) else data.get("findings", [])

found = {}  # principal -> [(severity, target, variants)]
for f in findings:
    ev = f.get("evidence", {})
    if ev.get("issue_category") == "privilege_escalation":
        who = ev.get("principal_arn", "").split("/")[-1]
        found.setdefault(who, []).append((f["severity"], ev.get("target_arn", "").split("/")[-1], sorted(ev.get("variants") or [ev.get("technique")])))

want_true = {"WORKLOAD_CLOUDFORMATION_002", "WORKLOAD_CODEBUILD_002", "WORKLOAD_STATES_002"}
decoys = ["cr-dec-wrongarn", "cr-dec-deny", "cr-dec-boundary", "cr-dec-partial", "cr-dec-lt", "cr-dec-condition"]
problems = []
hit = {v for sev, tgt, vs in found.get("cr-dec-true", []) if tgt == "cr-dec-target" for v in vs}
print(f"control cr-dec-true -> cr-dec-target: found {len(hit & want_true)} of {len(want_true)} techniques")
if not want_true <= hit:
    problems.append("MISS: the control user's path was not fully reported: " + ", ".join(sorted(want_true - hit)))
for who in decoys:
    got = found.get(who, [])
    print(f"decoy {who}: {'no finding' if not got else 'FINDING ' + str(got)}")
    if got:
        problems.append(f"FALSE POSITIVE: {who} {got}")
low = found.get("cr-dec-lowtarget", [])
print(f"cr-dec-lowtarget: {low if low else 'no finding'}")
for sev, tgt, vs in low:
    if tgt != "cr-dec-readonly" or sev in ("high", "critical"):
        problems.append(f"FALSE POSITIVE: cr-dec-lowtarget reached {tgt} at {sev}")
extra = [w for w in found if w.startswith("cr-dec-") and w not in decoys + ["cr-dec-true", "cr-dec-lowtarget"]]
if extra:
    problems.append("unexpected principals with findings: " + ", ".join(extra))
print("\n" + ("PASS: no miss, no false positive" if not problems else "\n".join(problems)))
sys.exit(1 if problems else 0)
