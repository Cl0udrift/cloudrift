# Dashboard Experience 2.0

Status: **partial delivery**. This cycle delivered the design-token layer, the app shell, shared state primitives, and targeted redesigns of Identities, Inventory and the Overview scan snapshot. Findings, Blast Explorer, Scan Control, Scan History, External entities, Accounts and Remediation were audited but not redesigned.

## 1. Assessment of the original experience
- Navigation was a flat list of 11 items with no grouping. Findings and Triage shared one icon, as did Identities and Access. Blast Explorer was reachable only through deep links.
- On screens under 768 px the fixed sidebar overlaid the content (the content margin applied only from `md` up). This was a P1 usability defect.
- Scan context lived in a tall sidebar card that pushed navigation off short screens, and was absent from the page area.
- The Inventory page restated the scan ID and the synthetic flag. Collection status was a dot-separated sentence, and 17 not-enabled Regions buried the Regions that were actually scanned.
- Identity detail was a bulleted wall of text. Candidate evidence was a single run-on sentence, and the distinctions between attached, declared, evaluated, hypothetical and validated were implicit.
- The Overview showed orphan-scan metrics only, and a scan with zero findings looked like a clean result.

## 2. Competitor research: evidence limitation
No live browsing of Wiz, Aikido or Prowler was performed this cycle, and authenticated products are not reachable. Nothing below is claimed about their detailed behavior. These are general, widely documented patterns, applied as principles:
| Pattern (general, from public positioning) | Cloudrift application | Done |
|---|---|---|
| Persistent scope/context bar | `ScanContextBar` in the topbar on every page | yes |
| Grouped, task-oriented navigation | Overview / Discover / Investigate / Operations | yes |
| Issue feed with compact context lines | Findings list | not done |
| Progressive disclosure of detail | Collapsed not-enabled Regions; evidence cards | partial |
| Connected-resource graph for investigation | Blast Explorer | not done |

Anti-patterns avoided: unexplained risk scores, fabricated trends, color-only status, decorative hero content.

## 3. Visual identity (as implemented)
- Existing Tailwind slate neutrals with one cyan accent, retained.
- Semantic state tokens in `styles.css` (`--cr-ok|warn|bad|unk|info|hyp` as fg/bg/border, light and dark). Each state renders as glyph plus text plus tint.
- Layout tokens: sidebar 15rem (4rem collapsed), topbar 3.25rem. The existing `hs-*` classes are kept as the single component layer.
- `prefers-reduced-motion` disables transitions and animations globally. A skip link and a `main` landmark were added.

## 4. Navigation
Before: 11 flat items. After: Overview (Dashboard); Discover (Inventory, Identities); Investigate (Findings, Triage, External entities, Access, Blast Explorer); Operations (Scan Control, Changes, Alerting, Query). Routes are unchanged. Mobile uses an off-canvas drawer closed by Escape, a scrim click or navigation.

## 5. Page changes
- **Shell:** topbar shows scan ID, Live or Synthetic, timestamp, account scope and a pluralised finding count.
- **Identities:** a five-level "What is known" ladder (attached, declared, evaluated, hypothetical, validated). Candidate cards carry evidence, eligibility and authorization chips, scope, exact conditions and provenance. The role ARN uses `CopyIdentifier`.
- **Inventory:** `MetricCard`s, collection status chips, service coverage chips, ECS/EKS/API Gateway icons, and not-enabled Regions collapsed while scanned, partial, failed and unknown Regions stay visible.
- **Overview:** Scan snapshot strip (resources, IAM roles, collection coverage) from existing endpoints. Unavailable analyses show "Not assessed", never 0.
- **Findings:** severity glyph; Module and Claimability merged into one Assessment column (6 to 5 columns); detail restructured into conclusion chips, security interpretation, affected resource, declared permission, policy provenance, with ID, fingerprint and raw evidence under Technical details.
- **Blast Explorer:** legend regrouped into Configuration, Declared candidate, Evaluated evidence, Validated hypothetical transition with line-style swatches; non-validated edges are dashed, validated are solid; selected edges show a validated or configuration-only chip.

## 6. Charts
No chart was added or removed. The existing risk trend only renders with two or more real scans. Chart audit remains open.

## 7. Not done (deferred, not blockers)
Findings filter bar and drawer tabs; Scan Control and Scan History redesign; Accounts and Remediation pages; a custom focus audit with a screen reader; a measured contrast report. Real AWS Architecture icons: the three added icons are simple original glyphs, not official assets.

## 8. Verdict
CONDITIONAL GO for the shipped scope. Not a GO for "Dashboard 2.0" as specified.

## 9. Product boundary (design rule)
Cloudrift is a read-only AWS exposure and entitlement investigation tool. It shows what is declared, evaluated and validated, what evidence supports it, and how complete collection was.

A UI feature belongs here only if it helps investigate and explain. These do not belong, and belong in a ticketing, IAM governance or CMDB tool instead:
- assigning owners, tickets, approvals, SLAs or due dates;
- tracking remediation status;
- generating or applying changes to AWS;
- maintaining an ownership source of truth.

Allowed context: account name, OU path and team tag, shown read-only when the scan collected them. Allowed navigation: exact evidence location (policy ARN, statement ID, action, resource) and scan-to-scan comparison. Review new UI against this rule.

Not implemented from the "daily workflow" ideas: root-cause grouping of declared IAM findings by shared policy (needs a per-policy usage view the API does not provide), and last-used activity on roles (not collected for roles).
