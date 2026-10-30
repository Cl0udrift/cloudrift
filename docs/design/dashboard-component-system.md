# Dashboard component system

One layer: Tailwind plus the existing `hs-*` and `cr-*` classes in `dashboard/src/styles.css`. No UI framework was added.

## Tokens
`--cr-{ok,warn,bad,unk,info,hyp}-{fg,bg,bd}` for light and dark, applied via `.cr-tone-*`. `--cr-sidebar-w`, `--cr-topbar-h`, `--cr-accent`.

## Components (`src/components/ui`, `src/components`)
| Component | Purpose | Rule |
|---|---|---|
| `StateChip` | glyph + label + tone | color never the only cue |
| `AuthorizationChip` | iamauth state | default is "Not evaluated" |
| `CollectionChip` | collection state | vocabulary: `completed`, `succeeded`, `collected`, `partial`, `failed`, `not_recorded`, `REGION_*`; anything else shows Unknown with the raw value in the tooltip |
| `EvidenceChip` | candidate state | Declared is not evaluated access |
| `AttackStatusChip` | validated / hypothetical / configuration | |
| `MetricCard` | label, value, context, drill-down | `null` renders "Not assessed", never 0 |
| `SectionHeader` | section title and hint | |
| `CopyIdentifier` | wrapping ARN plus copy | |
| `ScanContextBar` | topbar scope | only fields the scan list API returns |
| `ScanSnapshotStrip` | overview scope | existing endpoints only |

The Go API status vocabulary is the source of truth for `CollectionChip`. A wrong mapping was caught in browser QA and fixed: `completed` had rendered as Unknown.
