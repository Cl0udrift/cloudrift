# Dashboard UX QA

Real browser (built-in pane, vite dev server against `cloudrift dashboard` on stored scans). Not exercised: Playwright automation, screen reader, contrast measurement.

| Page | Viewport / theme | Scenario (scan) | Result |
|---|---|---|---|
| Identities | 1440 dark | Declared S3 role (`b4-declared`, synthetic) | Pass: ladder, chips and ARN copy render; list shows name and ARN |
| Inventory | 1280 dark | Partial regional collectors (`20261013-032650`) | Pass after fix: statuses map correctly; 17 not-enabled Regions collapsed |
| Inventory | 390 | Empty scan (`regions-coverage`) | Pass: no horizontal overflow (scrollWidth equals clientWidth); sidebar no longer overlaps |
| Findings | 390 | Synthetic one finding | Pass: no overflow; drawer opens |
| Overview | 1280 dark | Partial collection | Pass: snapshot strip shows 21 resources, 10 roles, Partial coverage |
| Findings | 1280 dark | Declared exposure, expanded (`b4-declared`) | Pass: five columns; detail shows conclusion chips, interpretation, resource, permission, provenance; older scans show "not recorded" |
| Blast Explorer | 1280 dark | Finding with Neo4j off (`demo-ciem-chain`) | Legend pass (four semantic groups). 3D graph and dashed-edge styling NOT visually verified: no Neo4j projection available |
| Shell | 1280 | Scan list loading | Defect found and fixed: topbar showed "Live" before the scan list loaded; now "Origin unknown" |
| All | light theme | not verified; app theme toggle is separate from emulation | Not verified |
| Tablet 768, loading/error states, Blast Explorer, Scan Control | | | Not tested |

Defect found and fixed in QA: `CollectionChip` initially rendered `completed` as Unknown (wrong vocabulary). Fixed against the Go API values.

## Regressions
- `go test ./internal/api/... ./internal/ciem/...`: pass.
- `tsc --noEmit`, `npm run build`, `vitest run` (11 tests): pass. The JS bundle is 2.28 MB (618 KB gzip), with the existing chunk warning. No bundle comparison was measured.
- No Go engine code or API contracts were changed in this cycle.
