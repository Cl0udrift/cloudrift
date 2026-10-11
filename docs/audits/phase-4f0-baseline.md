# Phase 4F.0 baseline

Captured before the audit fixes, then rechecked after them. No staging, commit, reset, or push was performed.

## Git

| Item | Value |
|---|---|
| Branch | `main`, tracking `origin/main`, **behind 1** |
| HEAD | `1659ff13bda0ea801b010a5e1cb976f4278adb03` |
| HEAD subject | Update docs.html |
| HEAD author | Zero (Arif), 2026-10-07 13:27:21 -0700 |
| Staged changes | none |
| Working tree | unstaged modifications plus untracked source |

The local branch is not even with `origin/main`. A later commit cannot be pushed as a fast-forward until that remote commit is reconciled. This audit did not pull or rebase.

## Toolchain

- Go `go1.24.6` (`go 1.24.0` in `go.mod`, toolchain `go1.24.6`)
- Node `v23.7.0`, npm `11.1.0`
- Dashboard `cloudrift-dashboard` `0.1.0`
- Scripts: `vite`, `tsc -b && vite build`, `vitest`, `vitest run`

## What changed, excluding generated junk

Measured after the audit fixes, still excluding `dashboard/dist`, `.DS_Store`, and `dashboard/tsconfig.tsbuildinfo`.

- Untracked source: **85 files, 18,221 lines**
- Tracked edits: **62 files, +3,048 / −571**
- Authored additions: **21,269 lines**
- Generated dashboard bundles are a separate dirty set (`index-ZBkW5Chx.js` deleted, `index-DTihiYNg.js` and matching CSS/chunk files untracked). They are build output.

Class totals are in `phase-4f0-code-size.md`.

## Secrets and unrelated dirt

- `cloudrift.toml` is modified and contains a local Neo4j password. It was **not** copied into the backup and must not be committed.
- `.DS_Store` files are modified or untracked. Exclude them.
- No `.env` file is present. `*.env` is gitignored.
- No AWS access key material was found in Go, TypeScript, YAML, or Markdown.
- `go.mod` / `go.sum` bump AWS SDK modules and add EC2, ECS, EKS, and Lambda clients. That belongs with the collector change.

## Recovery copy

Non-destructive backup, secrets excluded:

`/Users/arif/Desktop/cloudrift-phase4f0-backup-20261011T122007`

- `tracked.diff` sha256 `e412d219c76a628f1705ca36a997ec4f509f9ab72c93b5884107e81ce810ff84`
- `untracked-source.tgz` sha256 `90be91e8bbfdbcc922414b56da979f8b536e8f0916bbf356e8b82e6c6e9157c7`

The archive was taken before the small audit edits to inventory identity, the IAM policy files, and the benchmark note. Those edits remain in the working tree.

## Dirty-state risks

- Mixing `cloudrift.toml`, `.DS_Store`, and `dashboard/dist` into a product commit.
- Treating the remote-ahead commit as already merged.
- Assuming every untracked file is disposable. The untracked Go, TypeScript, and docs are the CIEM and inventory implementation.
