import type { UnknownCaller, WhoCanResponse } from "../api/types";

/** A cell that starts with = + - @ is read as a formula by spreadsheets; a leading apostrophe makes it text. */
function cell(value: string): string {
  const safe = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
  return /[",\n\r]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

const HEADER = ["result", "kind", "name", "arn", "account", "reason", "path"];

/** CSV of one who-can answer: callers that can, then callers that could not be decided (result "unknown"). */
export function whoCanCsv(data: WhoCanResponse, targetName: string): string {
  const rows: string[][] = [HEADER];
  for (const c of data.callers) {
    const path = (c.paths ?? []).map((p) => p.steps.map((s) => s.label).join(" > ")).join(" | ");
    rows.push([c.status, c.kind, c.name, c.arn, c.account_id, c.reason_text || c.reason, path]);
  }
  for (const u of data.unknown_callers as UnknownCaller[]) {
    rows.push(["unknown", u.kind, u.name, u.arn, u.account_id, u.reason_text || u.reason, ""]);
  }
  const meta = `# who can ${data.action} on ${targetName}; evaluated ${data.evaluated}; stored policies only, not observed use`;
  return [cell(meta), ...rows.map((r) => r.map(cell).join(","))].join("\n") + "\n";
}
