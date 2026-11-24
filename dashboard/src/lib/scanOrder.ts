import type { ScanListItem } from "../api/types";

const sameAccounts = (a: string[] = [], b: string[] = []) => [...a].sort().join(",") === [...b].sort().join(",");

/**
 * The baseline for a diff: the newest earlier scan of the same accounts. Scans arrive newest first. A scan of another
 * account is not a baseline, because every finding would look gone in one and new in the other.
 */
export function getPreviousScanIdForDiff(
  scansNewestFirst: ScanListItem[],
  selectedScanId: string | null
): string | null {
  if (!selectedScanId || scansNewestFirst.length < 2) {
    return null;
  }
  const idx = scansNewestFirst.findIndex((s) => s.scan_id === selectedScanId);
  if (idx < 0) {
    return null;
  }
  const current = scansNewestFirst[idx];
  const older = scansNewestFirst.slice(idx + 1).find((s) => sameAccounts(s.account_ids, current.account_ids));
  return older?.scan_id ?? null;
}

/** Other scans that can be picked as a baseline, scans of the same accounts first. */
export function baselineChoices(scansNewestFirst: ScanListItem[], selectedScanId: string | null): { id: string; sameAccounts: boolean }[] {
  const current = scansNewestFirst.find((s) => s.scan_id === selectedScanId);
  const rows = scansNewestFirst.filter((s) => s.scan_id !== selectedScanId).map((s) => ({ id: s.scan_id, sameAccounts: sameAccounts(s.account_ids, current?.account_ids) }));
  return [...rows.filter((r) => r.sameAccounts), ...rows.filter((r) => !r.sameAccounts)];
}

/** The scans that covered the same accounts as the selected one, newest first. Other accounts do not belong on its trend. */
export function scansOfSameAccounts(scansNewestFirst: ScanListItem[], selectedScanId: string | null): ScanListItem[] {
  const current = scansNewestFirst.find((s) => s.scan_id === selectedScanId);
  return current ? scansNewestFirst.filter((s) => sameAccounts(s.account_ids, current.account_ids)) : scansNewestFirst;
}
