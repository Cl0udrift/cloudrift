import { IDLE_DAYS } from "./lastUsedConstants";

/** Text for IAM-reported role activity. Missing or unrecorded evidence is never described as "unused". */
export function lastUsedLabel(status?: string, days?: number, region?: string): { text: string; idle: boolean } {
  const where = region ? ` (${region})` : "";
  switch (status) {
    case "used":
      return { text: days === undefined ? `Used${where}` : days === 0 ? `Used today${where}` : `Last used ${days} days ago${where}`, idle: days !== undefined && days >= IDLE_DAYS };
    case "not_used_in_tracking_window":
      return { text: "No use in IAM tracking window (about 400 days)", idle: true };
    case "not_reported":
      return { text: "IAM did not report last use", idle: false };
    case "not_collected":
      return { text: "Last use not collected for this role", idle: false };
    default:
      return { text: "Last use not recorded in this scan", idle: false };
  }
}
