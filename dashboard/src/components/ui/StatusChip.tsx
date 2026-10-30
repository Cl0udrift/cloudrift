import type { ReactNode } from "react";

export type Tone = "ok" | "warn" | "bad" | "unk" | "info" | "hyp";

/** One state chip. Tone supplies color; glyph and label carry the meaning without color. */
export function StateChip({ tone, glyph, label, title }: { tone: Tone; glyph: string; label: string; title?: string }) {
  return (
    <span className={`cr-chip-state cr-tone-${tone}`} title={title}>
      <span aria-hidden="true">{glyph}</span>
      {label}
    </span>
  );
}

const authorization: Record<string, [Tone, string, string]> = {
  VALIDATED_ALLOWED: ["bad", "✓", "Validated allowed"],
  VALIDATED_DENIED: ["ok", "✕", "Validated denied"],
  CONDITIONAL: ["warn", "◐", "Conditional"],
  UNKNOWN: ["unk", "?", "Unknown"],
  UNSUPPORTED: ["unk", "⊘", "Unsupported"],
  not_assessed: ["unk", "–", "Not evaluated"]
};

/** Evaluated authorization from iamauth.Evaluate. A declared candidate is never shown as validated. */
export function AuthorizationChip({ status }: { status: string }) {
  const [tone, glyph, label] = authorization[status] ?? authorization.not_assessed;
  return <StateChip tone={tone} glyph={glyph} label={label} />;
}

// Vocabulary emitted by the Go API (inventory collection, service coverage, region state).
const collection: Record<string, [Tone, string, string]> = {
  completed: ["ok", "✓", "Completed"],
  succeeded: ["ok", "✓", "Succeeded"],
  collected: ["ok", "✓", "Collected"],
  region_scan_succeeded: ["ok", "✓", "Succeeded"],
  partial: ["warn", "◐", "Partial"],
  region_scan_partial: ["warn", "◐", "Partial"],
  failed: ["bad", "!", "Failed"],
  region_scan_failed: ["bad", "!", "Failed"],
  region_discovery_failed: ["bad", "!", "Discovery failed"],
  not_recorded: ["unk", "–", "Not recorded"],
  not_applicable: ["unk", "∅", "Not applicable"],
  region_not_enabled: ["unk", "∅", "Not enabled"],
  excluded: ["unk", "∅", "Excluded"],
  region_opt_in_unknown: ["unk", "?", "Opt-in unknown"],
  unknown: ["unk", "?", "Unknown"]
};

/** Collection status. Anything unrecognised is shown as Unknown, never as Succeeded. */
export function CollectionChip({ status }: { status?: string }) {
  const raw = (status ?? "").toLowerCase();
  const [tone, glyph, label] = collection[raw] ?? ["unk", "?", "Unknown"];
  return <StateChip tone={tone} glyph={glyph} label={label} title={collection[raw] ? undefined : `Unrecognised status: ${status || "empty"}`} />;
}

const attack: Record<string, [Tone, string, string]> = {
  validated: ["bad", "→", "Validated transition"],
  hypothetical: ["hyp", "≈", "Hypothetical impact"],
  configuration: ["info", "·", "Configuration only"]
};

export function AttackStatusChip({ kind }: { kind: keyof typeof attack }) {
  const [tone, glyph, label] = attack[kind];
  return <StateChip tone={tone} glyph={glyph} label={label} />;
}

const evidence: Record<string, [Tone, string, string]> = {
  DECLARED: ["warn", "◆", "Declared"],
  CONDITIONAL: ["warn", "◐", "Declared, conditional"],
  UNSUPPORTED_CONSTRUCT: ["unk", "⊘", "Unsupported construct"],
  DENY_EVIDENCE: ["info", "✕", "Deny evidence"],
  UNKNOWN: ["unk", "?", "Insufficient evidence"]
};

/** Candidate evidence state from the shared extractor. Declared is not evaluated access. */
export function EvidenceChip({ state }: { state: string }) {
  const [tone, glyph, label] = evidence[state] ?? evidence.UNKNOWN;
  return <StateChip tone={tone} glyph={glyph} label={label} />;
}

export function SectionHeader({ title, hint, action }: { title: string; hint?: string; action?: ReactNode }) {
  return (
    <div className="flex items-end justify-between gap-3">
      <div className="min-w-0">
        <h3 className="cr-section-title">{title}</h3>
        {hint ? <p className="cr-helper mt-0.5">{hint}</p> : null}
      </div>
      {action}
    </div>
  );
}
