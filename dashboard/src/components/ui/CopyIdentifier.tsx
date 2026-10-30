import { useState } from "react";

/** Wrapping identifier with a copy button, so a long ARN is fully accessible without widening the layout. */
export function CopyIdentifier({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <span className="flex min-w-0 items-start gap-2">
      <code className="cr-ident">{value}</code>
      <button
        type="button"
        className="hs-btn-default shrink-0 px-2 py-0.5 text-[11px]"
        aria-label={`Copy ${value}`}
        onClick={() => {
          void navigator.clipboard?.writeText(value).then(() => {
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1200);
          });
        }}
      >
        {copied ? "Copied" : "Copy"}
      </button>
    </span>
  );
}
