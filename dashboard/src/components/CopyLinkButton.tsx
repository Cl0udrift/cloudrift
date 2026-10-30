import { useState } from "react";

/** Copies the current page URL, including scan_id and all filter state held in the query string. */
export function CopyLinkButton() {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(window.location.href);
      setState("copied");
    } catch {
      // Clipboard API can be denied (permissions, embedded frames). Fall back to a selection copy.
      const area = document.createElement("textarea");
      area.value = window.location.href;
      area.setAttribute("readonly", "");
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      let ok = false;
      try {
        ok = document.execCommand("copy");
      } catch {
        ok = false;
      }
      document.body.removeChild(area);
      setState(ok ? "copied" : "failed");
    }
    window.setTimeout(() => setState("idle"), 1500);
  };
  return (
    <button type="button" className="hs-btn-default shrink-0 px-2 py-1 text-xs" onClick={copy} title="Copy a link to this exact view">
      <span aria-live="polite">{state === "copied" ? "Link copied" : state === "failed" ? "Copy failed" : "Copy link"}</span>
    </button>
  );
}
