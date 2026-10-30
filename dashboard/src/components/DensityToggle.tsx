import { useEffect, useState } from "react";

/** Comfortable / Compact table rows. Stored per browser; applies a class on <html>. */
export function DensityToggle() {
  const [compact, setCompact] = useState(() => {
    try {
      return window.localStorage.getItem("cloudrift.density") === "compact";
    } catch {
      return false;
    }
  });
  useEffect(() => {
    document.documentElement.classList.toggle("cr-compact", compact);
    try {
      window.localStorage.setItem("cloudrift.density", compact ? "compact" : "comfortable");
    } catch {
      /* ignore */
    }
  }, [compact]);
  return (
    <button type="button" className="hs-btn-default hidden shrink-0 px-2 py-1 text-xs sm:inline-flex" aria-pressed={compact} onClick={() => setCompact((v) => !v)} title={compact ? "Compact rows (click for comfortable)" : "Comfortable rows (click for compact)"} aria-label={compact ? "Table density: compact" : "Table density: comfortable"}>
      <span aria-hidden="true">{compact ? "☰" : "≣"}</span>
    </button>
  );
}
