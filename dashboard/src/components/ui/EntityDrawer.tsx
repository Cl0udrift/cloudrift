import { useEffect, useRef } from "react";
import type { ReactNode } from "react";

/**
 * Right-hand detail drawer. The list behind it stays visible and keeps its scroll position.
 * Escape and the close button dismiss it; focus moves to the panel on open.
 */
export function EntityDrawer({ title, onClose, children }: { title: string; onClose: () => void; children: ReactNode }) {
  const ref = useRef<HTMLElement>(null);
  useEffect(() => {
    ref.current?.focus();
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <aside
      ref={ref}
      tabIndex={-1}
      role="complementary"
      aria-label={title}
      className="fixed inset-y-0 right-0 z-30 flex w-full max-w-xl flex-col border-l border-slate-200 bg-white shadow-xl outline-none dark:border-slate-700 dark:bg-slate-900"
    >
      <header className="flex h-[var(--cr-topbar-h)] shrink-0 items-center justify-between gap-3 border-b border-slate-200 px-4 dark:border-slate-700">
        <h2 className="cr-section-title truncate">{title}</h2>
        <button type="button" className="hs-btn-default px-2 py-1 text-xs" onClick={onClose} aria-label="Close detail">
          Close ✕
        </button>
      </header>
      <div className="min-h-0 flex-1 overflow-y-auto p-4">{children}</div>
    </aside>
  );
}
