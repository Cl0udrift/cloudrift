import { Link } from "react-router-dom";
import type { LossEstimate } from "../../api/types";
import { formatMoneyRange } from "../../lib/money";

/**
 * An optional planning estimate: the organization's own values for what a breach costs and how likely it is, applied
 * to what Cloudrift can see. It is shown folded and only when those values were entered, because it rests entirely
 * on assumptions. The measured figures (savings, spend within reach) come first on the page.
 */
export function LossPanel({ loss }: { loss?: LossEstimate }) {
  if (!loss || !loss.configured || loss.items.length === 0) return null;
  const cur = loss.currency || "USD";
  return (
    <details className="hs-card p-4" aria-label="Planning estimate">
      <summary className="hs-focus-ring cursor-pointer rounded text-sm font-medium text-slate-800 dark:text-slate-100">
        Planning estimate from your own assumptions: {formatMoneyRange(loss.low, loss.high, cur)} a year
      </summary>
      <p className="cr-helper mt-2">
        Chance of use in a year times what it would cost, both from <Link className="underline" to="/business">Business settings</Link>. This is a planning aid, not a measurement.
        {loss.not_estimated > 0 ? ` ${loss.not_estimated} ${loss.not_estimated === 1 ? "item" : "items"} could not be valued and ${loss.not_estimated === 1 ? "is" : "are"} left out.` : ""}
      </p>
      <ul className="mt-2 space-y-1 text-sm text-slate-700 dark:text-slate-300">
        {loss.items.map((i) => (
          <li key={i.subject}>
            <strong className="font-semibold">{i.subject}</strong> reaches {i.why}: {formatMoneyRange(i.low, i.high, cur)} a year.
          </li>
        ))}
      </ul>
    </details>
  );
}
