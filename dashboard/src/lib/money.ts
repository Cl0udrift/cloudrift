/** A figure with its currency. A three-letter code uses the browser's currency format; anything else is a prefix. */
export function formatMoney(value: number, currency = "USD"): string {
  const compact = Math.abs(value) >= 1_000;
  // Below a thousand every figure keeps its cents, so a list of them lines up: $0.50 must not read as $1.
  const cents = Math.abs(value) < 1_000 ? 2 : 1;
  try {
    if (/^[A-Za-z]{3}$/.test(currency)) {
      return new Intl.NumberFormat(undefined, { style: "currency", currency: currency.toUpperCase(), notation: compact ? "compact" : "standard", minimumFractionDigits: cents === 2 ? 2 : 0, maximumFractionDigits: cents }).format(value);
    }
  } catch {
    // fall through to the plain prefix
  }
  const n = new Intl.NumberFormat(undefined, { notation: compact ? "compact" : "standard", minimumFractionDigits: cents === 2 ? 2 : 0, maximumFractionDigits: cents }).format(value);
  return `${currency}${n}`;
}

export function formatMoneyRange(low: number, high: number, currency = "USD"): string {
  return low === high ? formatMoney(low, currency) : `${formatMoney(low, currency)} to ${formatMoney(high, currency)}`;
}
