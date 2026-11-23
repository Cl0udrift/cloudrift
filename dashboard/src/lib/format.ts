/** A dollar figure, or a dash for zero: a modeled cost of $0 means no figure exists, not that there is no risk. */
export function formatUsd(n: number): string {
  if (n === 0) return "—";
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 2,
    maximumFractionDigits: 2
  }).format(n);
}

export function formatCount(n: number): string {
  return new Intl.NumberFormat("en-US").format(n);
}

/** Prefer hostname; otherwise shorten long ARNs for table display. */
export function displayTarget(hostname: string | undefined, affectedArn: string): string {
  const h = hostname?.trim();
  if (h) {
    return h;
  }
  return shortenArn(affectedArn);
}

export function shortenArn(arn: string, head = 28, tail = 18): string {
  if (!arn) {
    return "—";
  }
  if (arn.length <= head + tail + 1) {
    return arn;
  }
  return `${arn.slice(0, head)}…${arn.slice(-tail)}`;
}
