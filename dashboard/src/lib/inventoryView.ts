// The API sends service coverage in upper case (COLLECTED, NOT_RECORDED) and collection status in lower case.
export const cov = (card: { coverage: string }) => card.coverage.toLowerCase();

export const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;
