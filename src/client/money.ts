/** Currency-safe display helpers for provider prices and payment records. */

export function formatMoney(
  amountMinor: number,
  currency: string,
  exponent: number,
  locale?: string,
): string {
  if (!Number.isSafeInteger(amountMinor))
    throw new Error("Amount must be a safe integer");
  if (!Number.isInteger(exponent) || exponent < 0 || exponent > 4) {
    throw new Error("Currency exponent must be between 0 and 4");
  }
  return new Intl.NumberFormat(locale, {
    style: "currency",
    currency,
    minimumFractionDigits: exponent,
    maximumFractionDigits: exponent,
  }).format(amountMinor / 10 ** exponent);
}

export function parseMajorAmount(value: string, exponent: number): number {
  if (!Number.isInteger(exponent) || exponent < 0 || exponent > 4) {
    throw new Error("Currency exponent must be between 0 and 4");
  }

  const normalized = value.trim();
  if (!/^\d+(?:\.\d+)?$/.test(normalized)) {
    throw new Error(
      "Enter a positive amount using digits and an optional decimal point",
    );
  }

  const [whole, fraction = ""] = normalized.split(".");
  if (fraction.length > exponent) {
    throw new Error(`This currency supports ${exponent} decimal places`);
  }

  const minor =
    BigInt(whole) * 10n ** BigInt(exponent) +
    BigInt(fraction.padEnd(exponent, "0") || "0");
  if (minor > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("Amount is too large");
  }
  return Number(minor);
}
