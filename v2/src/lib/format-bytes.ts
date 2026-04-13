/**
 * formatBytes — converts a raw byte count to a human-readable binary string.
 *
 * Uses binary prefixes (KiB, MiB, GiB, TiB) — appropriate for file sizes
 * where 1 KiB = 1024 bytes.
 *
 * Examples:
 *   formatBytes(0)            → "0 B"
 *   formatBytes(1023)         → "1023 B"
 *   formatBytes(1024)         → "1.00 KiB"
 *   formatBytes(1536)         → "1.50 KiB"
 *   formatBytes(1048576)      → "1.00 MiB"
 *   formatBytes(1073741824)   → "1.00 GiB"
 *
 * No external dependencies.
 */

const UNITS = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"] as const;

export function formatBytes(bytes: number): string {
  if (!isFinite(bytes) || bytes < 0) return "? B";
  if (bytes === 0) return "0 B";

  const i = Math.min(
    Math.floor(Math.log2(bytes) / 10),
    UNITS.length - 1,
  );

  if (i === 0) {
    return `${bytes} B`;
  }

  const value = bytes / Math.pow(1024, i);
  return `${value.toFixed(2)} ${UNITS[i]}`;
}
