import { useState, useEffect } from "react";

/**
 * Debounce a value by `delay` milliseconds.
 *
 * Usage:
 *   const [raw, setRaw] = useState("");
 *   const debounced = useDebounce(raw, 300);
 *
 * `debounced` only updates 300ms after `raw` stops changing.
 */
export function useDebounce<T>(value: T, delay: number): T {
  const [debounced, setDebounced] = useState(value);

  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);

  return debounced;
}
