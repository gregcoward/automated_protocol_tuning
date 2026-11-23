import { useState, useCallback, useRef, useEffect } from 'react';

export function useAsync(fn) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  // Keep a ref so run() always calls the latest fn without stale closures
  const fnRef = useRef(fn);
  useEffect(() => { fnRef.current = fn; }, [fn]);

  const run = useCallback(async (...args) => {
    setLoading(true);
    setError(null);
    try {
      const result = await fnRef.current(...args);
      return result;
    } catch (e) {
      setError(e.message || String(e));
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  return { run, loading, error, clearError: () => setError(null) };
}
