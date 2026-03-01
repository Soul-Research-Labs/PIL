/**
 * Generic polling hook for periodic data fetching.
 *
 * Supports configurable intervals, conditional pausing,
 * and automatic cleanup on unmount.
 */

import { useCallback, useEffect, useRef, useState } from "react";

export interface UsePollingOptions<T> {
  /** Async function to fetch data */
  fetcher: () => Promise<T>;
  /** Polling interval in ms (default 5000) */
  interval?: number;
  /** Start polling immediately (default true) */
  enabled?: boolean;
  /** Condition to stop polling (receives latest data) */
  stopWhen?: (data: T) => boolean;
  /** Callback when new data arrives */
  onData?: (data: T) => void;
  /** Callback on error */
  onError?: (error: Error) => void;
}

export interface UsePollingReturn<T> {
  data: T | null;
  isPolling: boolean;
  error: Error | null;
  start: () => void;
  stop: () => void;
  refetch: () => Promise<void>;
}

export function usePolling<T>({
  fetcher,
  interval = 5000,
  enabled = true,
  stopWhen,
  onData,
  onError,
}: UsePollingOptions<T>): UsePollingReturn<T> {
  const [data, setData] = useState<T | null>(null);
  const [isPolling, setIsPolling] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const fetcherRef = useRef(fetcher);
  const stopWhenRef = useRef(stopWhen);

  // Keep refs current
  useEffect(() => {
    fetcherRef.current = fetcher;
  }, [fetcher]);

  useEffect(() => {
    stopWhenRef.current = stopWhen;
  }, [stopWhen]);

  const fetchOnce = useCallback(async () => {
    try {
      const result = await fetcherRef.current();
      setData(result);
      setError(null);
      onData?.(result);

      if (stopWhenRef.current?.(result)) {
        stop();
      }
    } catch (err) {
      const e = err instanceof Error ? err : new Error(String(err));
      setError(e);
      onError?.(e);
    }
  }, [onData, onError]);

  const start = useCallback(() => {
    if (intervalRef.current) return;
    setIsPolling(true);
    fetchOnce(); // immediate fetch
    intervalRef.current = setInterval(fetchOnce, interval);
  }, [fetchOnce, interval]);

  const stop = useCallback(() => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    setIsPolling(false);
  }, []);

  // Auto-start if enabled
  useEffect(() => {
    if (enabled) {
      start();
    }
    return () => stop();
  }, [enabled, start, stop]);

  return {
    data,
    isPolling,
    error,
    start,
    stop,
    refetch: fetchOnce,
  };
}
