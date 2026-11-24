import { useState, useCallback } from 'react';

/**
 * Custom React hook for running Competitive Intelligence scans.
 */
export function useCompetitiveScanner() {
  const [status, setStatus] = useState('idle'); // 'idle' | 'scanning' | 'done' | 'error'
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);
  const [progress, setProgress] = useState({ stage: 'QUEUED', percent: 0, message: '' });

  const compare = useCallback(async (primaryUrl, competitorUrl, options = {}) => {
    setStatus('scanning');
    setError(null);
    setProgress({ stage: 'INITIALIZING', percent: 5, message: 'Validating domains and enforcing security shields...' });

    try {
      const res = await fetch('/api/competitive/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          primaryUrl,
          competitorUrl,
          ...options,
        }),
      });

      const data = await res.json();

      if (!res.ok || !data.success) {
        throw new Error(data.message || data.error?.message || 'Competitive intelligence scan failed');
      }

      setReport(data.data);
      setStatus('done');
      setProgress({ stage: 'COMPLETE', percent: 100, message: 'Scan completed successfully.' });
      return data.data;
    } catch (err) {
      setError(err.message);
      setStatus('error');
      setProgress({ stage: 'FAILED', percent: 0, message: err.message });
      throw err;
    }
  }, []);

  const reset = useCallback(() => {
    setStatus('idle');
    setReport(null);
    setError(null);
    setProgress({ stage: 'QUEUED', percent: 0, message: '' });
  }, []);

  return {
    status,
    report,
    error,
    progress,
    compare,
    reset,
    setReport,
  };
}
