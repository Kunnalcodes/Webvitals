import { useState, useCallback } from 'react';

const API_BASE = import.meta.env.VITE_API_BASE ?? '';

export function useTechStack() {
  const [status, setStatus] = useState('idle'); // 'idle' | 'detecting' | 'done' | 'error'
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);

  const detect = useCallback(async (url) => {
    if (!url || !url.trim()) return;
    setStatus('detecting');
    setError(null);
    setReport(null);

    const cleanUrl = url.trim();
    try {
      const res = await fetch(`${API_BASE}/api/techstack?url=${encodeURIComponent(cleanUrl)}`);

      if (!res.ok && res.status !== 200) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.message || `Server responded with HTTP ${res.status}`);
      }

      const json = await res.json();
      if (json.error && json.message) {
        setStatus('error');
        setError(json.message);
      } else {
        const extracted = json.data !== undefined ? json.data : json;
        setReport(extracted);
        setStatus('done');
      }
    } catch (err) {
      setStatus('error');
      setError(err.message || 'Could not connect to Tech Stack detector backend.');
    }
  }, []);

  const reset = useCallback(() => {
    setStatus('idle');
    setReport(null);
    setError(null);
  }, []);

  return {
    status,
    report,
    error,
    detect,
    reset,
  };
}
