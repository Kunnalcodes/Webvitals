import { useState, useCallback } from 'react';

const API_BASE = import.meta.env.VITE_API_BASE ?? '';

export function useSeoScanner() {
  const [status, setStatus] = useState('idle'); // 'idle' | 'auditing' | 'done' | 'error'
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);

  const audit = useCallback(async (url) => {
    if (!url || !url.trim()) return;
    setStatus('auditing');
    setError(null);
    setReport(null);

    const cleanUrl = url.trim();

    try {
      let res;
      try {
        res = await fetch(`${API_BASE}/api/seo/analyze`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: cleanUrl }),
        });
      } catch {
        res = await fetch(`${API_BASE}/api/seo/analyze?url=${encodeURIComponent(cleanUrl)}`);
      }

      const json = await res.json();

      if (!res.ok || (json.success === false && !json.data)) {
        setStatus('error');
        setError(json.error?.message || json.message || 'SEO audit failed.');
        return;
      }

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
      setError(err.message || 'Could not connect to SEO analyzer backend.');
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
    audit,
    reset,
  };
}

export function useSeoHistory() {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);

  const fetchSeoHistory = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/seo/history`);
      if (res.ok) {
        const json = await res.json();
        const data = json.data || json || [];
        setHistory(Array.isArray(data) ? data : []);
      }
    } catch {
      // silently fallback
    } finally {
      setLoading(false);
    }
  }, []);

  return { history, loading, fetchSeoHistory };
}
