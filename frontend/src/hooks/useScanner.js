import { useState, useCallback, useEffect, useRef } from 'react';

const API_BASE = import.meta.env.VITE_API_BASE ?? '';

export function useScanner() {
  const [status, setStatus] = useState('idle'); // 'idle' | 'scanning' | 'done' | 'error'
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);
  const [rateLimitInfo, setRateLimitInfo] = useState(null);
  const [isRateLimited, setIsRateLimited] = useState(false);
  const [retryCountdown, setRetryCountdown] = useState(0);

  // Live Scanning Progress & Real-time Stage Thread Feed
  const [progress, setProgress] = useState(0);
  const [currentStage, setCurrentStage] = useState('');
  const [stageLogs, setStageLogs] = useState([]);
  const [scanId, setScanId] = useState(null);

  const pollIntervalRef = useRef(null);
  const wsRef = useRef(null);

  const cleanupStreams = useCallback(() => {
    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current);
      pollIntervalRef.current = null;
    }
    if (wsRef.current) {
      try {
        wsRef.current.close();
      } catch {}
      wsRef.current = null;
    }
  }, []);

  // Countdown timer when rate limited
  useEffect(() => {
    if (retryCountdown <= 0) return;
    const interval = setInterval(() => {
      setRetryCountdown((prev) => {
        if (prev <= 1) {
          setIsRateLimited(false);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, [retryCountdown]);

  // Clean up on unmount
  useEffect(() => {
    return () => {
      cleanupStreams();
    };
  }, [cleanupStreams]);

  const addLog = useCallback((stage, message, statusType = 'running') => {
    const timestamp = new Date().toLocaleTimeString();
    setStageLogs((prev) => {
      const filtered = prev.filter((p) => p.stage !== stage);
      return [...filtered, { stage, message, timestamp, status: statusType }];
    });
  }, []);

  const scan = useCallback(async (url) => {
    if (!url || !url.trim()) return;
    cleanupStreams();

    setStatus('scanning');
    setError(null);
    setReport(null);
    setIsRateLimited(false);
    setProgress(10);
    setCurrentStage('VALIDATING');
    setStageLogs([
      { stage: 'INIT', message: `Initializing perimeter security probing on ${url.trim()}...`, timestamp: new Date().toLocaleTimeString(), status: 'done' },
      { stage: 'VALIDATING', message: 'Validating hostname & anti-SSRF protections...', timestamp: new Date().toLocaleTimeString(), status: 'running' },
    ]);

    const cleanUrl = url.trim();

    try {
      // Initiate scan
      const res = await fetch(`${API_BASE}/api/scan?url=${encodeURIComponent(cleanUrl)}&sync=true`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: cleanUrl, sync: true }),
      });

      // Extract Rate Limit Headers
      const limit = res.headers.get('X-RateLimit-Limit');
      const remaining = res.headers.get('X-RateLimit-Remaining');
      const reset = res.headers.get('X-RateLimit-Reset');
      if (limit) {
        setRateLimitInfo({
          limit: parseInt(limit, 10),
          remaining: parseInt(remaining || '0', 10),
          reset: parseInt(reset || '0', 10),
        });
      }

      if (res.status === 429) {
        const data = await res.json().catch(() => ({}));
        setStatus('error');
        setIsRateLimited(true);
        const retrySecs = data.retryAfterSeconds || 60;
        setRetryCountdown(retrySecs);
        setError(`Rate limit reached: ${data.message || 'Too many scans. Please wait a moment.'}`);
        return;
      }

      const resData = await res.json();

      if (!res.ok || (resData.success === false && !resData.data)) {
        setStatus('error');
        setError(resData.error?.message || resData.message || 'Scan failed to initialize.');
        return;
      }

      // If synchronous full report returned immediately
      const extractedReport = resData.data || resData;
      if (extractedReport && (extractedReport.score !== undefined || extractedReport.channels || extractedReport.findings)) {
        setReport(extractedReport);
        setProgress(100);
        setCurrentStage('COMPLETE');
        addLog('REPORT_READY', 'Audit report synthesized & verified.', 'done');
        setStatus('done');
        return;
      }

      // If asynchronous job ID returned, connect to status poller and WebSocket
      const jobId = extractedReport.scanId;
      if (jobId) {
        setScanId(jobId);

        // Polling loop
        let attempts = 0;
        pollIntervalRef.current = setInterval(async () => {
          attempts++;
          try {
            const statusRes = await fetch(`${API_BASE}/api/scan/status?scanId=${encodeURIComponent(jobId)}`);
            if (statusRes.ok) {
              const statusJson = await statusRes.json();
              const statusData = statusJson.data || statusJson;

              if (statusData.progress) {
                setProgress(Math.max(15, statusData.progress));
              }
              if (statusData.stage) {
                setCurrentStage(statusData.stage);
                addLog(statusData.stage, statusData.message || `Executing ${statusData.stage}...`, 'running');
              }

              if (statusData.status === 'COMPLETE' || statusData.report) {
                cleanupStreams();
                setReport(statusData.report || statusData);
                setProgress(100);
                setCurrentStage('COMPLETE');
                addLog('REPORT_READY', 'All 12 security channels evaluated successfully.', 'done');
                setStatus('done');
              } else if (statusData.status === 'FAILED') {
                cleanupStreams();
                setStatus('error');
                setError(statusData.error || 'Scan pipeline encountered an unrecoverable error.');
              }
            }
          } catch (pollErr) {
            // fallback, continue polling until timeout
          }

          if (attempts > 90) {
            cleanupStreams();
            setStatus('error');
            setError('Scan timed out after 45 seconds.');
          }
        }, 500);
      }
    } catch (err) {
      cleanupStreams();
      setStatus('error');
      setError('Could not connect to scanner backend. Ensure the server is running.');
    }
  }, [cleanupStreams, addLog]);

  const reset = useCallback(() => {
    cleanupStreams();
    setStatus('idle');
    setReport(null);
    setError(null);
    setIsRateLimited(false);
    setProgress(0);
    setCurrentStage('');
    setStageLogs([]);
    setScanId(null);
  }, [cleanupStreams]);

  return {
    status,
    report,
    error,
    isRateLimited,
    retryCountdown,
    rateLimitInfo,
    progress,
    currentStage,
    stageLogs,
    scanId,
    scan,
    reset,
  };
}

export function useScanHistory() {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);

  const fetchHistory = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/history`);
      if (res.ok) {
        const json = await res.json();
        const list = json.data || json || [];
        setHistory(Array.isArray(list) ? list : []);
      }
    } catch {
      // silently fallback
    } finally {
      setLoading(false);
    }
  }, []);

  return { history, loading, fetchHistory };
}

export function useDomainTrend() {
  const [trendData, setTrendData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [selectedDomain, setSelectedDomain] = useState('github.com');

  const fetchTrend = useCallback(async (domain) => {
    setLoading(true);
    try {
      const query = domain ? `?domain=${encodeURIComponent(domain)}` : '';
      const res = await fetch(`${API_BASE}/api/history/trend${query}`);
      if (res.ok) {
        const json = await res.json();
        const data = json.data || json;
        setTrendData(data);
        if (data.domain) setSelectedDomain(data.domain);
      }
    } catch {
      // fallback
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchTrend(selectedDomain);
  }, [fetchTrend, selectedDomain]);

  return { trendData, loading, selectedDomain, setSelectedDomain, fetchTrend };
}

export function useObservatoryBenchmark() {
  const [benchmark, setBenchmark] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchBenchmark = useCallback(async (url) => {
    if (!url) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/benchmark?url=${encodeURIComponent(url.trim())}`);
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.message || `HTTP ${res.status}`);
      }
      const json = await res.json();
      const data = json.data || json;
      if (json.error && json.message) {
        setError(json.message);
      } else {
        setBenchmark(data);
      }
    } catch (err) {
      setError(err.message || 'Failed to fetch benchmark comparison.');
    } finally {
      setLoading(false);
    }
  }, []);

  return { benchmark, setBenchmark, loading, error, fetchBenchmark };
}

export function useSecurityShieldStatus() {
  const [status, setStatus] = useState(null);

  useEffect(() => {
    async function checkStatus() {
      try {
        const res = await fetch(`${API_BASE}/api/security-status`);
        if (res.ok) {
          const json = await res.json();
          setStatus(json.data || json);
        }
      } catch {
        // fallback
      }
    }
    checkStatus();
  }, []);

  return status;
}
