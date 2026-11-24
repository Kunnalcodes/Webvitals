/**
 * DevSecOps Exporters & Quality Gate API Client — Phase 4
 * WebVitals
 */

import { QualityGateResponse } from '../types/reports';

const API_BASE = '/api';

export function getSarifDownloadUrl(scanId: string): string {
  return `${API_BASE}/scan/export/sarif?scanId=${encodeURIComponent(scanId)}`;
}

export function getMarkdownDownloadUrl(scanId: string): string {
  return `${API_BASE}/scan/export/markdown?scanId=${encodeURIComponent(scanId)}`;
}

export async function fetchMarkdownReport(scanId: string): Promise<string> {
  const res = await fetch(getMarkdownDownloadUrl(scanId));
  if (!res.ok) {
    throw new Error(`Failed to download Markdown report (${res.status})`);
  }
  return res.text();
}

export async function checkCiQualityGate(scanId: string, minScore = 80, score?: number): Promise<QualityGateResponse> {
  const url = `${API_BASE}/scan/gate?scanId=${encodeURIComponent(scanId)}&minScore=${minScore}${score !== undefined ? `&score=${score}` : ''}`;
  const res = await fetch(url);
  if (!res.ok && res.status !== 422) {
    throw new Error(`Quality gate check failed with status ${res.status}`);
  }
  const json = await res.json();
  return json.data || json;
}
