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

export async function checkCiQualityGate(scanId: string, minScore = 80): Promise<QualityGateResponse> {
  const res = await fetch(`${API_BASE}/scan/gate?scanId=${encodeURIComponent(scanId)}&minScore=${minScore}`);
  const data = await res.json();
  return data;
}
