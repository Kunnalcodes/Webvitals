/**
 * AI & Remediation API Client — Phase 4
 * WebVitals
 */

import { FindingExplanation, RemediationPlaybook, ExecutiveSummaryReport, ChatResponse, AudienceType } from '../types/ai';

const API_BASE = '/api';

export async function fetchFindingExplanation(
  scanId: string,
  findingId: string,
  audience: AudienceType = 'developer'
): Promise<FindingExplanation> {
  const res = await fetch(`${API_BASE}/ai/explain`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scanId, findingId, audience }),
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.error || `Failed to fetch explanation (${res.status})`);
  }

  return res.json();
}

export async function fetchRemediationPlaybook(
  scanId: string,
  findingId: string,
  stack?: string
): Promise<RemediationPlaybook> {
  const res = await fetch(`${API_BASE}/ai/remediate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scanId, findingId, stack }),
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.error || `Failed to fetch remediation (${res.status})`);
  }

  return res.json();
}

export async function fetchExecutiveSummary(scanId: string): Promise<ExecutiveSummaryReport> {
  const res = await fetch(`${API_BASE}/ai/executive-summary?scanId=${encodeURIComponent(scanId)}`);

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.error || `Failed to fetch executive summary (${res.status})`);
  }

  return res.json();
}

export async function sendSecurityChatMessage(
  scanId: string,
  message: string,
  conversationId?: string
): Promise<ChatResponse> {
  const res = await fetch(`${API_BASE}/ai/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ scanId, message, conversationId }),
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.error || `Failed to send chat message (${res.status})`);
  }

  return res.json();
}
