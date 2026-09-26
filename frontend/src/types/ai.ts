/**
 * AI Context, Explanation & Remediation Types — Phase 4
 * WebVitals
 */

import { FindingStatus, SeverityLevel } from './findings';

export type AudienceType = 'developer' | 'executive';

export interface FindingExplanation {
  findingId: string;
  audience: AudienceType;
  title: string;
  summary: string;
  whyItMatters: string;
  attackScenario: string;
  whatThisProves: string;
  whatThisDoesNotProve: string;
  remediationGuidance: string;
  validationSteps: string;
  limitations: string[];
  isAiGenerated: boolean;
  fallbackReason?: string;
}

export type RemediationApplicability = 'DIRECT' | 'LIKELY' | 'GENERIC' | 'INSUFFICIENT_EVIDENCE';

export interface RemediationPlaybook {
  findingId: string;
  stack: string;
  confidence: string;
  applicability: RemediationApplicability;
  file?: string;
  snippet: string;
  explanation: string;
  prerequisites?: string[];
  compatibilityWarnings?: string[];
  validationSteps: string;
  rollbackSteps: string;
}

export interface PriorityAction {
  priority: number;
  findingId: string;
  channel: string;
  title: string;
  severity: SeverityLevel;
  scoreImpact: number;
  effort: 'LOW' | 'MEDIUM' | 'HIGH';
  businessImpact: string;
  recommendation: string;
}

export interface ExecutiveSummaryReport {
  target: string;
  scanId: string;
  scannerVersion: string;
  overallScore: number;
  grade: string;
  gradeLabel: string;
  classification: string;
  postureHeadline: string;
  executiveNarrative: string;
  counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    totalFindings: number;
  };
  topPriorityActions: PriorityAction[];
  effortVsImpact: {
    quickWins: string[];
    moderateActions: string[];
    strategicActions: string[];
  };
  limitations: string[];
  timestamp: string;
  isAiGenerated: boolean;
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
  isAiGenerated?: boolean;
}

export interface ChatResponse {
  conversationId: string;
  scanId: string;
  reply: string;
  groundedIn: {
    target: string;
    score: number;
    findingsCount: number;
  };
  isAiGenerated: boolean;
}
