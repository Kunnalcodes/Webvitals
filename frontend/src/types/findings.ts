/**
 * Deterministic Findings & Evidence Types — Phase 4
 * WebVitals
 */

export type FindingStatus = 'PASS' | 'FAIL' | 'WARNING' | 'NOT_EVALUATED';
export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface SecurityEvidence {
  channel: string;
  source: string;
  dataType: string;
  rawProof?: any;
  hash?: string;
  collectedAt?: string;
  status?: FindingStatus;
  notes?: string;
}

export interface SecurityFinding {
  id: string;
  channel: string;
  title: string;
  status: FindingStatus;
  severity: SeverityLevel;
  confidence: number;
  scoreImpact: number;
  description: string;
  impact?: string;
  recommendation?: string;
  references?: string[];
  limitations?: string[];
  evidence?: SecurityEvidence[];
}

export interface DetectedTechnology {
  name: string;
  category: string;
  confidence: number;
  evidence: string;
  icon?: string;
}
