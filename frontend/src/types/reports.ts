/**
 * Scan Reports & CI/CD Gate Types — Phase 4
 * WebVitals
 */

import { SecurityFinding, DetectedTechnology } from './findings';

export interface ScanReport {
  scanId: string;
  hostname: string;
  requestedUrl: string;
  finalUrl?: string;
  score: number;
  grade: string;
  gradeLabel?: string;
  classification?: string;
  scannerVersion?: string;
  scanMetadata?: {
    startedAt: string;
    completedAt?: string;
    durationMs?: number;
  };
  technologies?: DetectedTechnology[];
  findings?: SecurityFinding[];
  limitations?: string[];
}

export interface QualityGateResponse {
  passed: boolean;
  score: number;
  minimumScore: number;
  grade: string;
  scanId: string;
  target: string;
  failedControlsCount: number;
  reason: string;
  timestamp: string;
}
