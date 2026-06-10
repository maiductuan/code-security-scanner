// ─── Finding Types ─────────────────────────────────────────────────────────

/** Severity levels for scan findings */
export type Severity = 'critical' | 'high' | 'medium' | 'low';

/** Confidence levels for findings */
export type Confidence = 'high' | 'medium' | 'low';

/** Scanner engine types */
export type ScannerType = 'security' | 'quality' | 'cve';

/** Source location in a file */
export interface SourceLocation {
  file: string;
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
  snippet: string;
}

/** Business logic context detected in code */
export interface CodeContext {
  type: 'auth' | 'payment' | 'data-handling' | 'api' | 'crypto' | 'file-io' | 'general';
  confidence: number;
  indicators: string[];
  relatedFiles: string[];
}

/** A step in a taint flow trace */
export interface TaintFlowStep {
  location: SourceLocation;
  label: string;
  kind: 'source' | 'propagator' | 'sanitizer' | 'sink';
}

/** AI validation result for a finding */
export interface AIValidationResult {
  isValid: boolean;
  explanation: string;
  confidence: number;
  fixSuggestion?: string;
}

/** Fix suggestion for a finding */
export interface FixSuggestion {
  description: string;
  suggestion?: string;
  references: string[];
}

/** A single scan finding / issue */
export interface Finding {
  id: string;
  ruleId: string;
  scanner: ScannerType;
  severity: Severity;
  confidence: Confidence;
  category: string;
  subcategory?: string;
  title: string;
  message: string;
  location: SourceLocation;
  context?: CodeContext;
  taintFlow?: TaintFlowStep[];
  cwe?: string[];
  owasp?: string[];
  fix?: FixSuggestion;
  references?: string[];
  aiValidation?: AIValidationResult;
  metadata: {
    fingerprint: string;
    firstSeen?: string;
    tags: string[];
  };
}

// ─── Scan Result Types ─────────────────────────────────────────────────────

/** Summary statistics for a scan */
export interface ScanSummary {
  totalFindings: number;
  bySeverity: Record<Severity, number>;
  byScanner: Record<ScannerType, number>;
  byCategory: Record<string, number>;
  filesScanned: number;
  filesWithFindings: number;
  scanDuration: number; // milliseconds
  timestamp: string;
}

/** Complete scan result */
export interface ScanResult {
  version: string;
  tool: {
    name: string;
    version: string;
  };
  target: string;
  config: string;
  summary: ScanSummary;
  findings: Finding[];
}
