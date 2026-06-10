import type { Severity } from './finding.js';

// ─── Configuration Types ───────────────────────────────────────────────────

/** Scanner-specific configuration */
export interface SecurityScannerConfig {
  enabled: boolean;
  severity: Severity[];
}

export interface QualityThresholds {
  maxComplexity: number;
  maxCognitiveComplexity: number;
  maxFileLength: number;
  maxFunctionLength: number;
  maxNestingDepth: number;
  minCommentRatio: number;
}

export interface QualityScannerConfig {
  enabled: boolean;
  thresholds: QualityThresholds;
}

export interface CVEScannerConfig {
  enabled: boolean;
  sources: string[];
  failOnSeverity?: Severity;
}

/** AI validation configuration */
export interface AIConfig {
  enabled: boolean;
  provider: 'openai' | 'anthropic' | 'ollama';
  model?: string;
  apiKey?: string;
  baseUrl?: string;
  maxFindings?: number;
  temperature?: number;
}

/** Project context configuration */
export interface ContextConfig {
  projectType: 'web' | 'api' | 'library' | 'mobile' | 'cli' | 'auto';
  frameworks: string[];
  sensitivePatterns: string[];
}

/** Output configuration */
export interface OutputConfig {
  format: OutputFormat;
  file?: string;
  verbose: boolean;
  colors: boolean;
}

/** Supported output formats */
export type OutputFormat = 'json' | 'csv' | 'html' | 'sarif' | 'console';

/** Rules configuration */
export interface RulesConfig {
  include: string[];
  exclude: string[];
  custom: string[];
}

/** Paths configuration */
export interface PathsConfig {
  include: string[];
  exclude: string[];
}

/** Complete DeepScan configuration */
export interface DeepScanConfig {
  version: string;
  scanners: {
    security: SecurityScannerConfig;
    quality: QualityScannerConfig;
    cve: CVEScannerConfig;
  };
  rules: RulesConfig;
  languages: string[];
  paths: PathsConfig;
  output: OutputConfig;
  ai: AIConfig;
  context: ContextConfig;
  parallel: number;
  incremental: boolean;
  deep: boolean;
}
