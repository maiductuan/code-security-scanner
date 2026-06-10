// DeepScan - Open-source security & code quality scanner
// https://github.com/deepscan/deepscan-cli

export { ScanPipeline, generateFingerprint } from './core/pipeline.js';
export { loadConfig } from './config/loader.js';
export { RuleEngine } from './rules/rule-engine.js';
export { getReporter } from './reporters/index.js';
export { SecurityScanner } from './scanners/security/index.js';
export { QualityScanner } from './scanners/quality/index.js';
export { CVEScanner } from './scanners/cve/index.js';

// Types
export type {
  Finding,
  ScanResult,
  ScanSummary,
  Severity,
  Confidence,
  ScannerType,
  SourceLocation,
  CodeContext,
  TaintFlowStep,
  AIValidationResult,
} from './types/finding.js';

export type {
  Rule,
  RulePattern,
  RuleCondition,
} from './types/rule.js';

export type {
  DeepScanConfig,
  OutputFormat,
} from './types/config.js';

export type {
  IScanner,
  IReporter,
  LanguageConfig,
} from './types/scanner.js';
