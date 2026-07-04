import type { Finding, ScanResult, SourceLocation, CodeContext } from './finding.js';
import type { Rule } from './rule.js';
import type { DeepScanConfig, OutputFormat } from './config.js';
import type { Parser, Tree } from 'web-tree-sitter';

// ─── Scanner Interface ─────────────────────────────────────────────────────

/** Context passed to scanners for each file */
export interface ScanFileContext {
  filePath: string;
  content: string;
  language: string;
  tree: Tree | null;
  parser: Parser | null;
  config: DeepScanConfig;
  rules: Rule[];
}

/** Interface that all scanner engines must implement */
export interface IScanner {
  name: string;
  type: 'security' | 'quality' | 'cve';

  /** Initialize the scanner with configuration */
  initialize(config: DeepScanConfig): Promise<void>;

  /** Scan a single file and return findings */
  scanFile(context: ScanFileContext): Promise<Finding[]>;

  /** Cleanup resources */
  destroy(): Promise<void>;
}

// ─── Reporter Interface ────────────────────────────────────────────────────

/** Interface that all reporters must implement */
export interface IReporter {
  format: OutputFormat;

  /** Generate report from scan results */
  generate(result: ScanResult): Promise<string>;

  /** Write report to file */
  writeToFile(result: ScanResult, filePath: string): Promise<void>;
}

// ─── Language Configuration ────────────────────────────────────────────────

/** Taint source definition */
export interface TaintSource {
  pattern: string;
  type: string;
  description: string;
}

/** Taint sink definition */
export interface TaintSink {
  pattern: string;
  type: string;
  description: string;
}

/** Sanitizer definition */
export interface Sanitizer {
  pattern: string;
  cleanses: string[];
  description: string;
}

/** Language-specific configuration */
export interface LanguageConfig {
  id: string;
  name: string;
  extensions: string[];
  treeSitterLanguage: string;
  taintSources: TaintSource[];
  taintSinks: TaintSink[];
  sanitizers: Sanitizer[];
  namingConventions: {
    variables: string;
    functions: string;
    classes: string;
    constants: string;
  };
  frameworks: string[];
  commentPatterns: {
    single: string;
    multiStart: string;
    multiEnd: string;
  };
}

// ─── Pipeline Types ────────────────────────────────────────────────────────

/** File info discovered during scanning */
export interface DiscoveredFile {
  path: string;
  relativePath: string;
  language: string;
  size: number;
  isDependencyFile: boolean;
  /** Lock files (pnpm-lock.yaml, yarn.lock, etc.) — skip for security scanning */
  isLockFile: boolean;
  /** Vendor/bundled third-party files (jquery.js, vendor/, etc.) */
  isVendorFile: boolean;
  /** Minified files (*.min.js, *.min.css) */
  isMinified: boolean;
  /** Test files (tests/, *.test.*, *.spec.*) */
  isTestFile: boolean;
}

/** Progress callback */
export type ProgressCallback = (current: number, total: number, file: string) => void;

/** Pipeline options */
export interface PipelineOptions {
  config: DeepScanConfig;
  targetPath: string;
  onProgress?: ProgressCallback;
}
