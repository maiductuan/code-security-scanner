// ─── Security Scanner ──────────────────────────────────────────────────────
// Bộ quét bảo mật – điều phối tất cả các analyzer bảo mật
// Orchestrator that runs all security analyzers and implements IScanner

import type { Finding, Severity } from '../../types/finding.js';
import type { IScanner, ScanFileContext } from '../../types/scanner.js';
import type { DeepScanConfig } from '../../types/config.js';
import { BaseScanner, createFinding } from '../base-scanner.js';
import { analyzeTaintFlow } from '../../core/taint-tracker.js';

// Import all security analyzers
import { analyzeInjection } from './analyzers/injection.js';
import { analyzeXSS } from './analyzers/xss.js';
import { analyzeSecrets } from './analyzers/secrets.js';
import { analyzeAuth } from './analyzers/auth.js';
import { analyzeCrypto } from './analyzers/crypto.js';
import { analyzeFileOps } from './analyzers/file-ops.js';
import { analyzeAPISec } from './analyzers/api-sec.js';

// ─── Analyzer Registry ────────────────────────────────────────────────────

interface SecurityAnalyzer {
  name: string;
  analyze: (context: ScanFileContext) => Finding[];
}

/** All registered security analyzers */
const ANALYZERS: SecurityAnalyzer[] = [
  { name: 'injection', analyze: analyzeInjection },
  { name: 'xss', analyze: analyzeXSS },
  { name: 'secrets', analyze: analyzeSecrets },
  { name: 'auth', analyze: analyzeAuth },
  { name: 'crypto', analyze: analyzeCrypto },
  { name: 'file-ops', analyze: analyzeFileOps },
  { name: 'api-sec', analyze: analyzeAPISec },
];

const TAINT_METADATA: Record<string, { severity: Severity; cwe: string[]; title: string }> = {
  code_injection: { severity: 'critical', cwe: ['CWE-94'], title: 'Code Injection via Taint Flow' },
  command_injection: { severity: 'critical', cwe: ['CWE-78'], title: 'Command Injection via Taint Flow' },
  sql_injection: { severity: 'critical', cwe: ['CWE-89'], title: 'SQL Injection via Taint Flow' },
  xss: { severity: 'high', cwe: ['CWE-79'], title: 'Cross-Site Scripting (XSS) via Taint Flow' },
  path_traversal: { severity: 'high', cwe: ['CWE-22'], title: 'Path Traversal via Taint Flow' },
  deserialization: { severity: 'critical', cwe: ['CWE-502'], title: 'Insecure Deserialization via Taint Flow' },
  buffer_overflow: { severity: 'high', cwe: ['CWE-120'], title: 'Buffer Overflow via Taint Flow' },
  format_string: { severity: 'high', cwe: ['CWE-134'], title: 'Format String Vulnerability via Taint Flow' },
  file_inclusion: { severity: 'critical', cwe: ['CWE-98'], title: 'File Inclusion via Taint Flow' },
};

// ─── Security Scanner Class ───────────────────────────────────────────────

/**
 * Security scanner engine that orchestrates all security analyzers.
 * Bộ quét bảo mật điều phối tất cả analyzer: injection, XSS, secrets, auth, crypto, file-ops, api-security
 */
export class SecurityScanner extends BaseScanner implements IScanner {
  name = 'SecurityScanner';
  type = 'security' as const;

  private enabledSeverities: Set<string> = new Set();

  async initialize(config: DeepScanConfig): Promise<void> {
    await super.initialize(config);

    // Store enabled severity levels for filtering
    if (config.scanners.security.severity?.length) {
      this.enabledSeverities = new Set(config.scanners.security.severity);
    } else {
      // Default: all severity levels
      this.enabledSeverities = new Set(['critical', 'high', 'medium', 'low']);
    }
  }

  /**
   * Scan a file through all security analyzers.
   * Quét tệp qua tất cả analyzer bảo mật
   */
  async scanFile(context: ScanFileContext): Promise<Finding[]> {
    // Skip if security scanning is disabled
    if (this.config && !this.config.scanners.security.enabled) {
      return [];
    }

    const allFindings: Finding[] = [];

    // Run each analyzer and collect findings
    for (const analyzer of ANALYZERS) {
      try {
        const findings = analyzer.analyze(context);
        allFindings.push(...findings);
      } catch (error) {
        // Log error but don't stop scanning
        // Ghi lỗi nhưng không dừng quét
        console.error(`[SecurityScanner] Error in ${analyzer.name} analyzer:`, error);
      }
    }

    // Run taint flow analysis if deep analysis is enabled
    if (context.config?.deep) {
      try {
        const taintResults = analyzeTaintFlow(context.content, context.filePath, context.language);
        for (const res of taintResults) {
          if (!res.hasTaintedSink || res.flow.length === 0) continue;
          const sinkStep = res.flow[res.flow.length - 1];
          const loc = sinkStep.location;
          const meta = TAINT_METADATA[res.sinkType] || {
            severity: 'high' as Severity,
            cwe: [],
            title: `Taint Flow: ${res.sinkType.replace(/_/g, ' ').toUpperCase()}`,
          };

          const finding = createFinding({
            ruleId: `security/taint-${res.sinkType.replace(/_/g, '-')}`,
            scanner: 'security',
            severity: meta.severity,
            confidence: 'high',
            category: 'taint-flow',
            subcategory: res.sinkType,
            title: meta.title,
            message: `Tainted data from source "${res.sourceType}" reaches sink "${res.sinkType}" via propagator.`,
            filePath: context.filePath,
            lineNumber: loc.startLine,
            column: loc.startColumn,
            snippet: loc.snippet,
            cwe: meta.cwe,
            owasp: ['A03:2021'],
            fix: {
              description: `Sanitize the tainted value before passing it to ${res.sinkType}.`,
              references: [],
            },
            tags: ['taint-flow', 'security'],
          });
          finding.taintFlow = res.flow;
          allFindings.push(finding);
        }
      } catch (error) {
        console.error('[SecurityScanner] Error in taint flow analysis:', error);
      }
    }

    // Also run rule-based pattern matching if rules are provided
    if (context.rules.length > 0) {
      const securityRules = context.rules.filter(
        (r) => r.category && ['injection', 'xss', 'secrets', 'auth', 'crypto', 'file-ops', 'api-security'].includes(r.category),
      );
      if (securityRules.length > 0) {
        try {
          const ruleFindings = this.matchRulePatterns(context, securityRules);
          allFindings.push(...ruleFindings);
        } catch (error) {
          console.error('[SecurityScanner] Error in rule matching:', error);
        }
      }
    }

    // Filter by enabled severity levels
    const filteredFindings = allFindings.filter((f) => this.enabledSeverities.has(f.severity));

    // Deduplicate findings by fingerprint
    // Loại bỏ trùng lặp bằng fingerprint
    const seen = new Set<string>();
    const deduplicated: Finding[] = [];
    for (const finding of filteredFindings) {
      if (!seen.has(finding.metadata.fingerprint)) {
        seen.add(finding.metadata.fingerprint);
        deduplicated.push(finding);
      }
    }

    return deduplicated;
  }

  async destroy(): Promise<void> {
    await super.destroy();
    this.enabledSeverities.clear();
  }
}
