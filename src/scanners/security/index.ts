// ─── Security Scanner ──────────────────────────────────────────────────────
// Bộ quét bảo mật – điều phối tất cả các analyzer bảo mật
// Orchestrator that runs all security analyzers and implements IScanner

import type { Finding } from '../../types/finding.js';
import type { IScanner, ScanFileContext } from '../../types/scanner.js';
import type { DeepScanConfig } from '../../types/config.js';
import { BaseScanner } from '../base-scanner.js';

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
