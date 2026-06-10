import type { Finding } from '../../types/finding.js';
import type { ScanFileContext, IScanner } from '../../types/scanner.js';
import type { DeepScanConfig } from '../../types/config.js';
import { analyzeComplexity } from './analyzers/complexity.js';
import { analyzeCodeSmells } from './analyzers/code-smells.js';
import { analyzeDuplication } from './analyzers/duplication.js';
import { analyzeMetrics } from './analyzers/metrics.js';

/**
 * Quality Scanner - Orchestrates all code quality analyzers
 *
 * Analyzers:
 * - Complexity: cyclomatic complexity, nesting depth, function length
 * - Code Smells: long files, magic numbers, empty catch, console.log, TODO/FIXME
 * - Duplication: token-based duplicate code detection
 * - Metrics: LOC, comment ratio
 */
export class QualityScanner implements IScanner {
  name = 'QualityScanner';
  type = 'quality' as const;
  private config!: DeepScanConfig;

  async initialize(config: DeepScanConfig): Promise<void> {
    this.config = config;
  }

  async scanFile(context: ScanFileContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    if (!context.content || context.content.trim().length === 0) return findings;

    try {
      const complexityFindings = analyzeComplexity(context);
      findings.push(...complexityFindings);
    } catch {
      // Skip on error
    }

    try {
      const smellFindings = analyzeCodeSmells(context);
      findings.push(...smellFindings);
    } catch {
      // Skip on error
    }

    try {
      const dupFindings = analyzeDuplication(context);
      findings.push(...dupFindings);
    } catch {
      // Skip on error
    }

    try {
      const metricFindings = analyzeMetrics(context);
      findings.push(...metricFindings);
    } catch {
      // Skip on error
    }

    return findings;
  }

  async destroy(): Promise<void> {
    // No cleanup needed
  }
}
