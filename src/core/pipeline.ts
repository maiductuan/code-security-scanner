import { createHash } from 'node:crypto';
import { consola } from 'consola';
import type { Finding, ScanResult, ScanSummary, Severity } from '../types/finding.js';
import type { DeepScanConfig } from '../types/config.js';
import type { IScanner, DiscoveredFile, PipelineOptions, ProgressCallback, ScanFileContext } from '../types/scanner.js';
import { discoverFiles, readFileContent } from './file-discovery.js';
import { RuleEngine } from '../rules/rule-engine.js';
import { getLanguageConfig } from '../languages/registry.js';
import { AIValidator } from './ai-validator.js';
import { ASTParser } from './ast-parser.js';

/** DeepScan version */
const VERSION = '1.0.0';

/**
 * Main scanning pipeline orchestrator
 */
export class ScanPipeline {
  private config: DeepScanConfig;
  private scanners: IScanner[] = [];
  private ruleEngine: RuleEngine;
  private astParser: ASTParser;
  private findings: Finding[] = [];

  constructor(config: DeepScanConfig) {
    this.config = config;
    this.ruleEngine = new RuleEngine(config);
    this.astParser = new ASTParser();
  }

  /**
   * Register a scanner engine
   */
  addScanner(scanner: IScanner): void {
    this.scanners.push(scanner);
  }

  /**
   * Run the full scanning pipeline
   */
  async run(options: PipelineOptions): Promise<ScanResult> {
    const startTime = Date.now();
    const { targetPath, onProgress } = options;

    consola.start('DeepScan v' + VERSION);
    consola.info(`Target: ${targetPath}`);

    // Step 1: Initialize rule engine
    await this.ruleEngine.initialize();

    // Step 1.5: Initialize AST parser (non-blocking, degrades gracefully)
    await this.astParser.initialize();

    // Step 2: Initialize all scanners
    for (const scanner of this.scanners) {
      await scanner.initialize(this.config);
    }

    // Step 3: Discover files
    const files = await discoverFiles(
      targetPath,
      this.config.paths,
      this.config.languages,
    );

    if (files.length === 0) {
      consola.warn('No files found to scan');
      return this.buildResult(targetPath, startTime, files.length);
    }

    // Step 4: Scan each file
    let processed = 0;
    const totalFiles = files.length;

    for (const file of files) {
      try {
        await this.scanFile(file);
      } catch (error) {
        consola.debug(`Error scanning ${file.relativePath}:`, error);
      }

      processed++;
      if (onProgress) {
        onProgress(processed, totalFiles, file.relativePath);
      }
    }

    // Step 4.5: AI Validation (if enabled)
    if (this.config.ai?.enabled) {
      try {
        const aiValidator = new AIValidator(this.config.ai);
        if (aiValidator.isAvailable()) {
          this.findings = await aiValidator.validateFindings(this.findings);
          // Filter out findings evaluated as false positives
          this.findings = this.findings.filter(f => !f.aiValidation || f.aiValidation.isValid !== false);
        }
      } catch (error) {
        consola.error('AI Validation failed:', error);
      }
    }

    // Step 5: Cleanup
    for (const scanner of this.scanners) {
      await scanner.destroy();
    }
    await this.astParser.destroy();

    // Step 6: Build and return result
    const result = this.buildResult(targetPath, startTime, files.length);

    consola.success(
      `Scan complete: ${result.summary.totalFindings} findings in ${result.summary.filesScanned} files (${result.summary.scanDuration}ms)`
    );

    return result;
  }

  /**
   * Scan a single file with all registered scanners
   */
  private async scanFile(file: DiscoveredFile): Promise<void> {
    const content = readFileContent(file.path);
    if (!content) return;

    // Get language-specific rules
    const rules = this.ruleEngine.getRulesForLanguage(file.language);

    // Build scan context
    // Parse AST tree for context-aware analysis (degrades gracefully if grammar unavailable)
    const tree = await this.astParser.parse(content, file.language, file.path);

    const context: ScanFileContext = {
      filePath: file.path,
      content,
      language: file.language,
      tree,
      parser: this.astParser.getParser(),
      config: this.config,
      rules,
    };

    // Run each scanner
    for (const scanner of this.scanners) {
      try {
        // Skip disabled scanners
        if (scanner.type === 'security' && !this.config.scanners.security.enabled) continue;
        if (scanner.type === 'quality' && !this.config.scanners.quality.enabled) continue;
        if (scanner.type === 'cve' && !this.config.scanners.cve.enabled) continue;

        // CVE scanner only processes dependency files
        if (scanner.type === 'cve' && !file.isDependencyFile) continue;

        // Security scanner skips lock files, vendor/bundle files, and minified files
        // These produce massive false positives with no real security value
        if (scanner.type === 'security') {
          if (file.isLockFile || file.isVendorFile || file.isMinified) continue;
        }

        const findings = await scanner.scanFile(context);

        // Filter by configured severity
        const filteredFindings = findings.filter(f => {
          if (scanner.type === 'security') {
            return this.config.scanners.security.severity.includes(f.severity);
          }
          return true;
        });

        this.findings.push(...filteredFindings);
      } catch (error) {
        consola.debug(`Scanner ${scanner.name} failed on ${file.relativePath}:`, error);
      }
    }
  }

  /**
   * Build the final scan result
   */
  private buildResult(targetPath: string, startTime: number, filesScanned: number): ScanResult {
    const duration = Date.now() - startTime;

    // Deduplicate findings by fingerprint AND smart line+category grouping for security scanner
    const seenFingerprints = new Set<string>();
    const groupedSecurityFindings = new Map<string, Finding[]>();
    const deduped: Finding[] = [];

    for (const finding of this.findings) {
      if (seenFingerprints.has(finding.metadata.fingerprint)) {
        continue;
      }
      seenFingerprints.add(finding.metadata.fingerprint);

      if (finding.scanner === 'security') {
        // Group by file, line, and category to catch rules that overlap
        const key = `${finding.location.file}:${finding.location.startLine}:${finding.category}`;
        if (!groupedSecurityFindings.has(key)) {
          groupedSecurityFindings.set(key, []);
        }
        groupedSecurityFindings.get(key)!.push(finding);
      } else {
        deduped.push(finding);
      }
    }

    for (const [_, group] of groupedSecurityFindings.entries()) {
      if (group.length === 1) {
        deduped.push(group[0]);
      } else {
        // Sort to find the best finding to keep:
        // 1. Prefer specific rules (e.g. starting with SEC-) over generic ones (starting with security/)
        // 2. Prefer higher severity (critical > high > medium > low)
        // 3. Prefer longer/more descriptive message
        group.sort((a, b) => {
          const isGenericA = a.ruleId.startsWith('security/');
          const isGenericB = b.ruleId.startsWith('security/');
          
          if (isGenericA && !isGenericB) return 1;
          if (!isGenericA && isGenericB) return -1;
          
          const severityOrder: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
          const aSev = severityOrder[a.severity] ?? 4;
          const bSev = severityOrder[b.severity] ?? 4;
          const sevDiff = aSev - bSev;
          if (sevDiff !== 0) return sevDiff;
          
          return b.message.length - a.message.length;
        });
        
        deduped.push(group[0]);
      }
    }

    // Sort findings: critical first, then by file
    deduped.sort((a, b) => {
      const severityOrder: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
      const sevDiff = severityOrder[a.severity] - severityOrder[b.severity];
      if (sevDiff !== 0) return sevDiff;
      return a.location.file.localeCompare(b.location.file);
    });

    // Build summary
    const filesWithFindings = new Set(deduped.map(f => f.location.file)).size;
    const summary: ScanSummary = {
      totalFindings: deduped.length,
      bySeverity: {
        critical: deduped.filter(f => f.severity === 'critical').length,
        high: deduped.filter(f => f.severity === 'high').length,
        medium: deduped.filter(f => f.severity === 'medium').length,
        low: deduped.filter(f => f.severity === 'low').length,
      },
      byScanner: {
        security: deduped.filter(f => f.scanner === 'security').length,
        quality: deduped.filter(f => f.scanner === 'quality').length,
        cve: deduped.filter(f => f.scanner === 'cve').length,
      },
      byCategory: {},
      filesScanned,
      filesWithFindings,
      scanDuration: duration,
      timestamp: new Date().toISOString(),
    };

    // Count by category
    for (const finding of deduped) {
      summary.byCategory[finding.category] = (summary.byCategory[finding.category] || 0) + 1;
    }

    return {
      version: VERSION,
      tool: { name: 'DeepScan', version: VERSION },
      target: targetPath,
      config: this.config.version,
      summary,
      findings: deduped,
    };
  }
}

/**
 * Generate a unique fingerprint for a finding (for deduplication across scans)
 */
export function generateFingerprint(
  ruleId: string,
  filePath: string,
  line: number,
  snippet: string,
): string {
  const hash = createHash('sha256');
  hash.update(`${ruleId}:${filePath}:${line}:${snippet.trim().slice(0, 100)}`);
  return hash.digest('hex').slice(0, 16);
}
