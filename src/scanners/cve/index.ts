import type { Finding, Severity } from '../../types/finding.js';
import type { ScanFileContext, IScanner } from '../../types/scanner.js';
import type { DeepScanConfig } from '../../types/config.js';
import { parseDependencies, type DependencyInfo } from './parsers/package-parser.js';
import { queryVulnerabilities, type VulnerabilityMatch } from './vulnerability-db.js';
import { createHash } from 'node:crypto';

/**
 * CVE/SCA Scanner - Software Composition Analysis
 *
 * Parses dependency manifests and checks for known vulnerabilities
 * using the OSV (Open Source Vulnerabilities) database.
 */
export class CVEScanner implements IScanner {
  name = 'CVEScanner';
  type = 'cve' as const;
  private config!: DeepScanConfig;

  async initialize(config: DeepScanConfig): Promise<void> {
    this.config = config;
  }

  async scanFile(context: ScanFileContext): Promise<Finding[]> {
    const { content, filePath } = context;
    const findings: Finding[] = [];

    if (!content) return findings;

    try {
      // Parse dependencies from manifest file
      const dependencies = parseDependencies(content, filePath);

      if (dependencies.length === 0) return findings;

      // Query for vulnerabilities
      const vulnerabilities = await queryVulnerabilities(dependencies);

      // Convert to findings
      for (const vuln of vulnerabilities) {
        const severity = mapSeverity(vuln.severity);
        const fingerprint = createHash('sha256')
          .update(`cve:${vuln.id}:${vuln.package}:${filePath}`)
          .digest('hex')
          .slice(0, 16);

        findings.push({
          id: `cve-${fingerprint.slice(0, 8)}`,
          ruleId: 'cve/known-vulnerability',
          scanner: 'cve',
          severity,
          confidence: 'high',
          category: 'vulnerability',
          title: `${vuln.id}: ${vuln.summary.slice(0, 100)}`,
          message: `Package "${vuln.package}@${vuln.version}" has a known vulnerability: ${vuln.summary}`,
          location: {
            file: filePath,
            startLine: vuln.lineNumber || 1,
            startColumn: 0,
            endLine: vuln.lineNumber || 1,
            endColumn: 0,
            snippet: `${vuln.package}: ${vuln.version}`,
          },
          cwe: vuln.cwe || [],
          fix: {
            description: vuln.fixedVersion
              ? `Upgrade ${vuln.package} to version ${vuln.fixedVersion}`
              : `No fix available yet. Consider finding an alternative package.`,
            references: vuln.references || [],
          },
          metadata: {
            fingerprint,
            tags: ['cve', 'dependency', vuln.ecosystem],
          },
        });
      }
    } catch (error) {
      // Skip on error - network issues, etc.
    }

    return findings;
  }

  async destroy(): Promise<void> {
    // No cleanup needed
  }
}

/**
 * Map vulnerability severity string to our Severity type
 */
function mapSeverity(severity: string): Severity {
  const lower = severity.toLowerCase();
  if (lower === 'critical') return 'critical';
  if (lower === 'high') return 'high';
  if (lower === 'medium' || lower === 'moderate') return 'medium';
  return 'low';
}
