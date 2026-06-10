// ─── SARIF Reporter ────────────────────────────────────────────────────────
// Produces SARIF v2.1.0 compliant output for integration with GitHub Code
// Scanning, Azure DevOps, and other SARIF-compatible tools.

import type { ScanResult, Finding, Severity } from '../types/finding.js';
import type { OutputFormat } from '../types/config.js';
import { BaseReporter } from './base-reporter.js';

// ── SARIF type definitions (subset) ──────────────────────────────────────

interface SarifMessage {
  text: string;
}

interface SarifArtifactLocation {
  uri: string;
  uriBaseId?: string;
}

interface SarifRegion {
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
  snippet?: { text: string };
}

interface SarifPhysicalLocation {
  artifactLocation: SarifArtifactLocation;
  region: SarifRegion;
}

interface SarifLocation {
  physicalLocation: SarifPhysicalLocation;
}

interface SarifCodeFlow {
  threadFlows: SarifThreadFlow[];
}

interface SarifThreadFlow {
  locations: SarifThreadFlowLocation[];
}

interface SarifThreadFlowLocation {
  location: SarifLocation;
  kinds?: string[];
  message?: SarifMessage;
}

interface SarifFix {
  description: SarifMessage;
}

interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: 'error' | 'warning' | 'note' | 'none';
  message: SarifMessage;
  locations: SarifLocation[];
  fingerprints?: Record<string, string>;
  codeFlows?: SarifCodeFlow[];
  fixes?: SarifFix[];
  properties?: Record<string, unknown>;
}

interface SarifReportingDescriptor {
  id: string;
  name: string;
  shortDescription: SarifMessage;
  fullDescription?: SarifMessage;
  helpUri?: string;
  defaultConfiguration?: { level: string };
  properties?: Record<string, unknown>;
  relationships?: SarifRelationship[];
}

interface SarifRelationship {
  target: {
    id: string;
    guid?: string;
    toolComponent: { name: string };
  };
  kinds: string[];
}

interface SarifToolComponent {
  name: string;
  version: string;
  informationUri?: string;
  rules: SarifReportingDescriptor[];
}

interface SarifTaxon {
  id: string;
  name: string;
  shortDescription?: SarifMessage;
}

interface SarifTaxonomy {
  name: string;
  version?: string;
  informationUri?: string;
  organization?: string;
  shortDescription?: SarifMessage;
  taxa: SarifTaxon[];
  guid?: string;
  isComprehensive?: boolean;
}

interface SarifRun {
  tool: { driver: SarifToolComponent };
  results: SarifResult[];
  taxonomies?: SarifTaxonomy[];
  invocations?: SarifInvocation[];
}

interface SarifInvocation {
  executionSuccessful: boolean;
  startTimeUtc?: string;
  endTimeUtc?: string;
  toolExecutionNotifications?: unknown[];
}

interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: SarifRun[];
}

// ── Severity → SARIF level mapping ───────────────────────────────────────

const SARIF_LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
};

/**
 * SARIF Reporter – produces a SARIF v2.1.0 JSON log.
 *
 * Features:
 * - Full tool metadata (name, version, rules array)
 * - CWE taxonomy references when CWE data is available
 * - Code-flow traces mapped from taint-flow data
 * - Fix suggestions as SARIF `fixes`
 * - Fingerprints for result matching / deduplication
 */
export class SarifReporter extends BaseReporter {
  readonly format: OutputFormat = 'sarif';

  async generate(result: ScanResult): Promise<string> {
    // Collect unique rules from findings
    const ruleMap = this.collectRules(result.findings);
    const rules = Array.from(ruleMap.values());
    const ruleIndex = new Map<string, number>();
    rules.forEach((r, idx) => ruleIndex.set(r.id, idx));

    // Build CWE taxonomy if any finding references CWEs
    const cweTaxa = this.collectCweTaxa(result.findings);
    const taxonomies: SarifTaxonomy[] = [];
    if (cweTaxa.length > 0) {
      taxonomies.push({
        name: 'CWE',
        version: '4.13',
        organization: 'MITRE',
        shortDescription: { text: 'The MITRE Common Weakness Enumeration' },
        informationUri: 'https://cwe.mitre.org/',
        isComprehensive: false,
        taxa: cweTaxa,
      });
    }

    // Attach CWE relationships to rules
    if (cweTaxa.length > 0) {
      for (const rule of rules) {
        const cweIds = (rule.properties?.['cwe'] as string[] | undefined) ?? [];
        if (cweIds.length > 0) {
          rule.relationships = cweIds.map((id) => ({
            target: {
              id,
              toolComponent: { name: 'CWE' },
            },
            kinds: ['superset'],
          }));
        }
      }
    }

    // Build SARIF results
    const sarifResults = result.findings.map((f) =>
      this.findingToResult(f, ruleIndex),
    );

    // Compute invocation timestamps
    const endTime = new Date(result.summary.timestamp);
    const startTime = new Date(endTime.getTime() - result.summary.scanDuration);

    const sarifLog: SarifLog = {
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: result.tool.name,
              version: result.tool.version,
              informationUri: 'https://github.com/deepscan/deepscan',
              rules,
            },
          },
          invocations: [
            {
              executionSuccessful: true,
              startTimeUtc: startTime.toISOString(),
              endTimeUtc: endTime.toISOString(),
            },
          ],
          results: sarifResults,
          ...(taxonomies.length > 0 ? { taxonomies } : {}),
        },
      ],
    };

    return JSON.stringify(sarifLog, null, 2) + '\n';
  }

  // ── Private helpers ────────────────────────────────────────────────────

  /**
   * Collect unique rule descriptors from the findings array.
   */
  private collectRules(findings: Finding[]): Map<string, SarifReportingDescriptor> {
    const map = new Map<string, SarifReportingDescriptor>();

    for (const f of findings) {
      if (map.has(f.ruleId)) continue;

      const descriptor: SarifReportingDescriptor = {
        id: f.ruleId,
        name: f.title,
        shortDescription: { text: f.title },
        fullDescription: { text: f.message },
        defaultConfiguration: { level: SARIF_LEVEL[f.severity] },
        properties: {
          category: f.category,
          ...(f.cwe?.length ? { cwe: f.cwe } : {}),
          ...(f.owasp?.length ? { owasp: f.owasp } : {}),
          tags: [f.scanner, f.category, ...(f.metadata.tags ?? [])],
        },
      };

      map.set(f.ruleId, descriptor);
    }

    return map;
  }

  /**
   * Collect unique CWE taxa from all findings.
   */
  private collectCweTaxa(findings: Finding[]): SarifTaxon[] {
    const seen = new Set<string>();
    const taxa: SarifTaxon[] = [];

    for (const f of findings) {
      if (!f.cwe) continue;
      for (const cweId of f.cwe) {
        if (seen.has(cweId)) continue;
        seen.add(cweId);
        taxa.push({
          id: cweId,
          name: `CWE-${cweId}`,
          shortDescription: { text: `Common Weakness Enumeration ${cweId}` },
        });
      }
    }

    return taxa;
  }

  /**
   * Map a Finding to a SARIF Result.
   */
  private findingToResult(
    f: Finding,
    ruleIndex: Map<string, number>,
  ): SarifResult {
    const result: SarifResult = {
      ruleId: f.ruleId,
      ruleIndex: ruleIndex.get(f.ruleId) ?? 0,
      level: SARIF_LEVEL[f.severity],
      message: { text: `${f.title}: ${f.message}` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: this.normaliseUri(f.location.file),
              uriBaseId: '%SRCROOT%',
            },
            region: {
              startLine: f.location.startLine,
              startColumn: f.location.startColumn,
              endLine: f.location.endLine,
              endColumn: f.location.endColumn,
              ...(f.location.snippet
                ? { snippet: { text: f.location.snippet } }
                : {}),
            },
          },
        },
      ],
      fingerprints: {
        'deepscan/v1': f.metadata.fingerprint,
      },
      properties: {
        confidence: f.confidence,
        scanner: f.scanner,
        category: f.category,
        ...(f.subcategory ? { subcategory: f.subcategory } : {}),
        ...(f.aiValidation
          ? {
              aiValidation: {
                isValid: f.aiValidation.isValid,
                confidence: f.aiValidation.confidence,
              },
            }
          : {}),
      },
    };

    // Taint flow → code flows
    if (f.taintFlow?.length) {
      result.codeFlows = [
        {
          threadFlows: [
            {
              locations: f.taintFlow.map((step) => ({
                location: {
                  physicalLocation: {
                    artifactLocation: {
                      uri: this.normaliseUri(step.location.file),
                      uriBaseId: '%SRCROOT%',
                    },
                    region: {
                      startLine: step.location.startLine,
                      startColumn: step.location.startColumn,
                      endLine: step.location.endLine,
                      endColumn: step.location.endColumn,
                    },
                  },
                },
                kinds: [step.kind],
                message: { text: step.label },
              })),
            },
          ],
        },
      ];
    }

    // Fix suggestions
    if (f.fix) {
      result.fixes = [
        {
          description: { text: f.fix.description },
        },
      ];
    }

    return result;
  }

  /**
   * Normalise a file path to a forward-slash URI suitable for SARIF.
   */
  private normaliseUri(filePath: string): string {
    return filePath.replace(/\\/g, '/');
  }
}
