// ─── CSV Reporter ──────────────────────────────────────────────────────────
// Outputs findings as a CSV file with proper escaping and UTF-8 BOM.

import type { ScanResult, Finding } from '../types/finding.js';
import type { OutputFormat } from '../types/config.js';
import { BaseReporter } from './base-reporter.js';

/** UTF-8 byte-order mark so Excel correctly detects the encoding. */
const UTF8_BOM = '\uFEFF';

/** CSV column headers. */
const HEADERS = [
  'ID',
  'Rule',
  'Scanner',
  'Severity',
  'Confidence',
  'Category',
  'File',
  'Line',
  'Title',
  'Message',
] as const;

/**
 * CSV Reporter – produces a standards-compliant CSV file.
 *
 * Features:
 * - UTF-8 BOM prefix for seamless Excel / Google Sheets import
 * - RFC 4180 compliant quoting: fields containing commas, double-quotes,
 *   or newlines are quoted; embedded double-quotes are doubled.
 * - One row per finding with the most useful columns
 */
export class CsvReporter extends BaseReporter {
  readonly format: OutputFormat = 'csv';

  async generate(result: ScanResult): Promise<string> {
    const rows: string[] = [];

    // Header row
    rows.push(HEADERS.join(','));

    // Data rows
    for (const finding of result.findings) {
      rows.push(this.findingToRow(finding));
    }

    return UTF8_BOM + rows.join('\r\n') + '\r\n';
  }

  // ── Private helpers ────────────────────────────────────────────────────

  /**
   * Convert a single Finding to a CSV row string.
   */
  private findingToRow(f: Finding): string {
    const cells: string[] = [
      f.id,
      f.ruleId,
      f.scanner,
      f.severity,
      f.confidence,
      f.category,
      f.location.file,
      String(f.location.startLine),
      f.title,
      f.message,
    ];

    return cells.map(CsvReporter.escapeField).join(',');
  }

  /**
   * Escape a CSV field following RFC 4180 rules.
   * If the value contains a comma, double-quote, or newline the entire field
   * is wrapped in double-quotes and any embedded double-quotes are doubled.
   */
  private static escapeField(value: string): string {
    if (
      value.includes(',') ||
      value.includes('"') ||
      value.includes('\n') ||
      value.includes('\r')
    ) {
      return `"${value.replace(/"/g, '""')}"`;
    }
    return value;
  }
}
