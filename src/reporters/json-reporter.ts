// ─── JSON Reporter ─────────────────────────────────────────────────────────
// Outputs the complete ScanResult as formatted JSON with 2-space indentation.

import type { ScanResult } from '../types/finding.js';
import type { OutputFormat } from '../types/config.js';
import { BaseReporter } from './base-reporter.js';

/**
 * JSON Reporter – emits the full `ScanResult` object as a JSON document.
 *
 * Features:
 * - Pretty-printed with 2-space indentation for readability
 * - Includes all metadata (tool info, summary, findings, AI validations, etc.)
 * - Deterministic output (no custom serialisation logic)
 */
export class JsonReporter extends BaseReporter {
  readonly format: OutputFormat = 'json';

  async generate(result: ScanResult): Promise<string> {
    // Construct an enriched output envelope so downstream consumers get
    // explicit schema hints alongside the raw scan data.
    const output = {
      $schema: 'https://deepscan.dev/schemas/scan-result-v1.json',
      ...result,
      generatedAt: new Date().toISOString(),
    };

    return JSON.stringify(output, null, 2) + '\n';
  }
}
