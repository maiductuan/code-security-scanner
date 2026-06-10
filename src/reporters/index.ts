// ─── Reporter Module Index ──────────────────────────────────────────────────
// Exports all reporters and provides a factory function.

import type { IReporter } from '../types/scanner.js';
import type { OutputFormat } from '../types/config.js';

import { ConsoleReporter } from './console-reporter.js';
import { JsonReporter } from './json-reporter.js';
import { CsvReporter } from './csv-reporter.js';
import { SarifReporter } from './sarif-reporter.js';
import { HtmlReporter } from './html-reporter.js';

// ── Re-exports ───────────────────────────────────────────────────────────

export { BaseReporter } from './base-reporter.js';
export { ConsoleReporter } from './console-reporter.js';
export { JsonReporter } from './json-reporter.js';
export { CsvReporter } from './csv-reporter.js';
export { SarifReporter } from './sarif-reporter.js';
export { HtmlReporter } from './html-reporter.js';

// ── Factory ──────────────────────────────────────────────────────────────

/**
 * Instantiate the appropriate reporter for the given output format.
 *
 * @param format - One of the supported `OutputFormat` values.
 * @returns A ready-to-use `IReporter` instance.
 * @throws If an unsupported format is provided.
 *
 * @example
 * ```ts
 * const reporter = getReporter('html');
 * const html = await reporter.generate(scanResult);
 * ```
 */
export function getReporter(format: OutputFormat): IReporter {
  switch (format) {
    case 'console':
      return new ConsoleReporter();
    case 'json':
      return new JsonReporter();
    case 'csv':
      return new CsvReporter();
    case 'sarif':
      return new SarifReporter();
    case 'html':
      return new HtmlReporter();
    default: {
      // Exhaustiveness check – TypeScript will flag if a new OutputFormat is
      // added but not handled here.
      const _exhaustive: never = format;
      throw new Error(`Unsupported output format: ${String(_exhaustive)}`);
    }
  }
}
