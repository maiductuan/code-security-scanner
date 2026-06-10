// ─── Base Reporter ─────────────────────────────────────────────────────────
// Abstract base class providing common utilities for all reporter implementations.

import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname } from 'node:path';
import type { IReporter } from '../types/scanner.js';
import type { ScanResult } from '../types/finding.js';
import type { OutputFormat } from '../types/config.js';

/**
 * Abstract base reporter class that implements `IReporter`.
 * Provides common file-writing utilities and ensures output directories exist.
 * Subclasses must implement the `generate` method for their specific format.
 */
export abstract class BaseReporter implements IReporter {
  abstract readonly format: OutputFormat;

  /**
   * Generate the report content as a string.
   * Each reporter subclass produces its own format (JSON, CSV, HTML, etc.).
   */
  abstract generate(result: ScanResult): Promise<string>;

  /**
   * Write the generated report to the specified file path.
   * Automatically creates parent directories if they do not exist.
   */
  async writeToFile(result: ScanResult, filePath: string): Promise<void> {
    const content = await this.generate(result);
    this.ensureDirectoryExists(filePath);
    writeFileSync(filePath, content, 'utf-8');
  }

  // ── Utility Helpers ────────────────────────────────────────────────────

  /**
   * Ensure the parent directory for a file path exists, creating it recursively
   * if necessary.
   */
  protected ensureDirectoryExists(filePath: string): void {
    const dir = dirname(filePath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
  }

  /**
   * Format a duration in milliseconds to a human-readable string.
   * Examples: "1.23s", "45.6s", "2m 15s"
   */
  protected formatDuration(ms: number): string {
    if (ms < 1000) {
      return `${ms}ms`;
    }
    const seconds = ms / 1000;
    if (seconds < 60) {
      return `${seconds.toFixed(2)}s`;
    }
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = (seconds % 60).toFixed(0);
    return `${minutes}m ${remainingSeconds}s`;
  }

  /**
   * Map severity strings to numeric sort weight.
   * Lower weight = higher priority.
   */
  protected severityWeight(severity: string): number {
    const weights: Record<string, number> = {
      critical: 0,
      error: 1,
      warning: 2,
      info: 3,
    };
    return weights[severity] ?? 4;
  }
}
