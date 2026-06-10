// ─── Console Reporter ──────────────────────────────────────────────────────
// Beautiful terminal output with colour-coded severity, code snippets,
// grouped findings, and a summary table.

import chalk from 'chalk';
import type { ScanResult, Finding, Severity } from '../types/finding.js';
import type { OutputFormat } from '../types/config.js';
import { BaseReporter } from './base-reporter.js';

/** Severity → chalk colour mapping */
const SEVERITY_COLOURS: Record<Severity, (text: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow.bold,
  low: chalk.blue.bold,
};

/** Severity badge labels (fixed width for alignment) */
const SEVERITY_BADGES: Record<Severity, string> = {
  critical: ' CRITICAL ',
  high: '   HIGH   ',
  medium: '  MEDIUM  ',
  low: '   LOW    ',
};

/** Unicode symbols */
const SYM = {
  bullet: '●',
  arrowRight: '→',
  bar: '█',
  barLight: '░',
  check: '✔',
  cross: '✖',
  line: '─',
  corner: '└',
  tee: '├',
  pipe: '│',
} as const;

/**
 * Console Reporter – renders findings directly to the terminal.
 *
 * Supports two modes controlled via the `verbose` / `quiet` options on the
 * ScanResult's config:
 *
 * - **Verbose**: shows full code snippets, taint traces, and fix suggestions.
 * - **Quiet** (default inverse of verbose): shows a compact one-line-per-finding
 *   view plus the summary table.
 *
 * The `generate` method returns the ANSI-formatted string; `writeToFile` strips
 * ANSI codes before writing so log files stay readable.
 */
export class ConsoleReporter extends BaseReporter {
  readonly format: OutputFormat = 'console';

  /** If true, output full details; if false, compact mode. */
  private verbose = false;

  setVerbose(flag: boolean): void {
    this.verbose = flag;
  }

  async generate(result: ScanResult): Promise<string> {
    const lines: string[] = [];

    lines.push('');
    lines.push(this.renderHeader(result));
    lines.push('');

    if (result.findings.length === 0) {
      lines.push(chalk.green.bold(`  ${SYM.check}  No findings detected – your code looks great!`));
      lines.push('');
      lines.push(this.renderScanMeta(result));
      return lines.join('\n');
    }

    // Group findings by file
    const grouped = this.groupByFile(result.findings);

    for (const [filePath, findings] of grouped) {
      lines.push(this.renderFileHeader(filePath, findings.length));
      // Sort findings within each file by severity weight, then by line number
      findings.sort(
        (a, b) =>
          this.severityWeight(a.severity) - this.severityWeight(b.severity) ||
          a.location.startLine - b.location.startLine,
      );
      for (const finding of findings) {
        lines.push(this.renderFinding(finding));
      }
      lines.push('');
    }

    lines.push(this.renderSummaryTable(result));
    lines.push('');
    lines.push(this.renderProgressBar(result));
    lines.push('');
    lines.push(this.renderScanMeta(result));

    return lines.join('\n');
  }

  // ── Section Renderers ──────────────────────────────────────────────────

  private renderHeader(result: ScanResult): string {
    const divider = chalk.dim(SYM.line.repeat(60));
    const title = chalk.bold.cyan('  ⬡  DeepScan Security Report');
    const target = chalk.dim(`  Target: ${result.target}`);
    const timestamp = chalk.dim(`  Time:   ${result.summary.timestamp}`);
    return [divider, title, target, timestamp, divider].join('\n');
  }

  private renderFileHeader(filePath: string, count: number): string {
    const badge = chalk.bgBlue.white.bold(` ${count} `);
    return `  ${chalk.underline.white(filePath)}  ${badge}`;
  }

  private renderFinding(f: Finding): string {
    const lines: string[] = [];
    const sev = SEVERITY_COLOURS[f.severity](SEVERITY_BADGES[f.severity]);
    const location = chalk.dim(`${f.location.file}:${f.location.startLine}:${f.location.startColumn}`);
    const rule = chalk.dim(`[${f.ruleId}]`);
    const title = chalk.white.bold(f.title);

    lines.push(`    ${sev} ${title} ${rule}`);
    lines.push(`      ${location}`);
    lines.push(`      ${chalk.gray(f.message)}`);

    // Code snippet
    if (f.location.snippet && this.verbose) {
      lines.push(this.renderSnippet(f));
    } else if (f.location.snippet) {
      // Compact snippet: show just the offending line
      const snippetLine = f.location.snippet.split('\n')[0]?.trim() ?? '';
      if (snippetLine) {
        lines.push(`      ${chalk.dim(SYM.pipe)} ${chalk.yellow(snippetLine)}`);
      }
    }

    // Fix suggestion (verbose only)
    if (this.verbose && f.fix) {
      lines.push(`      ${chalk.green(SYM.arrowRight)} ${chalk.green('Fix:')} ${f.fix.description}`);
      if (f.fix.suggestion) {
        lines.push(`        ${chalk.greenBright(f.fix.suggestion)}`);
      }
    }

    // CWE / OWASP tags
    if (this.verbose) {
      const tags: string[] = [];
      if (f.cwe?.length) tags.push(...f.cwe.map((c) => chalk.magenta(`CWE-${c}`)));
      if (f.owasp?.length) tags.push(...f.owasp.map((o) => chalk.magenta(o)));
      if (tags.length) {
        lines.push(`      ${tags.join(' ')}`);
      }
    }

    // Taint flow (verbose only)
    if (this.verbose && f.taintFlow?.length) {
      lines.push(`      ${chalk.cyan('Taint flow:')}`);
      for (let i = 0; i < f.taintFlow.length; i++) {
        const step = f.taintFlow[i]!;
        const connector = i < f.taintFlow.length - 1 ? SYM.tee : SYM.corner;
        const kindBadge =
          step.kind === 'source'
            ? chalk.red('SRC')
            : step.kind === 'sink'
              ? chalk.red('SNK')
              : step.kind === 'sanitizer'
                ? chalk.green('SAN')
                : chalk.yellow('PRO');
        lines.push(
          `        ${chalk.dim(connector)} ${kindBadge} ${step.label} ${chalk.dim(
            `@ ${step.location.file}:${step.location.startLine}`,
          )}`,
        );
      }
    }

    lines.push('');
    return lines.join('\n');
  }

  private renderSnippet(f: Finding): string {
    const snippetLines = f.location.snippet.split('\n');
    const startLine = f.location.startLine;
    const rendered = snippetLines.map((line, idx) => {
      const lineNo = String(startLine + idx).padStart(5);
      const isTarget =
        startLine + idx >= f.location.startLine && startLine + idx <= f.location.endLine;
      const prefix = isTarget ? chalk.red(SYM.arrowRight) : ' ';
      const lineContent = isTarget ? chalk.yellow(line) : chalk.dim(line);
      return `      ${prefix} ${chalk.dim(lineNo)} ${chalk.dim(SYM.pipe)} ${lineContent}`;
    });
    return rendered.join('\n');
  }

  private renderSummaryTable(result: ScanResult): string {
    const s = result.summary;
    const divider = chalk.dim(SYM.line.repeat(60));
    const header = chalk.bold.white('  Summary');

    const rows: string[] = [
      divider,
      header,
      divider,
      this.tableRow('Critical', s.bySeverity.critical, chalk.bgRed.white.bold),
      this.tableRow('High', s.bySeverity.high, chalk.red.bold),
      this.tableRow('Medium', s.bySeverity.medium, chalk.yellow.bold),
      this.tableRow('Low', s.bySeverity.low, chalk.blue.bold),
      divider,
      `  ${chalk.bold('Total')}: ${chalk.white.bold(String(s.totalFindings))} findings in ${chalk.white(
        String(s.filesWithFindings),
      )} files (${chalk.white(String(s.filesScanned))} scanned)`,
      `  ${chalk.bold('Duration')}: ${chalk.white(this.formatDuration(s.scanDuration))}`,
    ];

    return rows.join('\n');
  }

  private tableRow(
    label: string,
    count: number,
    colorFn: (text: string) => string,
  ): string {
    const countStr = String(count).padStart(5);
    const bar = count > 0 ? colorFn(SYM.bar.repeat(Math.min(count, 40))) : chalk.dim('none');
    return `  ${colorFn(label.padEnd(10))} ${countStr}  ${bar}`;
  }

  private renderProgressBar(result: ScanResult): string {
    const s = result.summary;
    const total = s.totalFindings || 1;
    const barWidth = 40;

    const segments: { count: number; color: (text: string) => string }[] = [
      { count: s.bySeverity.critical, color: chalk.bgRed },
      { count: s.bySeverity.high, color: chalk.bgRedBright },
      { count: s.bySeverity.medium, color: chalk.bgYellow },
      { count: s.bySeverity.low, color: chalk.bgBlue },
    ];

    let bar = '';
    for (const seg of segments) {
      const width = Math.round((seg.count / total) * barWidth);
      if (width > 0) {
        bar += seg.color(' '.repeat(width));
      }
    }
    // Fill remainder
    const usedWidth = segments.reduce(
      (sum, seg) => sum + Math.round((seg.count / total) * barWidth),
      0,
    );
    if (usedWidth < barWidth) {
      bar += chalk.bgGray(' '.repeat(barWidth - usedWidth));
    }

    return `  Severity Distribution: ${bar}`;
  }

  private renderScanMeta(result: ScanResult): string {
    return chalk.dim(
      `  ${result.tool.name} v${result.tool.version} ${SYM.bullet} ${result.summary.timestamp}`,
    );
  }

  // ── Helpers ────────────────────────────────────────────────────────────

  private groupByFile(findings: Finding[]): Map<string, Finding[]> {
    const map = new Map<string, Finding[]>();
    for (const f of findings) {
      const key = f.location.file;
      const arr = map.get(key);
      if (arr) {
        arr.push(f);
      } else {
        map.set(key, [f]);
      }
    }
    return map;
  }
}
