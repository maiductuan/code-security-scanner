import { Command } from 'commander';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { consola } from 'consola';
import type { ScanResult } from '../../types/finding.js';
import type { OutputFormat } from '../../types/config.js';
import { getReporter } from '../../reporters/index.js';

/**
 * Create the 'report' command
 * Usage: deepscan report convert <input> --to <format> --output <file>
 */
export function createReportCommand(): Command {
  const report = new Command('report');
  report.description('Convert and manage scan reports');

  report
    .command('convert <input>')
    .description('Convert scan results between formats')
    .requiredOption('--to <format>', 'Target format: json, csv, html, sarif')
    .option('-o, --output <file>', 'Output file path')
    .action(async (input: string, options: { to: string; output?: string }) => {
      try {
        const inputPath = resolve(input);
        const content = readFileSync(inputPath, 'utf-8');
        const scanResult: ScanResult = JSON.parse(content);

        const reporter = getReporter(options.to as OutputFormat);
        const output = await reporter.generate(scanResult);

        if (options.output) {
          const outputPath = resolve(options.output);
          writeFileSync(outputPath, output, 'utf-8');
          consola.success(`Report converted to ${options.to}: ${outputPath}`);
        } else {
          process.stdout.write(output);
        }
      } catch (error) {
        consola.error('Report conversion failed:', error);
        process.exitCode = 1;
      }
    });

  return report;
}
