import { Command } from 'commander';
import { resolve } from 'node:path';
import { consola } from 'consola';
import { loadConfig } from '../../config/loader.js';
import { ScanPipeline, generateFingerprint } from '../../core/pipeline.js';
import { SecurityScanner } from '../../scanners/security/index.js';
import { QualityScanner } from '../../scanners/quality/index.js';
import { CVEScanner } from '../../scanners/cve/index.js';
import { getReporter } from '../../reporters/index.js';
import type { OutputFormat } from '../../types/config.js';

/**
 * Create the 'scan' command
 * Usage: deepscan scan [path] [options]
 */
export function createScanCommand(): Command {
  const scan = new Command('scan');

  scan
    .description('Scan source code for security vulnerabilities and quality issues')
    .argument('[path]', 'Path to scan (default: current directory)', '.')
    .option('-s, --scanners <scanners>', 'Scanner engines to use (comma-separated: security,quality,cve)')
    .option('--security', 'Run security scanner only')
    .option('--quality', 'Run quality scanner only')
    .option('--cve', 'Run CVE/dependency scanner only')
    .option('-f, --format <format>', 'Output format: json, csv, html, sarif, console', 'console')
    .option('-o, --output <file>', 'Output file path')
    .option('--severity <levels>', 'Filter by severity (comma-separated: critical,error,warning,info)')
    .option('--include <patterns>', 'Include file patterns (comma-separated)')
    .option('--exclude <patterns>', 'Exclude file patterns (comma-separated)')
    .option('--deep', 'Enable deep analysis (taint tracking, semantic analysis)')
    .option('--ai', 'Enable AI-assisted validation (requires API key)')
    .option('--ai-provider <provider>', 'AI provider: openai, anthropic, ollama')
    .option('--rules <path>', 'Path to custom rules directory')
    .option('--parallel <n>', 'Number of parallel workers', '4')
    .option('--incremental', 'Only scan changed files (git-based)')
    .option('--preset <name>', 'Use a preset configuration (node-api, python-web, java-spring, minimal)')
    .option('--config <path>', 'Path to configuration file')
    .action(async (targetPath: string, options: Record<string, string | boolean | undefined>) => {
      try {
        const absolutePath = resolve(targetPath);

        // Build CLI overrides from options
        const cliOverrides: Record<string, unknown> = {};

        const hasExplicitFlag = options.security || options.quality || options.cve;
        if (hasExplicitFlag) {
          cliOverrides.scanners = {
            security: { enabled: !!options.security },
            quality: { enabled: !!options.quality },
            cve: { enabled: !!options.cve },
          };
        } else if (options.scanners) {
          const scannerList = (options.scanners as string).split(',');
          cliOverrides.scanners = {
            security: { enabled: scannerList.includes('security') },
            quality: { enabled: scannerList.includes('quality') },
            cve: { enabled: scannerList.includes('cve') },
          };
        }

        if (options.format) {
          cliOverrides.output = { format: options.format };
        }

        if (options.severity) {
          const severities = (options.severity as string).split(',');
          if (!cliOverrides.scanners) cliOverrides.scanners = {};
          (cliOverrides.scanners as Record<string, unknown>).security = { severity: severities };
        }

        if (options.include) {
          cliOverrides.paths = {
            ...(cliOverrides.paths as Record<string, unknown> || {}),
            include: (options.include as string).split(','),
          };
        }

        if (options.exclude) {
          cliOverrides.paths = {
            ...(cliOverrides.paths as Record<string, unknown> || {}),
            exclude: (options.exclude as string).split(','),
          };
        }

        if (options.deep) cliOverrides.deep = true;
        if (options.incremental) cliOverrides.incremental = true;
        if (options.parallel) cliOverrides.parallel = parseInt(options.parallel as string, 10);

        if (options.ai) {
          cliOverrides.ai = {
            enabled: true,
            provider: options.aiProvider || 'openai',
          };
        }

        if (options.rules) {
          cliOverrides.rules = { custom: [(options.rules as string)] };
        }

        // Load configuration
        const config = await loadConfig({
          configPath: options.config as string,
          targetPath: absolutePath,
          cliOverrides: cliOverrides as any,
          preset: options.preset as string,
        });

        // Override output format from CLI
        if (options.format) {
          config.output.format = options.format as OutputFormat;
        }

        // Create pipeline
        const pipeline = new ScanPipeline(config);

        // Register enabled scanners
        if (config.scanners.security.enabled) {
          pipeline.addScanner(new SecurityScanner());
        }
        if (config.scanners.quality.enabled) {
          pipeline.addScanner(new QualityScanner());
        }
        if (config.scanners.cve.enabled) {
          pipeline.addScanner(new CVEScanner());
        }

        // Run scan with progress
        const result = await pipeline.run({
          config,
          targetPath: absolutePath,
          onProgress: (current, total, file) => {
            if (config.output.format === 'console' && !options.quiet) {
              const pct = Math.round((current / total) * 100);
              process.stdout.write(`\r  Scanning... ${pct}% (${current}/${total}) ${file.slice(-50).padEnd(50)}`);
            }
          },
        });

        // Clear progress line
        if (config.output.format === 'console') {
          process.stdout.write('\r' + ' '.repeat(120) + '\r');
        }

        // Generate report
        const reporter = getReporter(config.output.format);
        const output = await reporter.generate(result);

        // Write to file or stdout
        if (options.output) {
          await reporter.writeToFile(result, options.output as string);
          consola.success(`Report written to: ${options.output}`);
        } else if (config.output.format !== 'console') {
          // For non-console formats, write to stdout
          process.stdout.write(output);
        } else {
          // Console format already printed
          process.stdout.write(output);
        }

        // Exit with error code if critical/error findings found
        const hasErrors = result.summary.bySeverity.critical > 0 || result.summary.bySeverity.high > 0;
        if (hasErrors) {
          process.exitCode = 1;
        }
      } catch (error) {
        consola.error('Scan failed:', error);
        process.exitCode = 2;
      }
    });

  return scan;
}
