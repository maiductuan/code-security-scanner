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
    .option('-s, --scanners <scanners>', 'Scanner engines to use (comma-separated: security,quality,cve) [default: security]')
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
    .option('--ai-provider <provider>', 'AI provider: openai, anthropic, ollama, google')
    .option('--rules <path>', 'Path to custom rules directory')
    .option('--parallel <n>', 'Number of parallel workers', '4')
    .option('--incremental', 'Only scan changed files (git-based)')
    .option('--preset <name>', 'Use a preset configuration (node-api, python-web, java-spring, minimal)')
    .option('--config <path>', 'Path to configuration file')
    .option('--cache', 'Enable local result caching (default: true)', true)
    .option('--no-cache', 'Disable local result caching')
    .option('--cache-dir <dir>', 'Path to cache directory')
    .option('--fail-on <severities>', 'Fail scan (exit code 1) on matching severities (comma-separated: critical,high,medium,low)')
    .option('-w, --watch', 'Watch files and automatically re-scan on change')
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
        if (options.cache === false) cliOverrides.cache = false;
        if (options.cacheDir) cliOverrides.cacheLocation = resolve(options.cacheDir as string, 'cache.json');
        if (options.failOn) cliOverrides.failOn = (options.failOn as string).split(',');
        if (options.watch) cliOverrides.watch = true;

        if (options.ai) {
          cliOverrides.ai = {
            enabled: true,
            provider: options.aiProvider || 'openai',
          };
        }

        if (options.rules) {
          cliOverrides.rules = { custom: [(options.rules as string)] };
        }

        const runScanIteration = async () => {
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
              if (!options.quiet && !options.watch) {
                const pct = Math.round((current / total) * 100);
                const fileDisplay = file.length > 50 ? '...' + file.slice(-47) : file;
                process.stderr.write(`\r  Scanning... ${pct}% (${current}/${total}) ${fileDisplay.padEnd(50)}`);
              }
            },
          });

          // Clear progress line
          if (!options.quiet && !options.watch) {
            process.stderr.write('\r' + ' '.repeat(120) + '\r');
          }

          // Generate report
          const reporter = getReporter(config.output.format);
          const output = await reporter.generate(result);

          // Write to file or stdout
          if (options.output) {
            await reporter.writeToFile(result, options.output as string);
            consola.success(`Report written to: ${options.output}`);
          } else if (config.output.format === 'html') {
            const defaultPath = 'report.html';
            await reporter.writeToFile(result, defaultPath);
            consola.success(`Report written to: ${defaultPath}`);
          } else if (config.output.format !== 'console') {
            // For non-console formats, write to stdout
            process.stdout.write(output);
          } else {
            // Console format already printed
            process.stdout.write(output);
          }

          // Check failure thresholds
          const failSeverities = config.failOn || ['critical', 'high'];
          const hasFailingFindings = failSeverities.some(sev => (result.summary.bySeverity[sev] || 0) > 0);

          if (hasFailingFindings) {
            process.exitCode = 1;
          } else {
            process.exitCode = 0;
          }

          return result;
        };

        // Execute initial scan
        await runScanIteration();

        // If watch mode is enabled, listen for file changes
        if (options.watch) {
          const { watch } = await import('node:fs');
          consola.info('👀 Watch mode active. Waiting for file changes (press Ctrl+C to stop)...');

          let debounceTimer: NodeJS.Timeout | null = null;
          let isScanning = false;

          try {
            watch(absolutePath, { recursive: true }, (eventType, filename) => {
              if (!filename) return;
              const norm = filename.replace(/\\/g, '/');
              if (
                norm.includes('node_modules') ||
                norm.includes('.git') ||
                norm.includes('.deepscan') ||
                norm.endsWith('.tmp') ||
                norm.endsWith('.log')
              ) {
                return;
              }

              if (debounceTimer) clearTimeout(debounceTimer);
              debounceTimer = setTimeout(async () => {
                if (isScanning) return;
                isScanning = true;
                console.log(`\n🔄 Change detected in ${filename}. Re-scanning...\n`);
                try {
                  await runScanIteration();
                } catch (err) {
                  consola.error('Scan error during watch:', err);
                } finally {
                  isScanning = false;
                }
              }, 300);
            });
          } catch (watchErr) {
            consola.warn('Recursive watch failed, falling back to non-recursive watch:', watchErr);
          }
        }
      } catch (error) {
        consola.error('Scan failed:', error);
        process.exitCode = 2;
      }
    });

  return scan;
}
