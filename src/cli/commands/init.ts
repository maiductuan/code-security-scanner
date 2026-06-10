import { Command } from 'commander';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import yaml from 'js-yaml';
import { consola } from 'consola';
import { DEFAULT_CONFIG } from '../../config/defaults.js';

/**
 * Create the 'init' command
 * Usage: deepscan init
 */
export function createInitCommand(): Command {
  const init = new Command('init');

  init
    .description('Initialize a .deepscan.yml configuration file in the current directory')
    .option('--preset <name>', 'Use a preset: node-api, python-web, java-spring, minimal')
    .option('--format <format>', 'Config file format: yml, json', 'yml')
    .action(async (options: Record<string, string | undefined>) => {
      try {
        const config = {
          version: '1.0',
          scanners: {
            security: {
              enabled: true,
              severity: ['critical', 'high', 'medium', 'low'],
            },
            quality: {
              enabled: true,
              thresholds: {
                maxComplexity: 15,
                maxFileLength: 500,
                maxFunctionLength: 50,
              },
            },
            cve: {
              enabled: true,
              sources: ['osv'],
            },
          },
          rules: {
            include: ['*'],
            exclude: [],
            custom: [],
          },
          paths: {
            include: ['**/*'],
            exclude: [
              'node_modules/**',
              'dist/**',
              'build/**',
              '.git/**',
              'vendor/**',
            ],
          },
          output: {
            format: 'console',
          },
          ai: {
            enabled: false,
          },
        };

        const format = options.format || 'yml';
        const fileName = format === 'json' ? '.deepscan.json' : '.deepscan.yml';
        const filePath = resolve(process.cwd(), fileName);

        let content: string;
        if (format === 'json') {
          content = JSON.stringify(config, null, 2);
        } else {
          content = '# DeepScan Configuration\n# https://github.com/deepscan/deepscan-cli\n\n'
            + yaml.dump(config, { indent: 2, lineWidth: 100, quotingType: '"' });
        }

        writeFileSync(filePath, content, 'utf-8');
        consola.success(`Created ${fileName}`);
        consola.info('Customize the configuration and run: deepscan scan');
      } catch (error) {
        consola.error('Init failed:', error);
        process.exitCode = 1;
      }
    });

  return init;
}
