import { Command } from 'commander';
import { createScanCommand } from './commands/scan.js';
import { createInitCommand } from './commands/init.js';
import { createRulesCommand } from './commands/rules.js';
import { createReportCommand } from './commands/report.js';

const VERSION = '1.0.0';

/**
 * Create the DeepScan CLI application
 */
export function createCLI(): Command {
  const program = new Command();

  program
    .name('deepscan')
    .description('🔍 DeepScan - Open-source security & code quality scanner')
    .version(VERSION, '-v, --version', 'Display version number')
    .option('--config <path>', 'Path to configuration file')
    .option('--verbose', 'Enable verbose output')
    .option('--quiet', 'Suppress all output except errors')
    .option('--no-color', 'Disable colored output');

  // Register commands
  program.addCommand(createScanCommand());
  program.addCommand(createInitCommand());
  program.addCommand(createRulesCommand());
  program.addCommand(createReportCommand());

  // Default action (no subcommand) → show help
  program.action(() => {
    program.outputHelp();
  });

  return program;
}
