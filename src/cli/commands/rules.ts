import { Command } from 'commander';
import { consola } from 'consola';
import chalk from 'chalk';
import { RuleEngine } from '../../rules/rule-engine.js';
import { DEFAULT_CONFIG } from '../../config/defaults.js';
import type { DeepScanConfig } from '../../types/config.js';
import { RULE_CATEGORIES } from '../../types/rule.js';

/**
 * Create the 'rules' command group
 * Usage: deepscan rules list|info
 */
export function createRulesCommand(): Command {
  const rules = new Command('rules');
  rules.description('Manage and inspect scanning rules');

  // Subcommand: list
  rules
    .command('list')
    .description('List all available rules')
    .option('-c, --category <category>', 'Filter by category')
    .option('-s, --severity <severity>', 'Filter by severity')
    .option('-l, --language <language>', 'Filter by language')
    .option('--scanner <type>', 'Filter by scanner type (security, quality)')
    .action(async (options: Record<string, string | undefined>) => {
      try {
        const ruleEngine = new RuleEngine(DEFAULT_CONFIG as DeepScanConfig);
        await ruleEngine.initialize();

        let allRules = ruleEngine.getAllRules();

        // Apply filters
        if (options.category) {
          allRules = allRules.filter(r => r.category === options.category);
        }
        if (options.severity) {
          allRules = allRules.filter(r => r.severity === options.severity);
        }
        if (options.language) {
          allRules = allRules.filter(r => r.languages.includes(options.language!) || r.languages.includes('*'));
        }
        if (options.scanner) {
          const secCategories = ['injection', 'xss', 'secrets', 'auth', 'crypto', 'file-ops'];
          if (options.scanner === 'security') {
            allRules = allRules.filter(r => secCategories.includes(r.category));
          } else {
            allRules = allRules.filter(r => !secCategories.includes(r.category));
          }
        }

        // Display results
        console.log(chalk.bold(`\n📋 DeepScan Rules (${allRules.length} rules)\n`));

        const severityColors: Record<string, (s: string) => string> = {
          critical: chalk.bgRed.white,
          error: chalk.red,
          warning: chalk.yellow,
          info: chalk.blue,
        };

        for (const rule of allRules) {
          const sevColor = severityColors[rule.severity] || chalk.white;
          const id = chalk.cyan(rule.id.padEnd(35));
          const sev = sevColor(rule.severity.padEnd(10));
          const langs = chalk.gray(rule.languages.join(', '));
          console.log(`  ${id} ${sev} ${rule.name}`);
          console.log(`  ${' '.repeat(35)} ${chalk.dim(rule.description.slice(0, 80))}`);
          console.log(`  ${' '.repeat(35)} Languages: ${langs}`);
          console.log();
        }
      } catch (error) {
        consola.error('Failed to list rules:', error);
      }
    });

  // Subcommand: info
  rules
    .command('info <ruleId>')
    .description('Show detailed information about a specific rule')
    .action(async (ruleId: string) => {
      try {
        const ruleEngine = new RuleEngine(DEFAULT_CONFIG as DeepScanConfig);
        await ruleEngine.initialize();

        const rule = ruleEngine.getRule(ruleId);
        if (!rule) {
          consola.error(`Rule not found: ${ruleId}`);
          return;
        }

        console.log(chalk.bold(`\n🔍 Rule: ${rule.id}\n`));
        console.log(`  ${chalk.bold('Name:')}        ${rule.name}`);
        console.log(`  ${chalk.bold('Category:')}    ${rule.category}`);
        console.log(`  ${chalk.bold('Severity:')}    ${rule.severity}`);
        console.log(`  ${chalk.bold('Confidence:')}  ${rule.confidence}`);
        console.log(`  ${chalk.bold('Languages:')}   ${rule.languages.join(', ')}`);
        console.log(`  ${chalk.bold('Description:')} ${rule.description}`);

        if (rule.cwe?.length) {
          console.log(`  ${chalk.bold('CWE:')}         ${rule.cwe.join(', ')}`);
        }
        if (rule.owasp?.length) {
          console.log(`  ${chalk.bold('OWASP:')}       ${rule.owasp.join(', ')}`);
        }
        if (rule.fix) {
          console.log(`  ${chalk.bold('Fix:')}         ${rule.fix.description}`);
        }
        if (rule.references?.length) {
          console.log(`  ${chalk.bold('References:')}`);
          for (const ref of rule.references) {
            console.log(`    - ${chalk.underline(ref)}`);
          }
        }
        if (rule.tags?.length) {
          console.log(`  ${chalk.bold('Tags:')}        ${rule.tags.join(', ')}`);
        }
        console.log();
      } catch (error) {
        consola.error('Failed to get rule info:', error);
      }
    });

  // Subcommand: categories
  rules
    .command('categories')
    .description('List all rule categories')
    .action(async () => {
      console.log(chalk.bold('\n📂 Rule Categories\n'));
      for (const cat of RULE_CATEGORIES) {
        const scanner = cat.scanner === 'security' ? chalk.red('🛡 Security') : chalk.blue('📊 Quality');
        console.log(`  ${chalk.cyan(cat.id.padEnd(20))} ${scanner}  ${cat.name}`);
        console.log(`  ${' '.repeat(20)}          ${chalk.dim(cat.description)}`);
        console.log();
      }
    });

  return rules;
}
