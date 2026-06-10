import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { resolve, join, extname } from 'node:path';
import yaml from 'js-yaml';
import { consola } from 'consola';
import { RuleFileSchema } from '../config/schema.js';
import type { Rule, RuleFile } from '../types/rule.js';
import type { DeepScanConfig } from '../types/config.js';
import { resolveBuiltInPath } from '../config/defaults.js';

/**
 * Rule Engine - loads, validates, filters, and manages rules
 */
export class RuleEngine {
  private rules: Map<string, Rule> = new Map();
  private config: DeepScanConfig;

  constructor(config: DeepScanConfig) {
    this.config = config;
  }

  /**
   * Initialize the rule engine by loading built-in and custom rules
   */
  async initialize(): Promise<void> {
    // Load built-in rules
    await this.loadBuiltInRules();

    // Load custom rules
    for (const customPath of this.config.rules.custom) {
      await this.loadRulesFromPath(resolve(customPath));
    }

    // Apply include/exclude filters
    this.applyFilters();

    consola.info(`Loaded ${this.rules.size} rules`);
  }

  /**
   * Get all active rules
   */
  getAllRules(): Rule[] {
    return Array.from(this.rules.values()).filter(r => r.enabled !== false);
  }

  /**
   * Get rules for a specific language
   */
  getRulesForLanguage(language: string): Rule[] {
    return this.getAllRules().filter(
      r => r.languages.includes(language) || r.languages.includes('*')
    );
  }

  /**
   * Get rules for a specific scanner type
   */
  getRulesForScanner(scannerType: 'security' | 'quality'): Rule[] {
    return this.getAllRules().filter(r => {
      const category = r.category;
      if (scannerType === 'security') {
        return ['injection', 'xss', 'secrets', 'auth', 'crypto', 'file-ops'].includes(category);
      }
      return ['complexity', 'duplication', 'code-smells', 'naming', 'metrics'].includes(category);
    });
  }

  /**
   * Get a specific rule by ID
   */
  getRule(id: string): Rule | undefined {
    return this.rules.get(id);
  }

  /**
   * Load built-in rules from the rules directory
   */
  private async loadBuiltInRules(): Promise<void> {
    try {
      const securityRulesPath = resolveBuiltInPath('security.yml');
      const qualityRulesPath = resolveBuiltInPath('quality.yml');

      await this.loadRuleFile(securityRulesPath);
      await this.loadRuleFile(qualityRulesPath);
    } catch (error) {
      consola.error('Failed to load built-in rules from YAML files:', error);
    }
  }

  /**
   * Load rules from a file or directory
   */
  private async loadRulesFromPath(rulesPath: string): Promise<void> {
    if (!existsSync(rulesPath)) {
      consola.warn(`Rules path not found: ${rulesPath}`);
      return;
    }

    try {
      const stat = statSync(rulesPath);

      if (stat.isDirectory()) {
        const files = readdirSync(rulesPath);
        for (const file of files) {
          if (file.endsWith('.yml') || file.endsWith('.yaml')) {
            await this.loadRuleFile(join(rulesPath, file));
          }
        }
      } else {
        await this.loadRuleFile(rulesPath);
      }
    } catch (error) {
      consola.error(`Failed to load rules from: ${rulesPath}`, error);
    }
  }

  /**
   * Load and validate a single rule YAML file
   */
  private async loadRuleFile(filePath: string): Promise<void> {
    try {
      const content = readFileSync(filePath, 'utf-8');
      const raw = yaml.load(content) as Record<string, unknown>;
      const validated = RuleFileSchema.parse(raw);

      for (const rule of validated.rules) {
        if (this.rules.has(rule.id)) {
          consola.debug(`Rule ${rule.id} overridden by: ${filePath}`);
        }
        this.rules.set(rule.id, rule as Rule);
      }

      consola.debug(`Loaded ${validated.rules.length} rules from: ${filePath}`);
    } catch (error) {
      consola.error(`Failed to parse rule file: ${filePath}`, error);
    }
  }

  /**
   * Apply include/exclude filters from configuration
   */
  private applyFilters(): void {
    const { include, exclude } = this.config.rules;

    // If include is not wildcard, filter to only included rules
    if (include.length > 0 && !include.includes('*')) {
      for (const [id] of this.rules) {
        const matches = include.some(pattern => matchRulePattern(id, pattern));
        if (!matches) {
          this.rules.delete(id);
        }
      }
    }

    // Remove excluded rules
    for (const pattern of exclude) {
      for (const [id] of this.rules) {
        if (matchRulePattern(id, pattern)) {
          this.rules.delete(id);
        }
      }
    }
  }
}

/**
 * Match a rule ID against a pattern (supports wildcards and category prefixes)
 */
function matchRulePattern(ruleId: string, pattern: string): boolean {
  if (pattern === '*') return true;
  if (pattern === ruleId) return true;

  // Support category prefix: "security/*" matches "security/sql-injection"
  if (pattern.endsWith('/*')) {
    const prefix = pattern.slice(0, -2);
    return ruleId.startsWith(prefix + '/');
  }

  // Support glob-like matching
  const regex = new RegExp(
    '^' + pattern.replace(/\*/g, '.*').replace(/\?/g, '.') + '$'
  );
  return regex.test(ruleId);
}

// ─── Rule Engine Helpers ──────────────────────────────────────────────────

export { matchRulePattern };
