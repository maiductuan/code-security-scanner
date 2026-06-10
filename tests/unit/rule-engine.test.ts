import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { resolve } from 'node:path';
import { writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { RuleEngine } from '../../src/rules/rule-engine.js';
import { DEFAULT_CONFIG } from '../../src/config/defaults.js';

describe('Rule Engine', () => {
  const testDir = resolve(process.cwd(), 'tests/scratch-rules-test');

  beforeEach(() => {
    try {
      mkdirSync(testDir, { recursive: true });
    } catch {
      // Ignore
    }
  });

  afterEach(() => {
    try {
      rmSync(testDir, { recursive: true, force: true });
    } catch {
      // Ignore
    }
  });

  it('should initialize and load built-in rules', async () => {
    const engine = new RuleEngine(DEFAULT_CONFIG);
    await engine.initialize();

    const rules = engine.getAllRules();
    expect(rules.length).toBeGreaterThan(0);
    
    // Check that we loaded SQL injection rule
    const sqlRule = engine.getRule('security/sql-injection');
    expect(sqlRule).toBeDefined();
    expect(sqlRule?.category).toBe('injection');
  });

  it('should filter rules by language', async () => {
    const engine = new RuleEngine(DEFAULT_CONFIG);
    await engine.initialize();

    // Check Javascript rules
    const jsRules = engine.getRulesForLanguage('javascript');
    expect(jsRules.length).toBeGreaterThan(0);
    expect(jsRules.some(r => r.id === 'security/sql-injection')).toBe(true);

    // Javascript should also match wildcard rules
    const wildcardRules = engine.getAllRules().filter(r => r.languages.includes('*'));
    for (const rule of wildcardRules) {
      expect(jsRules).toContain(rule);
    }
  });

  it('should filter rules by scanner type', async () => {
    const engine = new RuleEngine(DEFAULT_CONFIG);
    await engine.initialize();

    const securityRules = engine.getRulesForScanner('security');
    const qualityRules = engine.getRulesForScanner('quality');

    expect(securityRules.length).toBeGreaterThan(0);
    expect(qualityRules.length).toBeGreaterThan(0);

    expect(securityRules.some(r => r.id === 'security/sql-injection')).toBe(true);
    expect(qualityRules.some(r => r.id === 'quality/empty-catch')).toBe(true);
  });

  it('should respect exclude filters', async () => {
    const customConfig = {
      ...DEFAULT_CONFIG,
      rules: {
        include: ['*'],
        exclude: ['security/sql-injection', 'quality/*'],
        custom: []
      }
    };

    const engine = new RuleEngine(customConfig);
    await engine.initialize();

    expect(engine.getRule('security/sql-injection')).toBeUndefined();
    expect(engine.getRule('security/command-injection')).toBeDefined(); // Still exists
    
    const qualityRules = engine.getRulesForScanner('quality');
    expect(qualityRules.length).toBe(0); // All quality rules excluded by quality/*
  });

  it('should load custom rules from file', async () => {
    const customRuleFilePath = resolve(testDir, 'custom-rules.yml');
    writeFileSync(customRuleFilePath, `
rules:
  - id: custom/no-console-error
    name: No Console Error
    description: Prohibit console.error
    category: code-smells
    severity: medium
    confidence: high
    languages:
      - javascript
      - typescript
    patterns:
      - regex: console\\\\.error\\\\(
        message: Do not use console.error
`, 'utf-8');

    const customConfig = {
      ...DEFAULT_CONFIG,
      rules: {
        include: ['*'],
        exclude: [],
        custom: [customRuleFilePath]
      }
    };

    const engine = new RuleEngine(customConfig);
    await engine.initialize();

    const customRule = engine.getRule('custom/no-console-error');
    expect(customRule).toBeDefined();
    expect(customRule?.name).toBe('No Console Error');
    expect(customRule?.severity).toBe('medium');
  });
});
