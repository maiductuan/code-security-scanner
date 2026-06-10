import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { convertSemgrepRules } from '../../scripts/convert-rules.js';
import { RuleFileSchema } from '../../src/config/schema.js';

describe('Semgrep Rule Converter', () => {
  const samplePath = resolve(process.cwd(), 'tests/fixtures/semgrep-sample.yml');

  it('should successfully convert Semgrep rules to DeepScan format', () => {
    const result = convertSemgrepRules(samplePath);

    expect(result).toBeDefined();
    expect(result.rules).toBeDefined();
    expect(result.rules.length).toBe(2);

    // Validate using Zod schema
    const validated = RuleFileSchema.parse(result);
    expect(validated.rules.length).toBe(2);

    // Assert on rule 1 (direct response write)
    const rule1 = validated.rules[0];
    expect(rule1.id).toBe('javascript.express.security.audit.xss.direct-response-write');
    expect(rule1.name).toBe('direct-response-write');
    expect(rule1.category).toBe('xss');
    expect(rule1.severity).toBe('high'); // ERROR -> high
    expect(rule1.languages).toContain('javascript');
    expect(rule1.patterns.length).toBe(1);
    expect(rule1.patterns[0].pattern).toBe('res.write(req.query.url)');
    expect(rule1.cwe).toContain('CWE-79');
    expect(rule1.owasp).toContain('A03:2021');

    // Assert on rule 2 (weak hash md5)
    const rule2 = validated.rules[1];
    expect(rule2.id).toBe('python.lang.security.audit.crypto.weak-hash-md5');
    expect(rule2.name).toBe('weak-hash-md5');
    expect(rule2.category).toBe('crypto');
    expect(rule2.severity).toBe('medium'); // WARNING -> medium
    expect(rule2.languages).toContain('python');
    expect(rule2.patterns.length).toBe(1);
    expect(rule2.patterns[0].regex).toBe('hashlib\\.md5\\(');
    expect(rule2.cwe).toContain('CWE-328');
    expect(rule2.owasp).toContain('A02:2021');
  });
});
