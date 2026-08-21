import { describe, it, expect } from 'vitest';
import { parseSuppressions, isFindingSuppressed, filterSuppressedFindings } from '../../src/core/suppression.js';
import type { Finding } from '../../src/types/finding.js';

function createMockFinding(line: number, ruleId: string): Finding {
  return {
    id: `sec-${ruleId}-${line}`,
    ruleId,
    scanner: 'security',
    severity: 'high',
    confidence: 'high',
    category: 'injection',
    title: 'Test finding',
    message: 'Test finding message',
    location: {
      file: 'test.js',
      startLine: line,
      startColumn: 1,
      endLine: line,
      endColumn: 10,
      snippet: 'const x = 1;',
      snippetStartLine: line,
    },
    metadata: {
      fingerprint: `fp-${ruleId}-${line}`,
      timestamp: Date.now(),
      engineVersion: '1.0.0',
    },
  };
}

describe('Inline Suppression Parser & Filter', () => {
  it('should parse disable-next-line comment for a specific rule', () => {
    const code = `
const a = 1;
// deepscan-disable-next-line SEC-SQL-01
const query = "SELECT * FROM users WHERE id = " + id;
    `.trim();

    const directives = parseSuppressions(code);
    expect(directives.length).toBe(1);
    expect(directives[0]).toEqual({
      type: 'next-line',
      line: 2,
      ruleIds: ['SEC-SQL-01'],
    });

    const finding1 = createMockFinding(3, 'SEC-SQL-01');
    const finding2 = createMockFinding(3, 'SEC-XSS-01');

    expect(isFindingSuppressed(finding1, directives)).toBe(true);
    expect(isFindingSuppressed(finding2, directives)).toBe(false);
  });

  it('should parse current line suppression', () => {
    const code = `
const secret = "AKIA1234567890123456"; // deepscan-disable-line
    `.trim();

    const directives = parseSuppressions(code);
    expect(directives.length).toBe(1);
    expect(directives[0].type).toBe('current-line');
    expect(directives[0].line).toBe(1);

    const finding = createMockFinding(1, 'SEC-SECRET-AWS');
    expect(isFindingSuppressed(finding, directives)).toBe(true);
  });

  it('should support python style # comments and multi-rule suppression', () => {
    const code = `
# deepscan-disable-next-line SEC-SQL-01, SEC-CMD-01
os.system(cmd)
    `.trim();

    const directives = parseSuppressions(code);
    expect(directives.length).toBe(1);
    expect(directives[0].ruleIds).toContain('SEC-SQL-01');
    expect(directives[0].ruleIds).toContain('SEC-CMD-01');

    const finding = createMockFinding(2, 'SEC-CMD-01');
    expect(isFindingSuppressed(finding, directives)).toBe(true);
  });

  it('should support block disable and enable directives', () => {
    const code = `
/* deepscan-disable SEC-CRYPTO-MD5 */
const hash1 = md5(data);
const hash2 = md5(data2);
/* deepscan-enable SEC-CRYPTO-MD5 */
const hash3 = md5(data3);
    `.trim();

    const directives = parseSuppressions(code);
    expect(directives.length).toBe(2);

    const finding2 = createMockFinding(2, 'SEC-CRYPTO-MD5');
    const finding3 = createMockFinding(3, 'SEC-CRYPTO-MD5');
    const finding5 = createMockFinding(5, 'SEC-CRYPTO-MD5');

    expect(isFindingSuppressed(finding2, directives)).toBe(true);
    expect(isFindingSuppressed(finding3, directives)).toBe(true);
    expect(isFindingSuppressed(finding5, directives)).toBe(false);
  });

  it('should filter an array of findings accurately', () => {
    const code = `
// deepscan-disable-next-line
const bad1 = eval(userInput);
const bad2 = eval(userInput2);
    `.trim();

    const findings = [
      createMockFinding(2, 'SEC-EVAL-01'),
      createMockFinding(3, 'SEC-EVAL-01'),
    ];

    const result = filterSuppressedFindings(findings, code);
    expect(result.length).toBe(1);
    expect(result[0].location.startLine).toBe(3);
  });
});
