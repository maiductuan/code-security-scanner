import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { ScanPipeline } from '../../src/core/pipeline.js';
import { SecurityScanner } from '../../src/scanners/security/index.js';
import { QualityScanner } from '../../src/scanners/quality/index.js';
import { loadConfig } from '../../src/config/loader.js';

describe('DeepScan Integration Test', () => {
  const fixturesDir = resolve(process.cwd(), 'tests/fixtures');

  it('should run full scan on vulnerable-app.js and detect vulnerabilities/code smells', async () => {
    // Load config with security and quality enabled
    const config = await loadConfig({
      targetPath: fixturesDir,
      configPath: resolve(fixturesDir, 'non-existent.yml'), // Bypass parent .deepscan.yml loading if any
      cliOverrides: {
        scanners: {
          security: {
            enabled: true,
            severity: ['critical', 'high', 'medium', 'low']
          },
          quality: {
            enabled: true,
            thresholds: {
              maxComplexity: 15,
              maxCognitiveComplexity: 20,
              maxFileLength: 500,
              maxFunctionLength: 50,
              maxNestingDepth: 4,
              minCommentRatio: 0.1
            }
          },
          cve: {
            enabled: false,
            sources: ['osv']
          }
        }
      }
    });

    const pipeline = new ScanPipeline(config);
    pipeline.addScanner(new SecurityScanner());
    pipeline.addScanner(new QualityScanner());

    const result = await pipeline.run({
      targetPath: fixturesDir
    });

    expect(result.summary.filesScanned).toBe(1);
    expect(result.summary.totalFindings).toBeGreaterThan(0);

    const findings = result.findings;

    // Verify command injection
    const cmdInjections = findings.filter(f => f.ruleId === 'SEC-INJ-003' || f.ruleId === 'security/command-injection');
    expect(cmdInjections.length).toBeGreaterThan(0);
    expect(cmdInjections[0].location.file).toContain('vulnerable-app.js');

    // Verify secrets (API keys still fire in test files; password patterns are intentionally skipped)
    const secrets = findings.filter(f => f.ruleId === 'SEC-SEC-010' || f.ruleId === 'SEC-SEC-011' || f.ruleId === 'SEC-SEC-001' || f.ruleId === 'security/hardcoded-secret');
    expect(secrets.length).toBeGreaterThan(0);

    // Verify weak crypto
    const weakCrypto = findings.filter(f => f.ruleId === 'SEC-CRYPTO-001' || f.ruleId === 'security/weak-crypto');
    expect(weakCrypto.length).toBeGreaterThan(0);

    // Verify todo comments
    const todoComments = findings.filter(f => f.ruleId === 'QUA-SMELL-005' || f.ruleId === 'quality/todo-comment');
    expect(todoComments.length).toBeGreaterThan(0);

    // Verify SSRF
    const ssrfs = findings.filter(f => f.ruleId === 'SEC-SRF-001' || f.ruleId === 'security/ssrf');
    expect(ssrfs.length).toBeGreaterThan(0);

    // Verify CORS wildcard
    const cors = findings.filter(f => f.ruleId === 'SEC-COR-001' || f.ruleId === 'security/cors-wildcard');
    expect(cors.length).toBeGreaterThan(0);

    // Verify Missing Rate Limiting
    const rateLimits = findings.filter(f => f.ruleId === 'SEC-RAT-001' || f.ruleId === 'security/missing-rate-limit');
    expect(rateLimits.length).toBeGreaterThan(0);
  });
});
