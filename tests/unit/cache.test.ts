import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { resolve } from 'node:path';
import { mkdirSync, rmSync, existsSync } from 'node:fs';
import { ScanCache } from '../../src/core/cache.js';
import type { Finding } from '../../src/types/finding.js';

function createMockFinding(ruleId: string): Finding {
  return {
    id: `sec-${ruleId}`,
    ruleId,
    scanner: 'security',
    severity: 'high',
    confidence: 'high',
    category: 'injection',
    title: 'Test finding',
    message: 'Test finding message',
    location: {
      file: 'src/app.js',
      startLine: 1,
      startColumn: 1,
      endLine: 1,
      endColumn: 10,
      snippet: 'const x = 1;',
      snippetStartLine: 1,
    },
    metadata: {
      fingerprint: `fp-${ruleId}`,
      timestamp: Date.now(),
      engineVersion: '1.0.0',
    },
  };
}

describe('ScanCache Manager', () => {
  const testDir = resolve(process.cwd(), 'tests/scratch-cache-test');

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

  it('should store and retrieve cached findings for matching content hash', () => {
    const cache = new ScanCache(testDir, true, undefined, 'rules-v1');
    cache.load();

    const content = 'console.log("hello");';
    const hash = ScanCache.hashContent(content);
    const mockFindings = [createMockFinding('SEC-LOG-01')];

    expect(cache.get('src/app.js', hash)).toBeNull();

    cache.set('src/app.js', hash, mockFindings);
    expect(cache.get('src/app.js', hash)).toEqual(mockFindings);

    // Save to disk
    cache.save();

    // Reload in a new cache instance
    const cache2 = new ScanCache(testDir, true, undefined, 'rules-v1');
    cache2.load();

    expect(cache2.get('src/app.js', hash)).toEqual(mockFindings);

    // Cache miss if content modified
    const modifiedHash = ScanCache.hashContent('console.log("world");');
    expect(cache2.get('src/app.js', modifiedHash)).toBeNull();
  });

  it('should invalidate cache when rules hash changes', () => {
    const cache = new ScanCache(testDir, true, undefined, 'rules-v1');
    cache.load();

    const content = 'const x = 1;';
    const hash = ScanCache.hashContent(content);
    cache.set('src/app.js', hash, [createMockFinding('SEC-01')]);
    cache.save();

    // Load with new ruleset hash
    const cacheWithNewRules = new ScanCache(testDir, true, undefined, 'rules-v2-updated');
    cacheWithNewRules.load();

    expect(cacheWithNewRules.get('src/app.js', hash)).toBeNull();
  });

  it('should bypass cache when disabled', () => {
    const cache = new ScanCache(testDir, false, undefined, 'rules-v1');
    cache.load();

    const content = 'const x = 1;';
    const hash = ScanCache.hashContent(content);
    cache.set('src/app.js', hash, [createMockFinding('SEC-01')]);

    expect(cache.get('src/app.js', hash)).toBeNull();
  });
});
