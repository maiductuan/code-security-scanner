import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { resolve } from 'node:path';
import { writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { loadConfig, deepMerge } from '../../src/config/loader.js';

describe('Config Loader', () => {
  const testDir = resolve(process.cwd(), 'tests/scratch-config-test');

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

  it('should deep merge objects correctly', () => {
    const target = {
      a: 1,
      b: { c: 2, d: 3 },
      e: [1, 2]
    };
    const source = {
      b: { d: 4 },
      f: 5
    };
    const merged = deepMerge(target, source);

    expect(merged.a).toBe(1);
    expect(merged.b.c).toBe(2);
    expect(merged.b.d).toBe(4);
    expect(merged.e).toEqual([1, 2]);
    expect(merged.f).toBe(5);
  });

  it('should load default config when no config file exists', async () => {
    // We pass configPath to a non-existent file to bypass parent directory scanning
    const config = await loadConfig({ 
      targetPath: testDir, 
      configPath: resolve(testDir, 'non-existent.yml') 
    });
    expect(config.version).toBe('1.0');
    expect(config.scanners.security.enabled).toBe(true);
    expect(config.scanners.quality.enabled).toBe(false);
  });

  it('should apply presets', async () => {
    const config = await loadConfig({ 
      targetPath: testDir, 
      configPath: resolve(testDir, 'non-existent.yml'),
      preset: 'minimal' 
    });
    expect(config.scanners.security.enabled).toBe(true);
    expect(config.scanners.quality.enabled).toBe(false);
  });

  it('should load config from yml file', async () => {
    const configFilePath = resolve(testDir, '.deepscan.yml');
    writeFileSync(configFilePath, `
version: "1.0"
scanners:
  security:
    enabled: false
  quality:
    enabled: false
`, 'utf-8');

    const config = await loadConfig({ 
      targetPath: testDir,
      configPath: configFilePath
    });
    expect(config.scanners.security.enabled).toBe(false);
    expect(config.scanners.quality.enabled).toBe(false);
  });

  it('should substitute environment variables', async () => {
    process.env.TEST_API_KEY = 'super-secret-key';
    const cliOverrides = {
      ai: {
        apiKey: '${TEST_API_KEY}',
        enabled: true,
        maxFindings: 10
      }
    };
    const config = await loadConfig({ 
      targetPath: testDir, 
      configPath: resolve(testDir, 'non-existent.yml'),
      cliOverrides: cliOverrides as any 
    });
    expect(config.ai.apiKey).toBe('super-secret-key');
    delete process.env.TEST_API_KEY;
  });
});
