import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { resolve } from 'node:path';
import { writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { discoverFiles } from '../../src/core/file-discovery.js';

describe('File Discovery', () => {
  const testDir = resolve(process.cwd(), 'tests/scratch-file-test');

  beforeEach(() => {
    try {
      mkdirSync(testDir, { recursive: true });
      mkdirSync(resolve(testDir, 'src'), { recursive: true });
      mkdirSync(resolve(testDir, 'node_modules'), { recursive: true });
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

  it('should discover code files and ignore node_modules', async () => {
    // Create test files
    writeFileSync(resolve(testDir, 'src/main.js'), 'console.log("main");', 'utf-8');
    writeFileSync(resolve(testDir, 'src/helper.ts'), 'export const a = 1;', 'utf-8');
    writeFileSync(resolve(testDir, 'node_modules/bad.js'), 'console.log("bad");', 'utf-8');
    writeFileSync(resolve(testDir, 'src/data.bin'), 'binary data', 'utf-8'); // Binary/unknown

    const pathsConfig = {
      include: ['**/*'],
      exclude: ['node_modules/**']
    };

    const files = await discoverFiles(testDir, pathsConfig, ['javascript', 'typescript']);

    expect(files.length).toBe(2);
    
    const relPaths = files.map(f => f.relativePath.replace(/\\/g, '/'));
    expect(relPaths).toContain('src/main.js');
    expect(relPaths).toContain('src/helper.ts');
    expect(relPaths).not.toContain('node_modules/bad.js');
    expect(relPaths).not.toContain('src/data.bin');
  });

  it('should respect gitignore files', async () => {
    writeFileSync(resolve(testDir, 'src/main.js'), 'console.log("main");', 'utf-8');
    writeFileSync(resolve(testDir, 'src/ignored.js'), 'console.log("ignored");', 'utf-8');
    writeFileSync(resolve(testDir, '.gitignore'), 'src/ignored.js\n', 'utf-8');

    const pathsConfig = {
      include: ['**/*'],
      exclude: []
    };

    const files = await discoverFiles(testDir, pathsConfig, ['javascript']);
    const relPaths = files.map(f => f.relativePath.replace(/\\/g, '/'));

    expect(relPaths).toContain('src/main.js');
    expect(relPaths).not.toContain('src/ignored.js');
  });
});
