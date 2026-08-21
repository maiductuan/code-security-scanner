import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { getGitChangedFiles, discoverFiles } from '../../src/core/file-discovery.js';

describe('Git Incremental File Discovery', () => {
  it('should return null or set of files when querying git changed files', () => {
    const cwd = process.cwd();
    const result = getGitChangedFiles(cwd);
    // Either returns a set (if git repo) or null
    if (result !== null) {
      expect(result instanceof Set).toBe(true);
    }
  });

  it('should discover files without crashing when incremental is enabled', async () => {
    const cwd = process.cwd();
    const pathsConfig = {
      include: ['src/**/*.ts'],
      exclude: ['**/node_modules/**', 'dist/**'],
    };

    const files = await discoverFiles(cwd, pathsConfig, ['typescript'], true);
    expect(Array.isArray(files)).toBe(true);
  });
});
