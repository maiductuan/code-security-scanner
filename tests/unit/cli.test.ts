import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { existsSync, rmSync, readFileSync } from 'node:fs';
import { createScanCommand } from '../../src/cli/commands/scan.js';

describe('CLI Scan Command Options', () => {
  it('should parse --security option correctly', () => {
    const cmd = createScanCommand();
    // Simulate process.argv for command line arguments
    cmd.parse(['node', 'deepscan', 'scan', '--security']);
    const opts = cmd.opts();
    expect(opts.security).toBe(true);
    expect(opts.quality).toBeUndefined();
    expect(opts.cve).toBeUndefined();
  });

  it('should parse --quality and --cve options correctly', () => {
    const cmd = createScanCommand();
    cmd.parse(['node', 'deepscan', 'scan', '--quality', '--cve']);
    const opts = cmd.opts();
    expect(opts.security).toBeUndefined();
    expect(opts.quality).toBe(true);
    expect(opts.cve).toBe(true);
  });

  it('should automatically write HTML report to report.html when --format html is specified without output option', async () => {
    const reportPath = resolve(process.cwd(), 'report.html');
    if (existsSync(reportPath)) {
      rmSync(reportPath);
    }

    const cmd = createScanCommand();
    // Scan a small test directory to run fast
    await cmd.parseAsync(['node', 'deepscan', 'scan', './tests/fixtures', '--format', 'html', '--scanners', 'security']);

    expect(existsSync(reportPath)).toBe(true);
    const content = readFileSync(reportPath, 'utf-8');
    expect(content).toContain('<!DOCTYPE html>');
    expect(content).toContain('DeepScan Security Report');

    // Clean up
    rmSync(reportPath);
  });
});
