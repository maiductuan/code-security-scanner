import { describe, it, expect } from 'vitest';
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
});
