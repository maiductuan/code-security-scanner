import { readFileSync, writeFileSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve, dirname } from 'node:path';
import { consola } from 'consola';
import type { Finding } from '../types/finding.js';

interface CacheEntry {
  hash: string;
  timestamp: number;
  findings: Finding[];
}

interface CacheData {
  version: string;
  rulesHash: string;
  entries: Record<string, CacheEntry>;
}

export class ScanCache {
  private cachePath: string;
  private enabled: boolean;
  private rulesHash: string;
  private data: CacheData;
  private dirty: boolean = false;

  constructor(targetDir: string, enabled: boolean = true, customLocation?: string, rulesHash: string = '') {
    this.enabled = enabled;
    this.rulesHash = rulesHash;
    this.cachePath = customLocation
      ? resolve(customLocation)
      : resolve(targetDir, '.deepscan', 'cache.json');
    this.data = {
      version: '1.1.0',
      rulesHash: this.rulesHash,
      entries: {},
    };
  }

  /**
   * Compute SHA-256 hash of a string content
   */
  static hashContent(content: string): string {
    return createHash('sha256').update(content).digest('hex');
  }

  /**
   * Load cache from disk
   */
  load(): void {
    if (!this.enabled) return;

    try {
      if (existsSync(this.cachePath)) {
        const raw = readFileSync(this.cachePath, 'utf-8');
        const parsed = JSON.parse(raw) as CacheData;

        // Invalidate cache if rules have changed
        if (this.rulesHash && parsed.rulesHash !== this.rulesHash) {
          consola.debug('Rules changed - invalidating scan cache');
          this.data = {
            version: '1.1.0',
            rulesHash: this.rulesHash,
            entries: {},
          };
          this.dirty = true;
          return;
        }

        this.data = parsed;
        consola.debug(`Loaded scan cache with ${Object.keys(parsed.entries).length} entries`);
      }
    } catch (error) {
      consola.debug('Failed to load scan cache, initializing empty cache:', error);
      this.data = {
        version: '1.1.0',
        rulesHash: this.rulesHash,
        entries: {},
      };
    }
  }

  /**
   * Get cached findings for a file if hash matches
   */
  get(relativePath: string, currentContentHash: string): Finding[] | null {
    if (!this.enabled) return null;

    const entry = this.data.entries[relativePath];
    if (!entry) return null;

    if (entry.hash === currentContentHash) {
      return entry.findings;
    }

    return null;
  }

  /**
   * Set findings for a file
   */
  set(relativePath: string, contentHash: string, findings: Finding[]): void {
    if (!this.enabled) return;

    this.data.entries[relativePath] = {
      hash: contentHash,
      timestamp: Date.now(),
      findings,
    };
    this.dirty = true;
  }

  /**
   * Save cache to disk
   */
  save(): void {
    if (!this.enabled || !this.dirty) return;

    try {
      const dir = dirname(this.cachePath);
      if (!existsSync(dir)) {
        mkdirSync(dir, { recursive: true });
      }
      this.data.rulesHash = this.rulesHash;
      writeFileSync(this.cachePath, JSON.stringify(this.data, null, 2), 'utf-8');
      this.dirty = false;
      consola.debug(`Saved scan cache to ${this.cachePath}`);
    } catch (error) {
      consola.debug('Failed to save scan cache:', error);
    }
  }

  /**
   * Clear cache
   */
  clear(): void {
    this.data.entries = {};
    this.dirty = false;
    try {
      if (existsSync(this.cachePath)) {
        rmSync(this.cachePath, { force: true });
      }
    } catch {
      // Ignore
    }
  }
}
