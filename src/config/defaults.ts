import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import yaml from 'js-yaml';
import type { DeepScanConfig } from '../types/config.js';

/**
 * Resolve the path of a built-in resource (YAML files) across development and production
 */
export function resolveBuiltInPath(filename: string): string {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);

  const searchPaths = [
    resolve(__dirname, `../../rules/built-in/${filename}`), // from dist/bin/
    resolve(__dirname, `../rules/built-in/${filename}`),    // from dist/
    resolve(process.cwd(), `rules/built-in/${filename}`),   // in dev mode
  ];

  for (const p of searchPaths) {
    if (existsSync(p)) return p;
  }
  throw new Error(`Built-in resource not found: ${filename}`);
}

/**
 * Synchronously load the default configuration from YAML
 */
function loadDefaultConfig(): DeepScanConfig {
  try {
    const configPath = resolveBuiltInPath('default-config.yml');
    const content = readFileSync(configPath, 'utf-8');
    return yaml.load(content) as DeepScanConfig;
  } catch (error) {
    console.error('Failed to load default configuration from YAML:', error);
    // Hard fallback config in case resource loading completely fails
    return {
      version: '1.0',
      scanners: {
        security: { enabled: true, severity: ['critical', 'high', 'medium', 'low'] },
        quality: {
          enabled: true,
          thresholds: { maxComplexity: 15, maxCognitiveComplexity: 20, maxFileLength: 500, maxFunctionLength: 50, maxNestingDepth: 4, minCommentRatio: 0.1 }
        },
        cve: { enabled: true, sources: ['osv'], failOnSeverity: 'critical' }
      },
      rules: { include: ['*'], exclude: [], custom: [] },
      languages: ['auto'],
      paths: { include: ['**/*'], exclude: ['node_modules/', 'vendor/', 'dist/', 'build/', '.git/', '**/node_modules/**', '**/vendor/**', '**/dist/**', '**/build/**', '**/.git/**'] },
      output: { format: 'console', verbose: false, colors: true },
      ai: { enabled: false },
      context: { projectType: 'auto', frameworks: [], sensitivePatterns: [] }
    } as unknown as DeepScanConfig;
  }
}

export const DEFAULT_CONFIG = loadDefaultConfig();

/** Preset configurations for common project types */
export const PRESETS: Record<string, Partial<DeepScanConfig>> = {
  'node-api': {
    languages: ['javascript', 'typescript'],
    context: {
      projectType: 'api',
      frameworks: ['express', 'fastify', 'koa', 'nestjs'],
      sensitivePatterns: ['password', 'token', 'secret', 'api_key', 'authorization'],
    },
    paths: {
      include: ['src/**/*', 'lib/**/*', 'routes/**/*', 'controllers/**/*'],
      exclude: ['node_modules/', 'dist/', 'test/', '**/node_modules/**', '**/dist/**', '**/test/**', '**/*.test.*', '**/*.spec.*'],
    },
  },
  'python-web': {
    languages: ['python'],
    context: {
      projectType: 'web',
      frameworks: ['django', 'flask', 'fastapi'],
      sensitivePatterns: ['password', 'secret_key', 'database_url', 'api_key'],
    },
    paths: {
      include: ['**/*.py'],
      exclude: ['__pycache__/**', '.venv/**', 'venv/**', 'tests/**', 'test/**'],
    },
  },
  'java-spring': {
    languages: ['java'],
    context: {
      projectType: 'api',
      frameworks: ['spring', 'spring-boot'],
      sensitivePatterns: ['password', 'secret', 'credentials', 'apiKey'],
    },
    paths: {
      include: ['src/main/**/*.java'],
      exclude: ['target/**', 'src/test/**'],
    },
  },
  minimal: {
    scanners: {
      security: { enabled: true, severity: ['critical', 'high'] },
      quality: {
        enabled: false,
        thresholds: {
          maxComplexity: 15, maxCognitiveComplexity: 20,
          maxFileLength: 500, maxFunctionLength: 50,
          maxNestingDepth: 4, minCommentRatio: 0.1,
        },
      },
      cve: { enabled: false, sources: ['osv'] },
    },
  },
};
