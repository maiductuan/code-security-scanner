import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import yaml from 'js-yaml';
import { consola } from 'consola';
import { DeepScanConfigSchema } from './schema.js';
import { DEFAULT_CONFIG, PRESETS } from './defaults.js';
import type { DeepScanConfig } from '../types/config.js';

/** Config file names to search for (in priority order) */
const CONFIG_FILES = [
  '.deepscan.yml',
  '.deepscan.yaml',
  '.deepscan.json',
  '.deepscan.config.js',
  'deepscan.config.yml',
  'deepscan.config.yaml',
  'deepscan.config.json',
];

/**
 * Load and merge configuration from multiple sources.
 * Priority: CLI args > project config file > preset > defaults
 */
export async function loadConfig(options: {
  configPath?: string;
  targetPath?: string;
  cliOverrides?: Partial<DeepScanConfig>;
  preset?: string;
}): Promise<DeepScanConfig> {
  const { configPath, targetPath, cliOverrides, preset } = options;

  // Step 1: Start with defaults
  let config: Record<string, unknown> = structuredClone(DEFAULT_CONFIG) as unknown as Record<string, unknown>;

  // Step 2: Apply preset if specified
  if (preset && PRESETS[preset]) {
    config = deepMerge(config, PRESETS[preset] as Record<string, unknown>);
    consola.debug(`Applied preset: ${preset}`);
  }

  // Step 3: Load project config file
  const projectConfig = await loadProjectConfig(configPath, targetPath);
  if (projectConfig) {
    config = deepMerge(config, projectConfig);
    consola.debug(`Loaded config from file`);
  }

  // Step 4: Apply CLI overrides
  if (cliOverrides) {
    config = deepMerge(config, cliOverrides as Record<string, unknown>);
  }

  // Step 5: Resolve environment variables
  config = resolveEnvVars(config);

  // Step 6: Validate with Zod
  const validated = DeepScanConfigSchema.parse(config);

  return validated as DeepScanConfig;
}

/**
 * Find and load project configuration file
 */
async function loadProjectConfig(
  explicitPath?: string,
  targetPath?: string,
): Promise<Record<string, unknown> | null> {
  // If explicit path provided, use it
  if (explicitPath) {
    if (!existsSync(explicitPath)) {
      consola.warn(`Config file not found: ${explicitPath}`);
      return null;
    }
    return parseConfigFile(explicitPath);
  }

  // Search for config file in target directory and parents
  const searchDir = targetPath ? resolve(targetPath) : process.cwd();
  const configPath = findConfigFile(searchDir);

  if (configPath) {
    return parseConfigFile(configPath);
  }

  return null;
}

/**
 * Search for config file in directory and parent directories
 */
function findConfigFile(startDir: string): string | null {
  let currentDir = startDir;

  // Traverse up to 10 levels
  for (let i = 0; i < 10; i++) {
    for (const fileName of CONFIG_FILES) {
      const filePath = resolve(currentDir, fileName);
      if (existsSync(filePath)) {
        return filePath;
      }
    }

    const parentDir = dirname(currentDir);
    if (parentDir === currentDir) break; // Reached root
    currentDir = parentDir;
  }

  return null;
}

/**
 * Parse a configuration file (YAML or JSON)
 */
function parseConfigFile(filePath: string): Record<string, unknown> | null {
  try {
    const content = readFileSync(filePath, 'utf-8');

    if (filePath.endsWith('.json')) {
      return JSON.parse(content);
    }

    if (filePath.endsWith('.yml') || filePath.endsWith('.yaml')) {
      return yaml.load(content) as Record<string, unknown>;
    }

    consola.warn(`Unsupported config format: ${filePath}`);
    return null;
  } catch (error) {
    consola.error(`Failed to parse config file: ${filePath}`, error);
    return null;
  }
}

/**
 * Deep merge two objects (source overrides target)
 */
function deepMerge(
  target: Record<string, unknown>,
  source: Record<string, unknown>,
): Record<string, unknown> {
  const result = { ...target };

  for (const key of Object.keys(source)) {
    const sourceVal = source[key];
    const targetVal = target[key];

    if (
      sourceVal !== null &&
      typeof sourceVal === 'object' &&
      !Array.isArray(sourceVal) &&
      targetVal !== null &&
      typeof targetVal === 'object' &&
      !Array.isArray(targetVal)
    ) {
      result[key] = deepMerge(
        targetVal as Record<string, unknown>,
        sourceVal as Record<string, unknown>,
      );
    } else {
      result[key] = sourceVal;
    }
  }

  return result;
}

/**
 * Resolve environment variable references in config values.
 * Supports ${ENV_VAR} and ${ENV_VAR:default} syntax.
 */
function resolveEnvVars(obj: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(obj)) {
    if (typeof value === 'string') {
      result[key] = value.replace(
        /\$\{(\w+)(?::([^}]*))?\}/g,
        (_match, envName: string, defaultVal?: string) => {
          return process.env[envName] ?? defaultVal ?? '';
        },
      );
    } else if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      result[key] = resolveEnvVars(value as Record<string, unknown>);
    } else {
      result[key] = value;
    }
  }

  return result;
}

export { findConfigFile, parseConfigFile, deepMerge };
