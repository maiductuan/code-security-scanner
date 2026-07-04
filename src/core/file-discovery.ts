import { readFileSync, statSync } from 'node:fs';
import { resolve, relative, extname, basename } from 'node:path';
import { glob } from 'glob';
import ignore, { type Ignore } from 'ignore';
import { consola } from 'consola';
import type { DiscoveredFile } from '../types/scanner.js';
import type { PathsConfig } from '../types/config.js';
import { getLanguageByExtension } from '../languages/registry.js';

/** Dependency manifest files that trigger CVE scanning */
const DEPENDENCY_FILES = new Set([
  'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
  'requirements.txt', 'Pipfile', 'Pipfile.lock', 'poetry.lock', 'setup.py', 'setup.cfg', 'pyproject.toml',
  'pom.xml', 'build.gradle', 'build.gradle.kts', 'gradle.lockfile',
  'go.mod', 'go.sum',
  'Cargo.toml', 'Cargo.lock',
  'Gemfile', 'Gemfile.lock',
  'composer.json', 'composer.lock',
  'packages.config', 'Directory.Packages.props',
]);

/** Lock files — should be scanned for CVE but NOT for security patterns */
const LOCK_FILES = new Set([
  'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
  'Pipfile.lock', 'poetry.lock', 'composer.lock',
  'Cargo.lock', 'Gemfile.lock', 'gradle.lockfile',
  'go.sum',
]);

/** Vendor/third-party directory patterns */
const VENDOR_DIR_PATTERN = /(?:^|[\\/])(?:vendor|third[_-]?party|bower_components|externals?)[\\/]/i;

/** Known vendor/bundled files by filename */
const KNOWN_VENDOR_FILES_PATTERN = /(?:jquery|lodash|underscore|backbone|angular|react\.production|vue\.global|bootstrap|popper|moment(?:\.min)?|d3|select2|sweetalert|highlight|firebug)(?:[\.-][\w.]+)?\.js$/i;

/** Minified file patterns */
const MINIFIED_PATTERN = /\.min\.(?:js|css)$/i;

/** Test file/directory patterns */
const TEST_PATH_PATTERN = /(?:^|[\\/])(?:tests?|__tests__|spec|__spec__|fixtures?|mocks?|__mocks__|e2e|integration|cypress|playwright)[\\/]/i;
const TEST_FILE_PATTERN = /\.(?:test|spec|mock|fixture|e2e|cy)\./i;

function classifyFile(relPath: string, name: string): {
  isLockFile: boolean;
  isVendorFile: boolean;
  isMinified: boolean;
  isTestFile: boolean;
} {
  return {
    isLockFile: LOCK_FILES.has(name),
    isVendorFile: VENDOR_DIR_PATTERN.test(relPath) || KNOWN_VENDOR_FILES_PATTERN.test(name),
    isMinified: MINIFIED_PATTERN.test(name),
    isTestFile: TEST_PATH_PATTERN.test(relPath) || TEST_FILE_PATTERN.test(name),
  };
}

/** Binary/generated file extensions to always skip */
const SKIP_EXTENSIONS = new Set([
  '.exe', '.dll', '.so', '.dylib', '.o', '.obj', '.class',
  '.jar', '.war', '.ear', '.zip', '.tar', '.gz', '.rar',
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.bmp', '.webp',
  '.mp3', '.mp4', '.wav', '.avi', '.mov', '.wmv',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.pyc', '.pyo', '.wasm',
]);

/**
 * Discover all files to scan in the target directory
 */
export async function discoverFiles(
  targetPath: string,
  paths: PathsConfig,
  languages: string[],
): Promise<DiscoveredFile[]> {
  const absoluteTarget = resolve(targetPath);

  // If targetPath is a file, return it directly if it matches language and size limits
  try {
    const stat = statSync(absoluteTarget);
    if (stat.isFile()) {
      const ext = extname(absoluteTarget).toLowerCase();
      const name = basename(absoluteTarget);
      
      // Skip binary files
      if (SKIP_EXTENSIONS.has(ext)) {
        return [];
      }
      
      const language = getLanguageByExtension(ext);
      if (!language && !DEPENDENCY_FILES.has(name)) {
        return [];
      }

      // Filter by configured languages
      if (
        languages.length > 0 &&
        !languages.includes('auto') &&
        language &&
        !languages.includes(language)
      ) {
        return [];
      }

      // Skip very large files (>5MB)
      if (stat.size > 5 * 1024 * 1024) {
        consola.debug(`Skipping large file: ${name} (${(stat.size / 1024 / 1024).toFixed(1)}MB)`);
        return [];
      }

      consola.info(`Discovered 1 file to scan`);
      const classification = classifyFile(name, name);
      return [{
        path: absoluteTarget,
        relativePath: name,
        language: language || 'unknown',
        size: stat.size,
        isDependencyFile: DEPENDENCY_FILES.has(name),
        ...classification,
      }];
    }
  } catch {
    // If file/directory doesn't exist, proceed to globbing which will handle/log
  }

  // Load .gitignore and .deepscanignore
  const ig = ignore();
  loadIgnoreFile(absoluteTarget, '.gitignore', ig);
  loadIgnoreFile(absoluteTarget, '.deepscanignore', ig);

  // Add configured exclude patterns
  for (const pattern of paths.exclude) {
    ig.add(pattern);
  }

  // Find all matching files
  const files = await glob(paths.include, {
    cwd: absoluteTarget,
    nodir: true,
    dot: false,
    absolute: false,
  });

  const discovered: DiscoveredFile[] = [];

  for (const relPath of files) {
    // Check ignore patterns
    if (ig.ignores(relPath)) continue;

    const ext = extname(relPath).toLowerCase();
    const name = basename(relPath);
    const absPath = resolve(absoluteTarget, relPath);

    // Skip binary files
    if (SKIP_EXTENSIONS.has(ext)) continue;

    // Detect language
    const language = getLanguageByExtension(ext);
    if (!language && !DEPENDENCY_FILES.has(name)) continue;

    // Filter by configured languages
    if (
      languages.length > 0 &&
      !languages.includes('auto') &&
      language &&
      !languages.includes(language)
    ) {
      continue;
    }

    // Get file size
    let size = 0;
    try {
      const stat = statSync(absPath);
      size = stat.size;

      // Skip very large files (>5MB)
      if (size > 5 * 1024 * 1024) {
        consola.debug(`Skipping large file: ${relPath} (${(size / 1024 / 1024).toFixed(1)}MB)`);
        continue;
      }
    } catch {
      continue;
    }

    const classification = classifyFile(relPath, name);
    discovered.push({
      path: absPath,
      relativePath: relPath,
      language: language || 'unknown',
      size,
      isDependencyFile: DEPENDENCY_FILES.has(name),
      ...classification,
    });
  }

  consola.info(`Discovered ${discovered.length} files to scan`);
  return discovered;
}

/**
 * Load an ignore file (.gitignore or .deepscanignore)
 */
function loadIgnoreFile(
  dir: string,
  fileName: string,
  ig: Ignore,
): void {
  try {
    const filePath = resolve(dir, fileName);
    const content = readFileSync(filePath, 'utf-8');
    ig.add(content);
  } catch {
    // File doesn't exist, skip
  }
}

/**
 * Read file content safely
 */
export function readFileContent(filePath: string): string | null {
  try {
    return readFileSync(filePath, 'utf-8');
  } catch (error) {
    consola.debug(`Failed to read file: ${filePath}`, error);
    return null;
  }
}
