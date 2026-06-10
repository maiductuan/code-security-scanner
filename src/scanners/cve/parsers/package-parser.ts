import { basename } from 'node:path';

/**
 * Dependency information extracted from a manifest file
 */
export interface DependencyInfo {
  name: string;
  version: string;
  ecosystem: string;
  lineNumber?: number;
  isDev?: boolean;
}

/**
 * Parse dependencies from a manifest file
 */
export function parseDependencies(content: string, filePath: string): DependencyInfo[] {
  const fileName = basename(filePath).toLowerCase();

  switch (fileName) {
    case 'package.json':
      return parsePackageJson(content);
    case 'package-lock.json':
      return parsePackageLockJson(content);
    case 'requirements.txt':
      return parseRequirementsTxt(content);
    case 'pipfile':
    case 'pipfile.lock':
      return parsePipfile(content, fileName);
    case 'go.mod':
      return parseGoMod(content);
    case 'pom.xml':
      return parsePomXml(content);
    case 'build.gradle':
    case 'build.gradle.kts':
      return parseGradle(content);
    case 'cargo.toml':
      return parseCargoToml(content);
    case 'gemfile':
    case 'gemfile.lock':
      return parseGemfile(content, fileName);
    case 'composer.json':
    case 'composer.lock':
      return parseComposerJson(content, fileName);
    case 'pyproject.toml':
      return parsePyprojectToml(content);
    default:
      return [];
  }
}

/**
 * Parse package.json (npm/yarn)
 */
function parsePackageJson(content: string): DependencyInfo[] {
  const deps: DependencyInfo[] = [];
  try {
    const pkg = JSON.parse(content);

    if (pkg.dependencies) {
      for (const [name, version] of Object.entries(pkg.dependencies)) {
        deps.push({
          name,
          version: cleanVersion(version as string),
          ecosystem: 'npm',
          isDev: false,
        });
      }
    }

    if (pkg.devDependencies) {
      for (const [name, version] of Object.entries(pkg.devDependencies)) {
        deps.push({
          name,
          version: cleanVersion(version as string),
          ecosystem: 'npm',
          isDev: true,
        });
      }
    }
  } catch {
    // Invalid JSON
  }
  return deps;
}

/**
 * Parse package-lock.json
 */
function parsePackageLockJson(content: string): DependencyInfo[] {
  const deps: DependencyInfo[] = [];
  try {
    const lockfile = JSON.parse(content);
    const packages = lockfile.packages || lockfile.dependencies || {};

    for (const [path, info] of Object.entries(packages)) {
      const pkg = info as Record<string, unknown>;
      if (!path || path === '') continue; // Skip root
      const name = path.replace(/^node_modules\//, '');
      if (pkg.version) {
        deps.push({
          name,
          version: pkg.version as string,
          ecosystem: 'npm',
          isDev: pkg.dev === true,
        });
      }
    }
  } catch {
    // Invalid JSON
  }
  return deps;
}

/**
 * Parse requirements.txt (Python)
 */
function parseRequirementsTxt(content: string): DependencyInfo[] {
  const deps: DependencyInfo[] = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith('#') || line.startsWith('-')) continue;

    // Match patterns: package==1.0.0, package>=1.0.0, package~=1.0.0
    const match = line.match(/^([a-zA-Z0-9_.-]+)\s*(?:[=~!<>]=?\s*)([a-zA-Z0-9_.*-]+)?/);
    if (match) {
      deps.push({
        name: match[1],
        version: match[2] || '*',
        ecosystem: 'PyPI',
        lineNumber: i + 1,
      });
    }
  }
  return deps;
}

/**
 * Parse Pipfile/Pipfile.lock
 */
function parsePipfile(content: string, fileName: string): DependencyInfo[] {
  const deps: DependencyInfo[] = [];

  if (fileName === 'pipfile.lock') {
    try {
      const lockfile = JSON.parse(content);
      for (const section of ['default', 'develop']) {
        const packages = lockfile[section] || {};
        for (const [name, info] of Object.entries(packages)) {
          const pkg = info as Record<string, unknown>;
          deps.push({
            name,
            version: cleanVersion((pkg.version || '*') as string),
            ecosystem: 'PyPI',
            isDev: section === 'develop',
          });
        }
      }
    } catch {
      // Invalid JSON
    }
  } else {
    // Basic TOML-like parsing for Pipfile
    let inPackages = false;
    let isDev = false;
    const lines = content.split('\n');

    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed === '[packages]') { inPackages = true; isDev = false; continue; }
      if (trimmed === '[dev-packages]') { inPackages = true; isDev = true; continue; }
      if (trimmed.startsWith('[')) { inPackages = false; continue; }

      if (inPackages) {
        const match = trimmed.match(/^([a-zA-Z0-9_.-]+)\s*=\s*"?([^"]*)"?/);
        if (match) {
          deps.push({
            name: match[1],
            version: cleanVersion(match[2]),
            ecosystem: 'PyPI',
            isDev,
          });
        }
      }
    }
  }
  return deps;
}

/**
 * Parse go.mod (Go)
 */
function parseGoMod(content: string): DependencyInfo[] {
  const deps: DependencyInfo[] = [];
  const lines = content.split('\n');
  let inRequire = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    if (line === 'require (') {
      inRequire = true;
      continue;
    }
    if (line === ')') {
      inRequire = false;
      continue;
    }

    // Single-line require
    const singleMatch = line.match(/^require\s+(\S+)\s+(\S+)/);
    if (singleMatch) {
      deps.push({
        name: singleMatch[1],
        version: singleMatch[2],
        ecosystem: 'Go',
        lineNumber: i + 1,
      });
      continue;
    }

    // Multi-line require block
    if (inRequire) {
      const match = line.match(/^\s*(\S+)\s+(\S+)/);
      if (match && !match[1].startsWith('//')) {
        deps.push({
          name: match[1],
          version: match[2],
          ecosystem: 'Go',
          lineNumber: i + 1,
        });
      }
    }
  }
  return deps;
}

/**
 * Parse pom.xml (Maven) - basic regex parsing
 */
function parsePomXml(content: string): DependencyInfo[] {
  const deps: DependencyInfo[] = [];
  const depRegex = /<dependency>\s*<groupId>([^<]+)<\/groupId>\s*<artifactId>([^<]+)<\/artifactId>\s*(?:<version>([^<]+)<\/version>)?/g;

  let match;
  while ((match = depRegex.exec(content)) !== null) {
    deps.push({
      name: `${match[1]}:${match[2]}`,
      version: match[3] || '*',
      ecosystem: 'Maven',
    });
  }
  return deps;
}

/**
 * Parse build.gradle / build.gradle.kts
 */
function parseGradle(content: string): DependencyInfo[] {
  const deps: DependencyInfo[] = [];
  // Match: implementation 'group:artifact:version'
  const gradleRegex = /(?:implementation|api|compileOnly|runtimeOnly|testImplementation)\s*[('"]([^:'"]+):([^:'"]+):([^'")\s]+)/g;

  let match;
  while ((match = gradleRegex.exec(content)) !== null) {
    deps.push({
      name: `${match[1]}:${match[2]}`,
      version: match[3],
      ecosystem: 'Maven',
    });
  }
  return deps;
}

/**
 * Parse Cargo.toml (Rust)
 */
function parseCargoToml(content: string): DependencyInfo[] {
  const deps: DependencyInfo[] = [];
  let inDeps = false;
  let isDev = false;
  const lines = content.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed === '[dependencies]') { inDeps = true; isDev = false; continue; }
    if (trimmed === '[dev-dependencies]') { inDeps = true; isDev = true; continue; }
    if (trimmed.startsWith('[') && trimmed !== '[dependencies]' && trimmed !== '[dev-dependencies]') {
      inDeps = false; continue;
    }

    if (inDeps) {
      // Simple: package = "version"
      const simpleMatch = trimmed.match(/^([a-zA-Z0-9_-]+)\s*=\s*"([^"]+)"/);
      if (simpleMatch) {
        deps.push({
          name: simpleMatch[1],
          version: cleanVersion(simpleMatch[2]),
          ecosystem: 'crates.io',
          isDev,
        });
        continue;
      }

      // Complex: package = { version = "1.0", features = [...] }
      const complexMatch = trimmed.match(/^([a-zA-Z0-9_-]+)\s*=\s*\{.*version\s*=\s*"([^"]+)"/);
      if (complexMatch) {
        deps.push({
          name: complexMatch[1],
          version: cleanVersion(complexMatch[2]),
          ecosystem: 'crates.io',
          isDev,
        });
      }
    }
  }
  return deps;
}

/**
 * Parse Gemfile/Gemfile.lock (Ruby)
 */
function parseGemfile(content: string, fileName: string): DependencyInfo[] {
  const deps: DependencyInfo[] = [];

  if (fileName === 'gemfile.lock') {
    // Parse Gemfile.lock specs section
    let inSpecs = false;
    for (const line of content.split('\n')) {
      if (line.trim() === 'specs:') { inSpecs = true; continue; }
      if (!line.startsWith(' ') && inSpecs) { inSpecs = false; continue; }

      if (inSpecs) {
        const match = line.match(/^\s{4}(\S+)\s+\(([^)]+)\)/);
        if (match) {
          deps.push({
            name: match[1],
            version: match[2],
            ecosystem: 'RubyGems',
          });
        }
      }
    }
  } else {
    // Parse Gemfile
    const gemRegex = /gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?/g;
    let match;
    while ((match = gemRegex.exec(content)) !== null) {
      deps.push({
        name: match[1],
        version: match[2] ? cleanVersion(match[2]) : '*',
        ecosystem: 'RubyGems',
      });
    }
  }
  return deps;
}

/**
 * Parse composer.json/composer.lock (PHP)
 */
function parseComposerJson(content: string, fileName: string): DependencyInfo[] {
  const deps: DependencyInfo[] = [];
  try {
    const pkg = JSON.parse(content);

    if (fileName === 'composer.lock') {
      for (const p of pkg.packages || []) {
        deps.push({
          name: p.name,
          version: cleanVersion(p.version || '*'),
          ecosystem: 'Packagist',
        });
      }
    } else {
      for (const section of ['require', 'require-dev']) {
        const packages = pkg[section] || {};
        for (const [name, version] of Object.entries(packages)) {
          if (name === 'php' || name.startsWith('ext-')) continue;
          deps.push({
            name,
            version: cleanVersion(version as string),
            ecosystem: 'Packagist',
            isDev: section === 'require-dev',
          });
        }
      }
    }
  } catch {
    // Invalid JSON
  }
  return deps;
}

/**
 * Parse pyproject.toml (Python - PEP 621)
 */
function parsePyprojectToml(content: string): DependencyInfo[] {
  const deps: DependencyInfo[] = [];
  let inDeps = false;

  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (trimmed === 'dependencies = [') { inDeps = true; continue; }
    if (inDeps && trimmed === ']') { inDeps = false; continue; }

    if (inDeps) {
      const match = trimmed.match(/["']([a-zA-Z0-9_.-]+)(?:[>=<~!]+([a-zA-Z0-9_.*-]+))?["'],?/);
      if (match) {
        deps.push({
          name: match[1],
          version: match[2] || '*',
          ecosystem: 'PyPI',
        });
      }
    }
  }
  return deps;
}

/**
 * Clean version string by removing prefixes like ^, ~, >=, etc.
 */
function cleanVersion(version: string): string {
  return version.replace(/^[~^>=<!\s]+/, '').trim();
}
