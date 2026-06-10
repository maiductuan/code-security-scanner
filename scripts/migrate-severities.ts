import { readFileSync, writeFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';

// 1. Files in src/
const srcDir = resolve(process.cwd(), 'src');
const scriptsDir = resolve(process.cwd(), 'scripts');
const rulesDir = resolve(process.cwd(), 'rules');
const docsDir = resolve(process.cwd(), 'docs');
const readmeFile = resolve(process.cwd(), 'README.md');

function walk(dir: string, callback: (path: string) => void) {
  const files = readdirSync(dir);
  for (const file of files) {
    const p = join(dir, file);
    if (statSync(p).isDirectory()) {
      walk(p, callback);
    } else {
      callback(p);
    }
  }
}

// Migrate Typescript files
const tsFiles: string[] = [];
walk(srcDir, (p) => { if (p.endsWith('.ts')) tsFiles.push(p); });
walk(scriptsDir, (p) => { if (p.endsWith('.ts')) tsFiles.push(p); });

for (const file of tsFiles) {
  let content = readFileSync(file, 'utf-8');
  let original = content;

  // Replace type definitions and enum values
  content = content.replace(/'critical'\s*\|\s*'error'\s*\|\s*'warning'\s*\|\s*'info'/g, "'critical' | 'high' | 'medium' | 'low'");
  content = content.replace(/\[\s*'critical'\s*,\s*'error'\s*,\s*'warning'\s*,\s*'info'\s*\]/g, "['critical', 'high', 'medium', 'low']");
  content = content.replace(/\[\s*'critical'\s*,\s*'error'\s*\]/g, "['critical', 'high']");
  content = content.replace(/z\.enum\(\[\s*'critical'\s*,\s*'error'\s*,\s*'warning'\s*,\s*'info'\s*\]\)/g, "z.enum(['critical', 'high', 'medium', 'low'])");
  content = content.replace(/z\.enum\(\[\s*"critical"\s*,\s*"error"\s*,\s*"warning"\s*,\s*"info"\s*\]\)/g, "z.enum(['critical', 'high', 'medium', 'low'])");
  
  // Replace severity assignments in analyzers
  content = content.replace(/severity:\s*'error'/g, "severity: 'high'");
  content = content.replace(/severity:\s*'warning'/g, "severity: 'medium'");
  content = content.replace(/severity:\s*'info'/g, "severity: 'low'");

  // Replace mapSeverity logic in cve/index.ts
  content = content.replace(/if\s*\(lower\s*===\s*'high'\)\s*return\s*'error';/g, "if (lower === 'high') return 'high';");
  content = content.replace(/if\s*\(lower\s*===\s*'medium'\s*\|\|\s*lower\s*===\s*'moderate'\)\s*return\s*'warning';/g, "if (lower === 'medium' || lower === 'moderate') return 'medium';");
  content = content.replace(/return\s*'info';/g, "return 'low';");

  // Replace convert logic in scripts
  content = content.replace(/let\s+severity\s*=\s*'warning';/g, "let severity = 'medium';");
  content = content.replace(/if\s*\(semgrepSeverity\s*===\s*'ERROR'\)\s*severity\s*=\s*'error';/g, "if (semgrepSeverity === 'ERROR') severity = 'high';");
  content = content.replace(/else\s+if\s*\(semgrepSeverity\s*===\s*'WARNING'\)\s*severity\s*=\s*'warning';/g, "else if (semgrepSeverity === 'WARNING') severity = 'medium';");
  content = content.replace(/else\s+if\s*\(semgrepSeverity\s*===\s*'INFO'\)\s*severity\s*=\s*'info';/g, "else if (semgrepSeverity === 'INFO') severity = 'low';");

  // In scripts/evaluate.ts expected categories / summaries
  content = content.replace(/category:\s*['"]xss['"]/g, "category: 'xss'");
  
  if (content !== original) {
    writeFileSync(file, content, 'utf-8');
    console.log(`Migrated: ${file}`);
  }
}

// Migrate YAML files
const yamlFiles: string[] = [];
walk(rulesDir, (p) => { if (p.endsWith('.yml') || p.endsWith('.yaml')) yamlFiles.push(p); });

for (const file of yamlFiles) {
  let content = readFileSync(file, 'utf-8');
  let original = content;

  // Replace severity field
  content = content.replace(/\bseverity:\s*error\b/g, "severity: high");
  content = content.replace(/\bseverity:\s*warning\b/g, "severity: medium");
  content = content.replace(/\bseverity:\s*info\b/g, "severity: low");

  // Replace default-config list of severities
  content = content.replace(/-\s*error/g, "- high");
  content = content.replace(/-\s*warning/g, "- medium");
  content = content.replace(/-\s*info/g, "- low");

  if (content !== original) {
    writeFileSync(file, content, 'utf-8');
    console.log(`Migrated YAML: ${file}`);
  }
}

// Migrate docs & readme
const docFiles = [readmeFile, resolve(docsDir, 'admin-guide.md')];
for (const file of docFiles) {
  if (!existsSync(file)) continue;
  let content = readFileSync(file, 'utf-8');
  let original = content;

  content = content.replace(/\berror\b/g, "high");
  content = content.replace(/\bwarning\b/g, "medium");
  content = content.replace(/\binfo\b/g, "low");

  content = content.replace(/\bERROR\b/g, "HIGH");
  content = content.replace(/\bWARNING\b/g, "MEDIUM");
  content = content.replace(/\bINFO\b/g, "LOW");

  if (content !== original) {
    writeFileSync(file, content, 'utf-8');
    console.log(`Migrated Doc: ${file}`);
  }
}

console.log('Migration completed successfully!');
