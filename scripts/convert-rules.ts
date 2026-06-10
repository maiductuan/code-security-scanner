import { readFileSync, writeFileSync, existsSync, statSync, readdirSync } from 'node:fs';
import { resolve, join } from 'node:path';
import yaml from 'js-yaml';
import { RuleFileSchema } from '../src/config/schema.js';

interface SemgrepPattern {
  pattern?: string;
  'pattern-regex'?: string;
  patterns?: any[];
  'pattern-either'?: any[];
}

function parseArgs() {
  const args = process.argv.slice(2);
  let input = '';
  let output = '';
  let category = '';

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--input' || args[i] === '-i') {
      input = args[++i];
    } else if (args[i] === '--output' || args[i] === '-o') {
      output = args[++i];
    } else if (args[i] === '--category' || args[i] === '-c') {
      category = args[++i];
    }
  }

  return { input, output, category };
}

function extractCWEs(metadata: any): string[] {
  if (!metadata) return [];
  const cweData = metadata.cwe || [];
  const list = Array.isArray(cweData) ? cweData : [cweData];
  const cwes: string[] = [];

  for (const item of list) {
    if (typeof item !== 'string') continue;
    const match = item.match(/CWE-\d+/i);
    if (match) {
      cwes.push(match[0].toUpperCase());
    }
  }
  return cwes;
}

function extractOWASPs(metadata: any): string[] {
  if (!metadata) return [];
  const owaspData = metadata.owasp || [];
  const list = Array.isArray(owaspData) ? owaspData : [owaspData];
  const owasps: string[] = [];

  for (const item of list) {
    if (typeof item !== 'string') continue;
    // Match patterns like A03:2021 or A3:2021 or A03
    const match = item.match(/A\d{1,2}(?::\d{4})?/i);
    if (match) {
      owasps.push(match[0].toUpperCase());
    }
  }
  return owasps;
}

function deduceCategory(id: string, override?: string): string {
  if (override) return override;

  const idLower = id.toLowerCase();
  if (idLower.includes('sqli') || idLower.includes('sql-injection') || idLower.includes('sql')) return 'injection';
  if (idLower.includes('cmd-injection') || idLower.includes('command-injection') || idLower.includes('rce')) return 'injection';
  if (idLower.includes('eval') || idLower.includes('code-injection')) return 'injection';
  if (idLower.includes('xss') || idLower.includes('cross-site-scripting')) return 'xss';
  if (idLower.includes('secret') || idLower.includes('token') || idLower.includes('key') || idLower.includes('password')) return 'secrets';
  if (idLower.includes('auth') || idLower.includes('jwt') || idLower.includes('session')) return 'auth';
  if (idLower.includes('crypto') || idLower.includes('hash') || idLower.includes('md5') || idLower.includes('cipher')) return 'crypto';
  if (idLower.includes('path') || idLower.includes('traversal') || idLower.includes('file')) return 'file-ops';
  if (idLower.includes('ssrf') || idLower.includes('xxe') || idLower.includes('cors') || idLower.includes('csrf') || idLower.includes('rate-limit')) return 'api-security';

  return 'security'; // default fallback
}

function convertSemgrepRule(semgrepRule: any, defaultCategory?: string): any {
  const id = semgrepRule.id;
  const name = id.split('.').pop() || id;
  const description = semgrepRule.message || 'No description provided';
  const category = deduceCategory(id, defaultCategory);

  // Map severity
  let severity = 'medium';
  const semgrepSeverity = semgrepRule.severity?.toUpperCase();
  if (semgrepSeverity === 'ERROR') severity = 'high';
  else if (semgrepSeverity === 'WARNING') severity = 'medium';
  else if (semgrepSeverity === 'INFO') severity = 'low';

  const metadata = semgrepRule.metadata || {};
  const cwe = extractCWEs(metadata);
  const owasp = extractOWASPs(metadata);

  const patterns: any[] = [];

  // Parse pattern logic
  if (semgrepRule.pattern) {
    patterns.push({
      pattern: semgrepRule.pattern,
      message: semgrepRule.message,
    });
  }

  if (semgrepRule['pattern-regex']) {
    patterns.push({
      regex: semgrepRule['pattern-regex'],
      message: semgrepRule.message,
    });
  }

  // Parse nested patterns (simple extraction of positive matches)
  if (Array.isArray(semgrepRule.patterns)) {
    for (const p of semgrepRule.patterns) {
      if (p.pattern) {
        patterns.push({ pattern: p.pattern, message: semgrepRule.message });
      }
      if (p['pattern-regex']) {
        patterns.push({ regex: p['pattern-regex'], message: semgrepRule.message });
      }
    }
  }

  if (Array.isArray(semgrepRule['pattern-either'])) {
    for (const p of semgrepRule['pattern-either']) {
      if (p.pattern) {
        patterns.push({ pattern: p.pattern, message: semgrepRule.message });
      }
      if (p['pattern-regex']) {
        patterns.push({ regex: p['pattern-regex'], message: semgrepRule.message });
      }
    }
  }

  // Default pattern if none resolved
  if (patterns.length === 0) {
    patterns.push({
      regex: '.*', // dummy matching all
      message: semgrepRule.message,
    });
  }

  return {
    id,
    name,
    description,
    category,
    severity,
    confidence: 'medium',
    languages: semgrepRule.languages || ['*'],
    patterns,
    cwe,
    owasp,
    references: metadata.references || [],
    tags: metadata.technology || [],
  };
}

export function convertSemgrepRules(inputPath: string, defaultCategory?: string): any {
  const fileContent = readFileSync(inputPath, 'utf-8');
  const doc = yaml.load(fileContent) as any;

  if (!doc || !Array.isArray(doc.rules)) {
    throw new Error('Invalid Semgrep rule file: rules array not found');
  }

  const convertedRules = doc.rules.map((r: any) => convertSemgrepRule(r, defaultCategory));

  return { rules: convertedRules };
}

// Only execute when run directly from Node
if (process.argv[1] && process.argv[1].endsWith('convert-rules.ts')) {
  try {
    const { input, output, category } = parseArgs();

    if (!input || !output) {
      console.error('Usage: npx tsx scripts/convert-rules.ts --input <file> --output <file> [--category <cat>]');
      process.exit(1);
    }

    console.log(`Converting Semgrep rules from: ${input}`);
    const result = convertSemgrepRules(resolve(input), category);

    // Validate with DeepScan schema
    RuleFileSchema.parse(result);

    // Write output
    const outputYaml = yaml.dump(result, { indent: 2, lineWidth: 120 });
    writeFileSync(resolve(output), outputYaml, 'utf-8');
    console.log(`Successfully converted and wrote ${result.rules.length} rules to: ${output}`);
  } catch (error) {
    console.error('Conversion failed:', error);
    process.exit(1);
  }
}
