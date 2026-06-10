import { writeFileSync, mkdirSync, rmSync, readdirSync, statSync, readFileSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { execSync } from 'node:child_process';
import yaml from 'js-yaml';

const ZIP_URL = 'https://github.com/semgrep/semgrep-rules/archive/refs/heads/develop.zip';
const TEMP_ZIP = resolve(process.cwd(), 'rules-temp.zip');
const TEMP_DIR = resolve(process.cwd(), 'rules-temp');
const OUTPUT_DIR = resolve(process.cwd(), 'rules/built-in');

async function downloadFile(url: string, destPath: string): Promise<void> {
  console.log(`Downloading: ${url}`);
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to download: ${response.statusText}`);
  }
  const arrayBuffer = await response.arrayBuffer();
  const buffer = Buffer.from(arrayBuffer);
  writeFileSync(destPath, buffer);
  console.log(`Saved zip to: ${destPath}`);
}

function extractZip(zipPath: string, destDir: string): void {
  console.log(`Extracting ${zipPath} to ${destDir}...`);
  if (existsSync(destDir)) {
    rmSync(destDir, { recursive: true, force: true });
  }
  mkdirSync(destDir, { recursive: true });

  const isWindows = process.platform === 'win32';
  if (isWindows) {
    execSync(`powershell -Command "Expand-Archive -Path '${zipPath}' -DestinationPath '${destDir}' -Force"`, { stdio: 'inherit' });
  } else {
    execSync(`unzip -o "${zipPath}" -d "${destDir}"`, { stdio: 'inherit' });
  }
  console.log('Extraction complete.');
}

function findYamlFiles(dir: string, fileList: string[] = []): string[] {
  try {
    const files = readdirSync(dir);
    for (const file of files) {
      const filePath = join(dir, file);
      const stat = statSync(filePath);
      if (stat.isDirectory()) {
        findYamlFiles(filePath, fileList);
      } else if (file.endsWith('.yml') || file.endsWith('.yaml')) {
        fileList.push(filePath);
      }
    }
  } catch {
    // Skip unreadable files/folders
  }
  return fileList;
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
    const match = item.match(/A\d{1,2}(?::\d{4})?/i);
    if (match) {
      owasps.push(match[0].toUpperCase());
    }
  }
  return owasps;
}

function deduceCategory(id: string): string {
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

  return 'security';
}

function convertSemgrepRule(semgrepRule: any): any {
  const id = semgrepRule.id;
  const name = id.split('.').pop() || id;
  const description = semgrepRule.message || 'No description provided';
  const category = deduceCategory(id);

  let severity = 'medium';
  const semgrepSeverity = semgrepRule.severity?.toUpperCase();
  if (semgrepSeverity === 'ERROR') severity = 'high';
  else if (semgrepSeverity === 'WARNING') severity = 'medium';
  else if (semgrepSeverity === 'INFO') severity = 'low';

  const metadata = semgrepRule.metadata || {};
  const cwe = extractCWEs(metadata);
  const owasp = extractOWASPs(metadata);

  const patterns: any[] = [];

  if (semgrepRule.pattern) {
    patterns.push({ pattern: semgrepRule.pattern, message: semgrepRule.message });
  }

  if (semgrepRule['pattern-regex']) {
    patterns.push({ regex: semgrepRule['pattern-regex'], message: semgrepRule.message });
  }

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

  if (patterns.length === 0) {
    patterns.push({ regex: '.*', message: semgrepRule.message });
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

function mapLanguage(lang: string): string {
  const l = lang.toLowerCase().trim();
  if (l === '*' || l === 'all' || l === 'generic') return 'generic';
  if (l === 'js' || l === 'javascript') return 'javascript';
  if (l === 'ts' || l === 'typescript') return 'typescript';
  if (l === 'py' || l === 'python') return 'python';
  if (l === 'java') return 'java';
  if (l === 'go' || l === 'golang') return 'go';
  if (l === 'c') return 'c';
  if (l === 'cpp' || l === 'c++') return 'cpp';
  if (l === 'csharp' || l === 'c#') return 'csharp';
  if (l === 'php') return 'php';
  if (l === 'rb' || l === 'ruby') return 'ruby';
  if (l === 'rs' || l === 'rust') return 'rust';
  if (l === 'kt' || l === 'kotlin') return 'kotlin';
  if (l === 'swift') return 'swift';
  return l;
}

async function run() {
  try {
    // 1. Download
    await downloadFile(ZIP_URL, TEMP_ZIP);

    // 2. Extract
    extractZip(TEMP_ZIP, TEMP_DIR);

    // 3. Find YAML rules
    console.log('Scanning extracted files for YAML rules...');
    const yamlFiles = findYamlFiles(TEMP_DIR);
    console.log(`Found ${yamlFiles.length} YAML files.`);

    // 4. Convert and group by language
    const groupedRules: Record<string, any[]> = {};
    let totalRulesConverted = 0;

    for (const file of yamlFiles) {
      try {
        const content = readFileSync(file, 'utf-8');
        const doc = yaml.load(content) as any;

        if (doc && Array.isArray(doc.rules)) {
          for (const rule of doc.rules) {
            const converted = convertSemgrepRule(rule);
            totalRulesConverted++;

            const langs = rule.languages || ['*'];
            for (const l of langs) {
              const mappedLang = mapLanguage(l);
              if (!groupedRules[mappedLang]) {
                groupedRules[mappedLang] = [];
              }
              groupedRules[mappedLang].push(converted);
            }
          }
        }
      } catch {
        // Skip unparseable files
      }
    }

    console.log(`Converted a total of ${totalRulesConverted} rules.`);

    // 5. Write grouped rule files
    mkdirSync(OUTPUT_DIR, { recursive: true });

    for (const [lang, rules] of Object.entries(groupedRules)) {
      if (rules.length === 0) continue;
      // Deduplicate rules by ID in each language group
      const seenIds = new Set<string>();
      const dedupedRules = rules.filter(r => {
        if (seenIds.has(r.id)) return false;
        seenIds.add(r.id);
        return true;
      });

      const outputFileName = `semgrep-${lang}.yml`;
      const outputPath = join(OUTPUT_DIR, outputFileName);
      const outputDoc = { rules: dedupedRules };

      writeFileSync(outputPath, yaml.dump(outputDoc, { indent: 2, lineWidth: 120 }), 'utf-8');
      console.log(`Wrote ${dedupedRules.length} rules to: ${outputPath}`);
    }

    // 6. Clean up
    console.log('Cleaning up temporary directories...');
    rmSync(TEMP_ZIP, { force: true });
    rmSync(TEMP_DIR, { recursive: true, force: true });
    console.log('Rules update completed successfully!');
  } catch (error) {
    console.error('Update failed:', error);
    process.exit(1);
  }
}

run();
