// ─── Code Smells Analyzer ──────────────────────────────────────────────────
// Phát hiện code smells: tệp dài, import chưa dùng, magic numbers, console logs
// Detects long files, unused imports, magic numbers, console logs, TODO/FIXME, empty catch

import type { Finding, Severity } from '../../../types/finding.js';
import type { ScanFileContext } from '../../../types/scanner.js';
import type { QualityThresholds } from '../../../types/config.js';
import { createFinding, extractSnippet } from '../../base-scanner.js';

// ─── Default Thresholds ────────────────────────────────────────────────────

const DEFAULT_MAX_FILE_LENGTH = 500;

// ─── Main Analyzer Function ────────────────────────────────────────────────

/**
 * Analyze source code for code smells.
 * Phân tích mã nguồn để phát hiện code smells
 */
export function analyzeCodeSmells(context: ScanFileContext): Finding[] {
  const findings: Finding[] = [];
  const { content, filePath, config } = context;

  if (content.length < 10) return findings;

  const thresholds = config?.scanners?.quality?.thresholds;
  const maxFileLength = thresholds?.maxFileLength ?? DEFAULT_MAX_FILE_LENGTH;

  const lines = content.split('\n');

  // ── Detect long files ──
  findings.push(...detectLongFile(lines, filePath, content, maxFileLength));

  // ── Detect unused imports ──
  findings.push(...detectUnusedImports(lines, filePath, content));

  // ── Detect magic numbers ──
  findings.push(...detectMagicNumbers(lines, filePath, content));

  // ── Detect console.log / print statements ──
  findings.push(...detectConsoleLogs(lines, filePath, content));

  // ── Detect TODO/FIXME/HACK comments ──
  findings.push(...detectTodoComments(lines, filePath, content));

  // ── Detect empty catch blocks ──
  findings.push(...detectEmptyCatch(lines, filePath, content));

  return findings;
}

// ─── Long File Detection ───────────────────────────────────────────────────

function detectLongFile(lines: string[], filePath: string, content: string, maxFileLength: number): Finding[] {
  if (lines.length <= maxFileLength) return [];

  const severity: Severity = lines.length > maxFileLength * 3 ? 'medium' : 'low';

  return [
    createFinding({
      ruleId: 'QUA-SMELL-001',
      scanner: 'quality',
      severity,
      confidence: 'high',
      category: 'code-smells',
      subcategory: 'long-file',
      title: 'File Too Long',
      message: `File has ${lines.length} lines (threshold: ${maxFileLength}). Consider splitting into smaller modules.`,
      filePath,
      lineNumber: 1,
      snippet: lines.slice(0, 5).join('\n'),
      tags: ['code-smell', 'maintainability'],
      fix: {
        description: 'Split the file into smaller, focused modules. Group related functions and classes together.',
        references: [],
      },
    }),
  ];
}

// ─── Unused Import Detection ───────────────────────────────────────────────

/**
 * Basic unused import detection using regex.
 * Checks if imported identifiers are used elsewhere in the file.
 * Phát hiện import chưa sử dụng bằng regex
 */
function detectUnusedImports(lines: string[], filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  const imports: Array<{ name: string; line: number }> = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Match ES import patterns: import { Foo, Bar } from '...'
    const namedImportMatch = line.match(/import\s+\{([^}]+)\}\s+from\s+/);
    if (namedImportMatch) {
      const names = namedImportMatch[1].split(',').map((n) => {
        const parts = n.trim().split(/\s+as\s+/);
        return parts[parts.length - 1].trim(); // Use alias if present
      });
      for (const name of names) {
        if (name && name !== 'type') {
          imports.push({ name, line: i + 1 });
        }
      }
    }

    // Match default import: import Foo from '...'
    const defaultImportMatch = line.match(/import\s+(\w+)\s+from\s+/);
    if (defaultImportMatch && !line.includes('{')) {
      imports.push({ name: defaultImportMatch[1], line: i + 1 });
    }

    // Match Python import: from xxx import yyy
    const pyImportMatch = line.match(/from\s+\S+\s+import\s+(.+)/);
    if (pyImportMatch) {
      const names = pyImportMatch[1].split(',').map((n) => {
        const parts = n.trim().split(/\s+as\s+/);
        return parts[parts.length - 1].trim();
      });
      for (const name of names) {
        if (name) imports.push({ name, line: i + 1 });
      }
    }

    // Match Python import: import xxx
    const pySimpleImportMatch = line.match(/^import\s+(\w+)/);
    if (pySimpleImportMatch && !line.includes('from')) {
      imports.push({ name: pySimpleImportMatch[1], line: i + 1 });
    }
  }

  // Check which imports are used in the rest of the file (excluding import lines)
  const nonImportContent = lines
    .filter((l) => !/^\s*(?:import|from)\b/.test(l))
    .join('\n');

  for (const imp of imports) {
    // Skip type-only imports (TypeScript)
    if (/import\s+type\b/.test(lines[imp.line - 1])) continue;

    // Check if the identifier is used anywhere in non-import code
    // Use word boundary to avoid false matches
    const usageRegex = new RegExp(`\\b${escapeRegex(imp.name)}\\b`);
    if (!usageRegex.test(nonImportContent)) {
      const snippet = extractSnippet(content, imp.line);
      findings.push(
        createFinding({
          ruleId: 'QUA-SMELL-002',
          scanner: 'quality',
          severity: 'low',
          confidence: 'medium',
          category: 'code-smells',
          subcategory: 'unused-import',
          title: 'Unused Import',
          message: `Import '${imp.name}' appears to be unused`,
          filePath,
          lineNumber: imp.line,
          snippet,
          tags: ['code-smell', 'dead-code'],
          fix: {
            description: 'Remove unused imports to keep the code clean and reduce bundle size.',
            references: [],
          },
        }),
      );
    }
  }

  return findings;
}

// ─── Magic Number Detection ────────────────────────────────────────────────

/** Numbers that are commonly used and not considered "magic" */
const ALLOWED_NUMBERS = new Set([
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '-1', '0.0', '1.0', '100', '0.5',
  '12', '14', '18', '22', '28', '36', '72', // font & border radius sizes
  '50', '100', '150', '200', '250', '300', '350', '400', '450', '500', '550', '600', '650', '700', '750', '800', '850', '900', '950', // UI dimensions & steps
  '99', '999', '9999', // z-indexes
  '1000', '2000', '3000', '4000', '5000', '10000', '30000', '60000', // timeouts / delays (ms)
  '60', '24', '3600', '86400', // time units (s/min/hr/day)
  '200', '201', '204', '301', '302', '304', '400', '401', '403', '404', '409', '422', '429', '500', '502', '503', '504', // HTTP status codes
  '1024', '2048', '4096', '8192', '16384', '32768', '65536', // powers of 2
  '80', '443', '3000', '5000', '8000', '8080', // common ports
  '16', '24', '32', '48', '64', '96', '128', '256', '320', '480', '640', '720', '750', '800', '1080', '1200', '1280', '1440', '1600', '1920', '2560', '3840', // standard image/screen sizes
  '70', '75', '80', '85', '90', '95', // image quality / compression levels
  '0755', '0775', '0644', '0600', '0700', '0777', // chmod permissions
  '15', '20', '25', '30', '50', // pagination limits
  '90', '180', '270', '360', // angles / degrees
]);

/**
 * Detect magic numbers in code.
 * Phát hiện các số magic (không có tên biến mô tả)
 */
function detectMagicNumbers(lines: string[], filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  const seenNumbersInFile = new Set<string>();
  const magicNumberRegex = /(?<!\w)(-?\d+\.?\d*)\b/g;

  // Skip seeders, migrations, factories, and config files where literal numbers are expected schema/seed data
  if (/(?:seeder|migration|factory|database[\\/]seeders|database[\\/]migrations|database[\\/]factories|config[\\/])/i.test(filePath)) {
    return findings;
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // Skip comments, imports, const declarations (defining the constant), and enum values
    if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('#') || trimmed.startsWith('/*')) continue;
    if (/^\s*(?:import|from|require|use)\b/.test(line)) continue;
    if (/^\s*(?:const|final|static|readonly)\s+\w+\s*[:=]/.test(line)) continue;
    if (/^\s*(?:export\s+)?(?:const|enum)\b/.test(line)) continue;
    // Skip array indices, common patterns, SVG paths/coordinates, and CSS/Tailwind values
    if (/\[\s*\d+\s*\]/.test(trimmed)) continue;
    if (/<(?:svg|path|circle|rect|line|polygon|polyline|ellipse|g)\b/i.test(trimmed)) continue;
    if (/\b(?:viewBox|strokeWidth|width|height|cx|cy|r|rx|ry|x1|y1|x2|y2|rgba?|hsla?)\b/i.test(trimmed)) continue;
    // Skip common string/pagination/cookie/timeout helper calls where numbers are self-documenting arguments
    if (/\b(?:limit|substr|mb_substr|slice|take|chunk|timeout|cookie|rand|random|round|max|min|padStart|padEnd|setTimeout|setInterval)\s*\(/i.test(trimmed)) continue;

    const regex = new RegExp(magicNumberRegex.source, magicNumberRegex.flags);
    let m: RegExpExecArray | null;
    while ((m = regex.exec(line)) !== null) {
      const num = m[1];
      if (seenNumbersInFile.has(num)) continue;
      if (ALLOWED_NUMBERS.has(num) || ALLOWED_NUMBERS.has(num.replace(/^0+/, '')) || ALLOWED_NUMBERS.has('0' + num)) continue;
      // Skip if it's part of a string literal
      const before = line.substring(0, m.index);
      const singleQuotes = (before.match(/'/g) || []).length;
      const doubleQuotes = (before.match(/"/g) || []).length;
      const backticks = (before.match(/`/g) || []).length;
      if (singleQuotes % 2 !== 0 || doubleQuotes % 2 !== 0 || backticks % 2 !== 0) continue;
      // Skip version numbers (e.g., "1.2.3")
      if (/\d+\.\d+\.\d+/.test(line.substring(Math.max(0, m.index - 5), m.index + num.length + 5))) continue;

      // Skip numbers that are small integers (-2 to 10)
      const numVal = parseFloat(num);
      if (Number.isNaN(numVal) || (numVal >= -2 && numVal <= 10)) continue;

      seenNumbersInFile.add(num);
      const snippet = extractSnippet(content, i + 1);
      findings.push(
        createFinding({
          ruleId: 'QUA-SMELL-003',
          scanner: 'quality',
          severity: 'low',
          confidence: 'low',
          category: 'code-smells',
          subcategory: 'magic-number',
          title: 'Magic Number',
          message: `Magic number ${num} – consider extracting to a named constant for readability`,
          filePath,
          lineNumber: i + 1,
          column: m.index + 1,
          snippet,
          tags: ['code-smell', 'readability'],
          fix: {
            description: 'Extract magic numbers into named constants to improve readability and maintainability.',
            references: [],
          },
        }),
      );

      if (m.index === regex.lastIndex) regex.lastIndex++;
    }
  }

  return findings;
}

// ─── Console Log Detection ─────────────────────────────────────────────────

/**
 * Detect console.log/print statements left in code.
 * Phát hiện console.log/print còn sót trong mã nguồn
 */
function detectConsoleLogs(lines: string[], filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  const consolePattern = /\bconsole\.(?:log|debug|info|warn|error|trace|dir|table)\s*\(/;
  const printPattern = /\b(?:print|println|puts|NSLog|System\.out\.print(?:ln)?)\s*\(/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // Skip comments
    if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('#') || trimmed.startsWith('/*')) continue;

    let match = consolePattern.exec(trimmed);
    if (!match) match = printPattern.exec(trimmed);

    if (match) {
      const snippet = extractSnippet(content, i + 1);
      findings.push(
        createFinding({
          ruleId: 'QUA-SMELL-004',
          scanner: 'quality',
          severity: 'low',
          confidence: 'medium',
          category: 'code-smells',
          subcategory: 'console-log',
          title: 'Console/Print Statement',
          message: 'Debug logging statement found – consider using a proper logger or removing before production',
          filePath,
          lineNumber: i + 1,
          column: match.index + 1,
          snippet,
          tags: ['code-smell', 'debug'],
          fix: {
            description: 'Replace console.log/print with a structured logging library (e.g., winston, pino, log4j).',
            references: [],
          },
        }),
      );
    }
  }

  return findings;
}

// ─── TODO/FIXME/HACK Comment Detection ─────────────────────────────────────

/**
 * Detect TODO, FIXME, HACK, XXX, BUG comments.
 * Chỉ quét trên các dòng comment thực sự (tránh bắt nhầm biến $tempId, temporary).
 */
function detectTodoComments(lines: string[], filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];
  const todoPattern = /(?:\/\/|\/\*|\*|#|<!--|{{--)\s*\b(TODO|FIXME|HACK|XXX|BUG|TEMP|WORKAROUND)\b[:\s-]*(.*)/i;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // Must contain a comment token
    if (!/(?:\/\/|\/\*|\*|#|<!--|{{--)/.test(line)) continue;

    const match = todoPattern.exec(line);

    if (match) {
      const tag = match[1].toUpperCase();
      let description = match[2]?.trim() || '';
      // Clean trailing comment closures
      description = description.replace(/\s*(?:\*\/|-->|--\}\})\s*$/, '').trim();
      const severity: Severity = tag === 'FIXME' || tag === 'BUG' ? 'medium' : 'low';

      const snippet = extractSnippet(content, i + 1);
      findings.push(
        createFinding({
          ruleId: 'QUA-SMELL-005',
          scanner: 'quality',
          severity,
          confidence: 'high',
          category: 'code-smells',
          subcategory: 'todo-comment',
          title: `${tag} Comment`,
          message: `${tag} comment found${description ? ': ' + description : ''}`,
          filePath,
          lineNumber: i + 1,
          column: (match.index ?? 0) + 1,
          snippet,
          tags: ['code-smell', 'technical-debt', tag.toLowerCase()],
        }),
      );
    }
  }

  return findings;
}

// ─── Empty Catch Block Detection ───────────────────────────────────────────

/**
 * Detect empty catch blocks that silently swallow exceptions.
 * Phát hiện khối catch rỗng
 */
function detectEmptyCatch(lines: string[], filePath: string, content: string): Finding[] {
  const findings: Finding[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    // Match catch block
    if (/\bcatch\s*\(/.test(line)) {
      // Check if the catch block is empty
      // Pattern 1: catch (...) { } on same line
      if (/catch\s*\([^)]*\)\s*\{\s*\}/.test(line)) {
        const snippet = extractSnippet(content, i + 1);
        findings.push(createEmptyCatchFinding(filePath, i + 1, snippet));
        continue;
      }

      // Pattern 2: catch on one line, empty body on next lines
      if (i + 1 < lines.length) {
        const nextLine = lines[i + 1]?.trim();
        const nextNextLine = lines[i + 2]?.trim();

        // catch (...) {
        // }
        if (nextLine === '}' || (nextLine === '' && nextNextLine === '}')) {
          const snippet = extractSnippet(content, i + 1);
          findings.push(createEmptyCatchFinding(filePath, i + 1, snippet));
        }
      }
    }
  }

  return findings;
}

function createEmptyCatchFinding(filePath: string, line: number, snippet: string): Finding {
  return createFinding({
    ruleId: 'QUA-SMELL-006',
    scanner: 'quality',
    severity: 'medium',
    confidence: 'high',
    category: 'code-smells',
    subcategory: 'empty-catch',
    title: 'Empty Catch Block',
    message: 'Empty catch block silently swallows exceptions – at minimum, log the error',
    filePath,
    lineNumber: line,
    snippet,
    tags: ['code-smell', 'error-handling'],
    fix: {
      description: 'Add error handling logic to the catch block. At minimum, log the error. If intentionally ignoring, add a comment explaining why.',
      references: [],
    },
  });
}

// ─── Utility ───────────────────────────────────────────────────────────────

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
