// ─── Base Scanner ──────────────────────────────────────────────────────────
// Lớp cơ sở trừu tượng cho tất cả scanner engines
// Abstract base class implementing IScanner with common utilities

import { createHash } from 'node:crypto';
import type { Finding, Severity, Confidence, ScannerType, SourceLocation, FixSuggestion } from '../types/finding.js';
import type { IScanner, ScanFileContext } from '../types/scanner.js';
import type { DeepScanConfig } from '../types/config.js';
import type { Rule } from '../types/rule.js';

// ─── Helper Types ──────────────────────────────────────────────────────────

/** Options for creating a finding */
export interface CreateFindingOptions {
  ruleId: string;
  scanner: ScannerType;
  severity: Severity;
  confidence: Confidence;
  category: string;
  subcategory?: string;
  title: string;
  message: string;
  filePath: string;
  lineNumber: number;
  column?: number;
  endLine?: number;
  endColumn?: number;
  snippet: string;
  cwe?: string[];
  owasp?: string[];
  fix?: FixSuggestion;
  references?: string[];
  tags?: string[];
}

// ─── Utility Functions ─────────────────────────────────────────────────────

/**
 * Generate a stable fingerprint for a finding.
 * Uses ruleId + filePath + line content hash for deduplication across scans.
 * Tạo fingerprint ổn định cho finding để nhận diện qua các lần quét
 */
export function generateFingerprint(ruleId: string, filePath: string, snippet: string): string {
  const input = `${ruleId}::${filePath}::${snippet.trim()}`;
  return createHash('sha256').update(input).digest('hex').substring(0, 16);
}

/**
 * Extract a code snippet around a given line number.
 * Trích xuất đoạn code xung quanh dòng được chỉ định
 * @param source - Full source code
 * @param lineNumber - 1-indexed line number
 * @param contextLines - Number of lines above and below to include (default: 3)
 */
export function extractSnippet(source: string, lineNumber: number, contextLines: number = 3): string {
  const lines = source.split('\n');
  const start = Math.max(0, lineNumber - 1 - contextLines);
  const end = Math.min(lines.length, lineNumber + contextLines);
  return lines.slice(start, end).join('\n');
}

/**
 * Create a fully-formed Finding object from options.
 * Tạo đối tượng Finding hoàn chỉnh từ các tùy chọn
 */
export function createFinding(options: CreateFindingOptions): Finding {
  const fingerprint = generateFingerprint(options.ruleId, options.filePath, options.snippet);

  const location: SourceLocation = {
    file: options.filePath,
    startLine: options.lineNumber,
    startColumn: options.column ?? 1,
    endLine: options.endLine ?? options.lineNumber,
    endColumn: options.endColumn ?? (options.column ?? 1),
    snippet: options.snippet,
  };

  return {
    id: `${options.scanner}-${fingerprint}`,
    ruleId: options.ruleId,
    scanner: options.scanner,
    severity: options.severity,
    confidence: options.confidence,
    category: options.category,
    subcategory: options.subcategory,
    title: options.title,
    message: options.message,
    location,
    cwe: options.cwe,
    owasp: options.owasp,
    fix: options.fix,
    references: options.references ?? options.fix?.references ?? [],
    metadata: {
      fingerprint,
      firstSeen: new Date().toISOString(),
      tags: options.tags ?? [],
    },
  };
}

/**
 * Match a regex pattern against source code and return all matches with line info.
 * Khớp mẫu regex với mã nguồn và trả về tất cả kết quả kèm thông tin dòng
 */
export function matchPattern(
  source: string,
  pattern: RegExp,
): Array<{ line: number; column: number; match: string; lineContent: string }> {
  const results: Array<{ line: number; column: number; match: string; lineContent: string }> = [];
  const lines = source.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const lineContent = lines[i];
    // Reset lastIndex for global patterns
    const regex = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g');
    let m: RegExpExecArray | null;
    while ((m = regex.exec(lineContent)) !== null) {
      results.push({
        line: i + 1, // 1-indexed
        column: m.index + 1,
        match: m[0],
        lineContent,
      });
      // Prevent infinite loop on zero-width matches
      if (m.index === regex.lastIndex) regex.lastIndex++;
    }
  }

  return results;
}

/**
 * Check if a line is inside a comment or string literal (basic heuristic).
 * Kiểm tra xem dòng có nằm trong comment hoặc chuỗi ký tự không
 */
export function isInCommentOrString(line: string, column: number): boolean {
  const trimmed = line.trimStart();
  // Single-line comment check
  if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*') || trimmed.startsWith('/*')) {
    return true;
  }
  return false;
}

/**
 * Check if a regex match falls inside a pattern/rule definition context,
 * indicating a likely false positive when scanning static analysis tool
 * source code or similar data-definition files.
 *
 * Detects:
 * 1. Match inside a regex literal: /somePattern/flags
 * 2. Line is a property in a pattern/rule definition object
 *    (e.g., `regex: /.../, pattern: '...', message: '...'`)
 * 3. Line defines a taint sink/source pattern string
 *    (e.g., `{ pattern: 'eval($TAINTED)', ... }`)
 * 4. Match inside a string literal that is being assigned to a data property
 */
export function isPatternDefinitionContext(lineContent: string, column: number): boolean {
  const trimmed = lineContent.trimStart();

  // 1. Line is a property in a pattern definition object
  //    (regex:, pattern:, message:, description:)
  if (/^\s*(?:regex|pattern|message|description)\s*[:=]\s/.test(lineContent)) {
    return true;
  }

  // 2. Check if match is inside a regex literal on this line
  //    Look for the pattern: / ... <match> ... /flags
  //    We scan for regex literal boundaries (unescaped `/` not preceded by `\`)
  const regexLiteralRanges = findRegexLiteralRanges(lineContent);
  const colIdx = column - 1; // Convert to 0-indexed
  for (const [start, end] of regexLiteralRanges) {
    if (colIdx >= start && colIdx <= end) {
      return true;
    }
  }

  // 3. Taint sink/source definition strings
  //    e.g., { pattern: 'eval($TAINTED)', type: 'code_injection', description: '...' }
  if (/\bpattern\s*:\s*['"]/.test(trimmed) && /\$TAINTED|\$BUF|\$X/.test(trimmed)) {
    return true;
  }

  // 4. Line is inside a taint sink/source array entry
  //    e.g., { pattern: 'system($TAINTED)', type: 'command_injection', ... }
  if (/\btype\s*:\s*'(?:code_injection|command_injection|sql_injection|xss|path_traversal|buffer_overflow|format_string|file_inclusion|deserialization|network)'/.test(trimmed)) {
    return true;
  }

  // 5. Line contains a string that defines a detection pattern with meta-references
  //    e.g., cwe: ['CWE-...'], or severity: '...' as part of rule definition objects
  if (/\bcwe\s*:\s*\[/.test(trimmed) && /\bseverity\s*:\s*['"]/.test(lineContent)) {
    return true;
  }

  return false;
}

/**
 * Find ranges (start, end) of regex literals in a line of JavaScript/TypeScript code.
 * Returns an array of [startIndex, endIndex] pairs (0-indexed, inclusive).
 * Handles escaped characters inside regex literals.
 */
function findRegexLiteralRanges(line: string): Array<[number, number]> {
  const ranges: Array<[number, number]> = [];
  const len = line.length;
  let i = 0;

  while (i < len) {
    const ch = line[i];

    // Skip string literals (single, double, backtick)
    if (ch === "'" || ch === '"' || ch === '`') {
      i = skipStringLiteral(line, i);
      continue;
    }

    // Skip single-line comments
    if (ch === '/' && i + 1 < len && line[i + 1] === '/') {
      break; // Rest of line is a comment
    }

    // Detect regex literal start
    // A `/` is a regex start if preceded by certain tokens (heuristic)
    if (ch === '/' && i + 1 < len && line[i + 1] !== '/' && line[i + 1] !== '*') {
      if (isRegexStart(line, i)) {
        const start = i;
        i++; // skip opening /
        // Find closing /
        while (i < len) {
          if (line[i] === '\\' && i + 1 < len) {
            i += 2; // skip escaped character
            continue;
          }
          if (line[i] === '/') {
            // Skip flags after closing /
            const end = i;
            i++;
            while (i < len && /[gimsuy]/.test(line[i])) i++;
            ranges.push([start, end]);
            break;
          }
          i++;
        }
        continue;
      }
    }

    i++;
  }

  return ranges;
}

/**
 * Heuristic: check if a `/` at position `pos` in `line` is the start of a regex literal.
 * A `/` starts a regex if the preceding non-whitespace token is one of:
 *   = ( [ ! & | ? : ; , { } ~ ^ % + - * return typeof void delete case in instanceof
 * or the line starts with `/` (beginning of statement).
 */
function isRegexStart(line: string, pos: number): boolean {
  if (pos === 0) return true;

  // Look backwards for the previous non-whitespace character
  let j = pos - 1;
  while (j >= 0 && (line[j] === ' ' || line[j] === '\t')) j--;
  if (j < 0) return true;

  const prevChar = line[j];
  // These characters can precede a regex literal
  if ('=([!&|?:;,{}~^%+-*<>'.includes(prevChar)) return true;

  // Check for keyword predecessors (return, typeof, etc.)
  const before = line.substring(0, j + 1).trimEnd();
  if (/(?:return|typeof|void|delete|case|in|instanceof|new|throw|of)\s*$/.test(before)) return true;

  return false;
}

/**
 * Skip a string literal starting at position `pos` in `line`.
 * Returns the index after the closing quote.
 */
function skipStringLiteral(line: string, pos: number): number {
  const quote = line[pos];
  let i = pos + 1;
  while (i < line.length) {
    if (line[i] === '\\' && i + 1 < line.length) {
      i += 2; // skip escaped character
      continue;
    }
    if (line[i] === quote) {
      return i + 1;
    }
    i++;
  }
  return i;
}

/**
 * Check if a match at (line, column) is in a "safe" AST context:
 * string literal, comment, import statement, or type annotation.
 * Uses tree-sitter AST if available, otherwise returns false (falls back to regex heuristics).
 * 
 * @param tree - Tree from web-tree-sitter (or null)
 * @param line - 1-indexed line number
 * @param column - 1-indexed column number
 */
export function isInSafeASTContext(
  tree: import('web-tree-sitter').Tree | null,
  line: number,
  column: number,
): boolean {
  if (!tree) return false;

  try {
    // Get the AST node at the match position (tree-sitter uses 0-indexed)
    const node = tree.rootNode.descendantForPosition({ row: line - 1, column: column - 1 });
    if (!node) return false;

    // Walk up ancestors to check context
    let current: import('web-tree-sitter').Node | null = node;
    while (current) {
      const type = current.type;

      // Comments
      if (type === 'comment' || type === 'line_comment' || type === 'block_comment') return true;

      // String literals (but NOT template literals with substitutions — those may embed code)
      if (
        type === 'string' || type === 'string_literal' ||
        type === 'string_content' || type === 'interpreted_string_literal'
      ) return true;

      // Template strings are only safe if they have no interpolation
      if (type === 'template_string') {
        let hasInterpolation = false;
        for (let i = 0; i < current.childCount; i++) {
          if (current.child(i)?.type === 'template_substitution') {
            hasInterpolation = true;
            break;
          }
        }
        if (!hasInterpolation) return true;
      }

      // Import/require statements
      if (
        type === 'import_statement' || type === 'import_declaration' ||
        type === 'import_from_statement'
      ) return true;

      // Type annotations (TypeScript)
      if (
        type === 'type_annotation' || type === 'type_alias_declaration' ||
        type === 'interface_declaration'
      ) return true;

      current = current.parent;
    }
  } catch {
    // Tree-sitter errors — fall back gracefully
  }
  return false;
}

// ─── Abstract Base Scanner ─────────────────────────────────────────────────

/**
 * Abstract base class that implements IScanner.
 * Provides common rule matching, fingerprinting, and snippet extraction.
 * Lớp cơ sở trừu tượng cung cấp các tiện ích chung cho scanner
 */
export abstract class BaseScanner implements IScanner {
  abstract name: string;
  abstract type: 'security' | 'quality' | 'cve';

  protected config: DeepScanConfig | null = null;

  async initialize(config: DeepScanConfig): Promise<void> {
    this.config = config;
  }

  abstract scanFile(context: ScanFileContext): Promise<Finding[]>;

  async destroy(): Promise<void> {
    this.config = null;
  }

  /**
   * Match all rule patterns against source code and return findings.
   * Khớp tất cả rule patterns với mã nguồn và trả về findings
   */
  protected matchRulePatterns(context: ScanFileContext, rules: Rule[]): Finding[] {
    const findings: Finding[] = [];

    for (const rule of rules) {
      if (rule.enabled === false) continue;

      // Check if rule applies to this language
      if (rule.languages.length > 0 && !rule.languages.includes(context.language) && !rule.languages.includes('*')) {
        continue;
      }

      for (const rulePattern of rule.patterns) {
        // Use regex pattern if available
        const regexStr = rulePattern.regex ?? rulePattern.pattern;
        if (!regexStr) continue;

        try {
          const flags = rulePattern.regexFlags ?? 'gi';
          const regex = new RegExp(regexStr, flags);
          const matches = matchPattern(context.content, regex);

          for (const match of matches) {
            // Skip matches inside comments
            if (isInCommentOrString(match.lineContent, match.column)) continue;

            // Skip matches inside pattern/rule definition contexts (regex literals, data objects)
            if (isPatternDefinitionContext(match.lineContent, match.column)) continue;

            // AST-based context check: skip matches in string literals, comments, imports, type annotations
            if (context.tree && isInSafeASTContext(context.tree, match.line, match.column)) continue;

            // Skip secrets rules matching environment variables or template strings
            if (
              rule.category === 'secrets' ||
              rule.id === 'security/hardcoded-secret' ||
              rule.id.includes('secret') ||
              rule.id.includes('password')
            ) {
              // Skip password/secret rules in test files (dummy credentials are expected)
              // But NOT API key/token rules — those are real leaks even in tests
              const isPasswordRule = rule.id.includes('password') || rule.id.includes('secret') || rule.id === 'security/hardcoded-secret';
              if (isPasswordRule) {
                const TEST_PATH = /(?:^|[\\/])(?:tests?|__tests__|spec|__spec__|fixtures?|mocks?|__mocks__|e2e|integration)[\\/]/i;
                const TEST_FILE = /\.(?:test|spec|mock|fixture)\./i;
                if (TEST_PATH.test(context.filePath) || TEST_FILE.test(context.filePath)) {
                  continue;
                }
              }
              const line = match.lineContent;
              const val = match.match;
              // Skip lines that reference environment variables
              if (
                /process\.env\b|os\.environ|os\.getenv|System\.getenv|System\.getProperty|ENV\[|getenv\s*\(/i.test(line)
              ) {
                continue;
              }
              // Skip template/bracket placeholders or dynamic interpolation (e.g. {DB_PASSWORD}, $DB_PASSWORD, ${DB_PASSWORD})
              if (
                /\{\s*(?:DB_|db_|PASSWORD|PASS|USER|user|HOST|host|PORT|port|NAME|name|SECRET|TOKEN|KEY|API)/.test(line) ||
                /\{\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\}/.test(line) || // generic {variable}
                /\$[a-zA-Z_][a-zA-Z0-9_]*/.test(line) || // generic $variable
                /\$\{[a-zA-Z_][a-zA-Z0-9_]*\}/.test(line) // generic ${variable}
              ) {
                continue;
              }
              // Skip example/placeholder values (excluding high-fidelity test keys like AWS keys containing EXAMPLE)
              if (
                !/^(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}$/i.test(val) &&
                /(?:example|placeholder|your[_-]|changeme|xxxx|TODO|FIXME)/i.test(val)
              ) {
                continue;
              }
            }

            // Skip static assignments to innerHTML in rule-based matchers to avoid false positives
            if (rule.id === 'security/xss-innerhtml' || rule.id === 'insecure-innerhtml') {
              const line = match.lineContent;
              if (line.includes('escapeHtml') || line.includes('escapeHTML') || line.includes('DOMPurify') || line.includes('sanitizeHtml')) {
                continue;
              }
              const innerHtmlMatch = line.match(/\.(?:inner|outer)HTML\s*\+?=\s*(.*)/i);
              if (innerHtmlMatch) {
                let rhs = innerHtmlMatch[1].trim();
                if (rhs.endsWith(';')) {
                  rhs = rhs.slice(0, -1).trim();
                }
                const singleQuoted = /^'[^'\\]*(?:\\.[^'\\]*)*'$/;
                const doubleQuoted = /^"[^"\\]*(?:\\.[^"\\]*)*"$/;
                const backtickQuoted = /^`[^`\\]*(?:\\.[^`\\]*)*`$/;
                const isStaticString = 
                  singleQuoted.test(rhs) || 
                  doubleQuoted.test(rhs) || 
                  (backtickQuoted.test(rhs) && !rhs.includes('${'));
                if (isStaticString) {
                  continue;
                }
              }

              // Skip innerHTML in report/template generator files
              if (
                context.filePath.includes('reporter') ||
                context.filePath.includes('template') ||
                context.filePath.includes('report-generator')
              ) {
                continue;
              }

              // Skip innerHTML where a custom escaping function is used
              if (innerHtmlMatch && /\besc\s*\(/.test(line)) {
                continue;
              }
            }

            // Skip Math.random() in non-cryptographic/non-security contexts
            if (rule.id === 'SEC-CRYPTO-003' || rule.id === 'security/weak-crypto') {
              const trimmed = match.lineContent.trim();
              const isSafeContext = 
                trimmed.includes('id:') ||
                trimmed.includes('id =') ||
                trimmed.includes('key:') ||
                trimmed.includes('key =') ||
                trimmed.includes('reactKey') ||
                trimmed.includes('index') ||
                trimmed.includes('assert') ||
                trimmed.includes('tc.') ||
                /^(?:const|let|var)\s+\w*(?:id|key|uuid|idx|index)\w*\s*=/i.test(trimmed);
              if (isSafeContext) {
                continue;
              }
            }

            // Skip relative imports/requires/includes for path traversal rules to avoid false positives
            if (rule.id === 'security/path-traversal') {
              const line = match.lineContent.trim();
              const isConfigFile = 
                context.filePath.endsWith('.config.js') || 
                context.filePath.endsWith('.config.ts') || 
                context.filePath.includes('vite.config') || 
                context.filePath.includes('webpack.') || 
                context.filePath.includes('tailwind.');

              if (
                line.startsWith('import ') ||
                line.startsWith('import(') ||
                line.startsWith('export ') ||
                line.startsWith('from ') ||
                line.includes('require(') ||
                line.includes('require ') ||
                line.includes('require_once ') ||
                line.includes('include ') ||
                line.includes('include_once ') ||
                isConfigFile
              ) {
                continue;
              }

              // Skip static path constants starting points
              if (
                line.includes('__DIR__') ||
                line.includes('__dirname') ||
                line.includes('__filename') ||
                line.includes('__FILE__') ||
                line.includes('import.meta.url')
              ) {
                if (!/(?:req|request|params|query|body|args|input|user|GET|POST|REQUEST)\b/i.test(line)) {
                  continue;
                }
              }
            }

            // Skip XXE warnings if the XML parser is safely configured in the file
            if (rule.id === 'security/xxe' || rule.id === 'SEC-XXE-001') {
              if (
                context.content.includes('disallow-doctype-decl') ||
                (context.content.includes('external-general-entities') && context.content.includes('external-parameter-entities')) ||
                context.content.includes('SUPPORT_DTD') ||
                context.content.includes('IS_SUPPORTING_EXTERNAL_ENTITIES')
              ) {
                continue;
              }
            }

            // Skip SSRF warnings if the URL is validated in the file
            if (rule.id === 'security/ssrf' || rule.id === 'SEC-SRF-001' || rule.id === 'SEC-SRF-002') {
              if (
                context.content.includes('startsWith') ||
                context.content.includes('validate') ||
                context.content.includes('whitelist') ||
                context.content.includes('trusted')
              ) {
                continue;
              }
            }

            const snippet = extractSnippet(context.content, match.line);
            findings.push(
              createFinding({
                ruleId: rule.id,
                scanner: this.type,
                severity: rule.severity,
                confidence: rule.confidence,
                category: rule.category,
                subcategory: rule.subcategory,
                title: rule.name,
                message: rulePattern.message ?? rule.description,
                filePath: context.filePath,
                lineNumber: match.line,
                column: match.column,
                snippet,
                cwe: rule.cwe,
                owasp: rule.owasp,
                fix: rule.fix ? { description: rule.fix.description, suggestion: rule.fix.replacement, references: rule.references ?? [] } : undefined,
                references: rule.references,
                tags: rule.tags,
              }),
            );
          }
        } catch {
          // Invalid regex pattern – skip silently
        }
      }
    }

    return findings;
  }
}
