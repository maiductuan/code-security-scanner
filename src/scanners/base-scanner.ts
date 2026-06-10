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

            // Skip secrets rules matching environment variables or template strings
            if (
              rule.category === 'secrets' ||
              rule.id === 'security/hardcoded-secret' ||
              rule.id.includes('secret') ||
              rule.id.includes('password')
            ) {
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
