import type { Finding } from '../types/finding.js';

/**
 * Represents a parsed suppression rule directive
 */
export interface SuppressionDirective {
  type: 'next-line' | 'current-line' | 'block-start' | 'block-end';
  line: number;
  ruleIds: string[]; // empty array means suppress all rules
}

/**
 * Regular expressions matching DeepScan suppression comments
 * Supports:
 * - // deepscan-disable-next-line [rule1, rule2]
 * - // deepscan-ignore-next-line [rule1, rule2]
 * - // deepscan-disable-line [rule1, rule2]
 * - // deepscan-ignore-line [rule1, rule2]
 * - // deepscan-disable [rule1, rule2]
 * - // deepscan-enable [rule1, rule2]
 * - # deepscan-... (Python/Ruby/Shell/YAML)
 * - /* deepscan-... * / (JS/TS/C/Java/CSS)
 * - -- deepscan-... (SQL/Lua/Haskell)
 */
const SUPPRESSION_REGEX = /(?:\/\/|#|--|\/\*)\s*deepscan-(disable-next-line|ignore-next-line|disable-line|ignore-line|disable|enable)(?:[:\s]+([a-zA-Z0-9_\-\s,\/*]+))?/i;

/**
 * Parse suppression comments from source code content
 */
export function parseSuppressions(content: string): SuppressionDirective[] {
  const lines = content.split('\n');
  const directives: SuppressionDirective[] = [];

  for (let i = 0; i < lines.length; i++) {
    const lineNum = i + 1; // 1-indexed line
    const match = lines[i].match(SUPPRESSION_REGEX);
    if (!match) continue;

    const action = match[1].toLowerCase();
    const rawRuleIds = match[2] ? match[2].split(/[,\s]+/).map(r => r.trim()).filter(Boolean) : [];

    // Filter out trailing comment closers like */
    const ruleIds = rawRuleIds.filter(r => r !== '*/');

    if (action === 'disable-next-line' || action === 'ignore-next-line') {
      directives.push({
        type: 'next-line',
        line: lineNum,
        ruleIds,
      });
    } else if (action === 'disable-line' || action === 'ignore-line') {
      directives.push({
        type: 'current-line',
        line: lineNum,
        ruleIds,
      });
    } else if (action === 'disable') {
      directives.push({
        type: 'block-start',
        line: lineNum,
        ruleIds,
      });
    } else if (action === 'enable') {
      directives.push({
        type: 'block-end',
        line: lineNum,
        ruleIds,
      });
    }
  }

  return directives;
}

/**
 * Check if a specific ruleId matches any of the given suppressed rule patterns
 * Supports wildcard '*' or exact matching / category prefix matching
 */
function matchesRule(ruleId: string, suppressedRuleIds: string[]): boolean {
  if (suppressedRuleIds.length === 0) return true; // empty list means suppress ALL rules
  if (suppressedRuleIds.includes('*')) return true;

  return suppressedRuleIds.some(pattern => {
    if (pattern === ruleId) return true;
    if (pattern.endsWith('*') && ruleId.startsWith(pattern.slice(0, -1))) return true;
    return false;
  });
}

/**
 * Check if a finding at a given location is suppressed by any directive
 */
export function isFindingSuppressed(finding: Finding, directives: SuppressionDirective[]): boolean {
  const findingLine = finding.location.startLine;
  const ruleId = finding.ruleId;

  // 1. Check line-level and next-line directives
  for (const dir of directives) {
    if (dir.type === 'current-line' && dir.line === findingLine) {
      if (matchesRule(ruleId, dir.ruleIds)) return true;
    }

    if (dir.type === 'next-line' && dir.line + 1 === findingLine) {
      if (matchesRule(ruleId, dir.ruleIds)) return true;
    }
  }

  // 2. Check active block-level directives up to finding line
  let isBlockDisabled = false;

  for (const dir of directives) {
    if (dir.line > findingLine) break;

    if (dir.type === 'block-start') {
      if (dir.ruleIds.length === 0 || matchesRule(ruleId, dir.ruleIds)) {
        isBlockDisabled = true;
      }
    } else if (dir.type === 'block-end') {
      if (dir.ruleIds.length === 0 || matchesRule(ruleId, dir.ruleIds)) {
        isBlockDisabled = false;
      }
    }
  }

  return isBlockDisabled;
}

/**
 * Filter out any findings that are suppressed by inline code comments
 */
export function filterSuppressedFindings(findings: Finding[], fileContent: string): Finding[] {
  if (!findings || findings.length === 0) return [];
  const directives = parseSuppressions(fileContent);
  if (directives.length === 0) return findings;

  return findings.filter(finding => !isFindingSuppressed(finding, directives));
}
