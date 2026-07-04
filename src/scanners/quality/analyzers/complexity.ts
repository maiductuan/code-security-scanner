// ─── Complexity Analyzer ───────────────────────────────────────────────────
// Phân tích độ phức tạp: cyclomatic, nesting depth, function length
// Calculates cyclomatic complexity, detects deep nesting and long functions

import type { Finding } from '../../../types/finding.js';
import type { ScanFileContext } from '../../../types/scanner.js';
import type { QualityThresholds } from '../../../types/config.js';
import { createFinding, extractSnippet } from '../../base-scanner.js';

// ─── Default Thresholds ────────────────────────────────────────────────────

const DEFAULT_THRESHOLDS: QualityThresholds = {
  maxComplexity: 10,
  maxCognitiveComplexity: 15,
  maxFileLength: 500,
  maxFunctionLength: 50,
  maxNestingDepth: 4,
  minCommentRatio: 0.1,
};

// ─── Regex Patterns for Decision Points ────────────────────────────────────

/** Decision point patterns that increase cyclomatic complexity */
const DECISION_POINT_PATTERNS: RegExp[] = [
  /\bif\s*\(/,                      // if statements
  /\belse\s+if\s*\(/,              // else if
  /\bfor\s*\(/,                     // for loops
  /\bwhile\s*\(/,                   // while loops
  /\bdo\s*\{/,                      // do-while
  /\bcase\s+[^:]+:/,               // switch case
  /\bcatch\s*\(/,                   // catch blocks
  /\?\s*[^:]+\s*:/,                // ternary operator
  /\?\./,                           // optional chaining (counts as potential branch)
  /&&(?!=)/,                         // logical AND
  /\|\|(?!=)/,                       // logical OR
  /\?\?/,                           // nullish coalescing
];

/** Function declaration/expression patterns */
const FUNCTION_PATTERNS: RegExp[] = [
  /(?:function\s+\w+|(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?function)\s*\(/,
  /(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?\([^)]*\)\s*=>/,
  /(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?\w+\s*=>/,
  /(?:public|private|protected|static|async)\s+\w+\s*\([^)]*\)\s*(?::\s*\w+[<\[\]>|&\s]*)?\s*\{/,
  /\w+\s*\([^)]*\)\s*\{/,  // method shorthand
  /def\s+\w+\s*\(/,          // Python function def
];

// ─── Nesting Depth Tracking ───────────────────────────────────────────────

interface NestingInfo {
  line: number;
  depth: number;
}

/**
 * Track nesting depth throughout the file.
 * Theo dõi độ sâu lồng nhau trong tệp
 */
function calculateNestingDepths(lines: string[]): NestingInfo[] {
  const results: NestingInfo[] = [];
  let currentDepth = 0;
  let inMultiLineComment = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    // Track multi-line comments
    if (line.includes('/*') && !line.includes('*/')) {
      inMultiLineComment = true;
    }
    if (line.includes('*/')) {
      inMultiLineComment = false;
      continue;
    }
    if (inMultiLineComment || line.startsWith('//') || line.startsWith('#') || line.startsWith('*')) {
      results.push({ line: i + 1, depth: currentDepth });
      continue;
    }

    // Count braces to track depth
    const openBraces = (line.match(/\{/g) || []).length;
    const closeBraces = (line.match(/\}/g) || []).length;

    // Depth before processing this line (for accurate reporting)
    results.push({ line: i + 1, depth: currentDepth + openBraces });

    currentDepth += openBraces - closeBraces;
    if (currentDepth < 0) currentDepth = 0;
  }

  return results;
}

// ─── Function Extraction ───────────────────────────────────────────────────

interface FunctionInfo {
  name: string;
  startLine: number;
  endLine: number;
  complexity: number;
  lineCount: number;
}

/**
 * Extract functions and calculate their complexity.
 * Trích xuất hàm và tính độ phức tạp cyclomatic
 */
function extractFunctions(lines: string[]): FunctionInfo[] {
  const functions: FunctionInfo[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // Skip comments
    if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*') || trimmed.startsWith('/*')) {
      continue;
    }

    // Check if this line starts a function
    let funcName = '';
    for (const pattern of FUNCTION_PATTERNS) {
      const match = pattern.exec(trimmed);
      if (match) {
        // Try to extract function name
        const nameMatch = trimmed.match(/(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=|(\w+)\s*\(|def\s+(\w+))/);
        funcName = nameMatch?.[1] || nameMatch?.[2] || nameMatch?.[3] || nameMatch?.[4] || 'anonymous';
        break;
      }
    }

    if (!funcName) continue;

    // Find the end of the function by tracking braces
    let braceCount = 0;
    let startedBody = false;
    let endLine = i;

    for (let j = i; j < lines.length; j++) {
      const currentLine = lines[j];
      for (const ch of currentLine) {
        if (ch === '{') {
          braceCount++;
          startedBody = true;
        } else if (ch === '}') {
          braceCount--;
        }
      }
      if (startedBody && braceCount <= 0) {
        endLine = j;
        break;
      }
      // Safety: don't look beyond 500 lines
      if (j - i > 500) {
        endLine = j;
        break;
      }
    }

    // For Python (indentation-based), estimate end by looking at indentation
    if (!startedBody && trimmed.startsWith('def ')) {
      const baseIndent = line.length - line.trimStart().length;
      endLine = i;
      for (let j = i + 1; j < lines.length; j++) {
        const jLine = lines[j];
        if (jLine.trim() === '') continue;
        const jIndent = jLine.length - jLine.trimStart().length;
        if (jIndent <= baseIndent && jLine.trim() !== '') break;
        endLine = j;
      }
    }

    // Calculate cyclomatic complexity for this function
    let complexity = 1; // Base complexity
    for (let j = i; j <= endLine; j++) {
      const funcLine = lines[j];
      for (const dpPattern of DECISION_POINT_PATTERNS) {
        const dpMatches = funcLine.match(new RegExp(dpPattern.source, 'g'));
        if (dpMatches) {
          complexity += dpMatches.length;
        }
      }
    }

    functions.push({
      name: funcName,
      startLine: i + 1,
      endLine: endLine + 1,
      complexity,
      lineCount: endLine - i + 1,
    });
  }

  return functions;
}

// ─── Main Analyzer Function ────────────────────────────────────────────────

/**
 * Analyze source code for complexity issues.
 * Phân tích mã nguồn về vấn đề độ phức tạp
 */
export function analyzeComplexity(context: ScanFileContext): Finding[] {
  const findings: Finding[] = [];
  const { content, filePath, config } = context;

  if (content.length < 10) return findings;

  const thresholds = config?.scanners?.quality?.thresholds ?? DEFAULT_THRESHOLDS;
  const lines = content.split('\n');

  // Extract functions and analyze complexity
  const functions = extractFunctions(lines);

  for (const func of functions) {
    // Check cyclomatic complexity
    if (func.complexity > thresholds.maxComplexity) {
      const contextLines = 3;
      const snippet = extractSnippet(content, func.startLine, func.endLine, contextLines);
      const snippetStartLine = Math.max(1, func.startLine - contextLines);
      findings.push(
        createFinding({
          ruleId: 'QUA-CMPLX-001',
          scanner: 'quality',
          severity: func.complexity > thresholds.maxComplexity * 2 ? 'high' : 'medium',
          confidence: 'high',
          category: 'complexity',
          subcategory: 'cyclomatic',
          title: 'High Cyclomatic Complexity',
          message: `Function '${func.name}' has cyclomatic complexity of ${func.complexity} (threshold: ${thresholds.maxComplexity})`,
          filePath,
          lineNumber: func.startLine,
          endLine: func.endLine,
          snippet,
          snippetStartLine,
          tags: ['complexity', 'maintainability'],
          fix: {
            description: 'Refactor the function to reduce complexity. Extract helper functions, use early returns, or simplify conditional logic.',
            references: [],
          },
        }),
      );
    }

    // Check function length
    if (func.lineCount > thresholds.maxFunctionLength) {
      const contextLines = 3;
      const snippet = extractSnippet(content, func.startLine, func.endLine, contextLines);
      const snippetStartLine = Math.max(1, func.startLine - contextLines);
      findings.push(
        createFinding({
          ruleId: 'QUA-CMPLX-002',
          scanner: 'quality',
          severity: func.lineCount > thresholds.maxFunctionLength * 2 ? 'high' : 'medium',
          confidence: 'high',
          category: 'complexity',
          subcategory: 'function-length',
          title: 'Long Function',
          message: `Function '${func.name}' has ${func.lineCount} lines (threshold: ${thresholds.maxFunctionLength})`,
          filePath,
          lineNumber: func.startLine,
          endLine: func.endLine,
          snippet,
          snippetStartLine,
          tags: ['complexity', 'maintainability'],
          fix: {
            description: 'Break the function into smaller, focused functions. Each function should do one thing well.',
            references: [],
          },
        }),
      );
    }
  }

  // Check nesting depth
  const nestingInfos = calculateNestingDepths(lines);
  let lastReportedLine = -1;

  for (const info of nestingInfos) {
    if (info.depth > thresholds.maxNestingDepth && info.line - lastReportedLine > 5) {
      const lineContent = lines[info.line - 1]?.trim();
      // Only report on lines that actually introduce nesting
      if (lineContent && (lineContent.includes('{') || /^\s*(?:if|for|while|switch|try)\b/.test(lineContent))) {
        const snippet = extractSnippet(content, info.line);
        findings.push(
          createFinding({
            ruleId: 'QUA-CMPLX-003',
            scanner: 'quality',
            severity: info.depth > thresholds.maxNestingDepth + 2 ? 'high' : 'medium',
            confidence: 'high',
            category: 'complexity',
            subcategory: 'nesting-depth',
            title: 'Deep Nesting',
            message: `Code is nested ${info.depth} levels deep (threshold: ${thresholds.maxNestingDepth})`,
            filePath,
            lineNumber: info.line,
            snippet,
            tags: ['complexity', 'readability'],
            fix: {
              description: 'Reduce nesting by using early returns, guard clauses, or extracting logic into helper functions.',
              references: [],
            },
          }),
        );
        lastReportedLine = info.line;
      }
    }
  }

  return findings;
}
