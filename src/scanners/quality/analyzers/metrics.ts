// ─── Metrics Analyzer ──────────────────────────────────────────────────────
// Tính toán các chỉ số code: LOC, comment ratio, blank lines
// Calculate lines of code, comment ratio, and generate warnings

import type { Finding } from '../../../types/finding.js';
import type { ScanFileContext } from '../../../types/scanner.js';
import type { QualityThresholds } from '../../../types/config.js';
import { createFinding } from '../../base-scanner.js';

// ─── Default Thresholds ────────────────────────────────────────────────────

const DEFAULT_MIN_COMMENT_RATIO = 0.1;

// ─── Metrics Interface ────────────────────────────────────────────────────

export interface CodeMetrics {
  totalLines: number;
  codeLines: number;
  commentLines: number;
  blankLines: number;
  commentRatio: number;
}

// ─── Comment Patterns ──────────────────────────────────────────────────────

interface CommentPatterns {
  singleLine: RegExp[];
  multiLineStart: RegExp;
  multiLineEnd: RegExp;
}

/** Get comment patterns based on file language */
function getCommentPatterns(language: string): CommentPatterns {
  switch (language) {
    case 'python':
      return {
        singleLine: [/^\s*#/],
        multiLineStart: /^\s*(?:"""|''')/,
        multiLineEnd: /(?:"""|''')\s*$/,
      };
    case 'html':
    case 'xml':
      return {
        singleLine: [],
        multiLineStart: /^\s*<!--/,
        multiLineEnd: /-->\s*$/,
      };
    case 'css':
    case 'scss':
    case 'less':
      return {
        singleLine: [/^\s*\/\//],
        multiLineStart: /^\s*\/\*/,
        multiLineEnd: /\*\/\s*$/,
      };
    case 'ruby':
      return {
        singleLine: [/^\s*#/],
        multiLineStart: /^\s*=begin/,
        multiLineEnd: /^\s*=end/,
      };
    case 'lua':
      return {
        singleLine: [/^\s*--(?!\[)/],
        multiLineStart: /^\s*--\[\[/,
        multiLineEnd: /\]\]/,
      };
    // JavaScript, TypeScript, Java, C, C++, C#, Go, Rust, PHP, Swift, Kotlin
    default:
      return {
        singleLine: [/^\s*\/\//, /^\s*\*/],
        multiLineStart: /^\s*\/\*/,
        multiLineEnd: /\*\/\s*$/,
      };
  }
}

// ─── Metric Calculation ────────────────────────────────────────────────────

/**
 * Calculate code metrics for the given source.
 * Tính toán các chỉ số code cho mã nguồn
 */
export function calculateMetrics(content: string, language: string): CodeMetrics {
  const lines = content.split('\n');
  const patterns = getCommentPatterns(language);

  let codeLines = 0;
  let commentLines = 0;
  let blankLines = 0;
  let inMultiLineComment = false;

  for (const line of lines) {
    const trimmed = line.trim();

    // Blank line
    if (trimmed.length === 0) {
      blankLines++;
      continue;
    }

    // Multi-line comment handling
    if (inMultiLineComment) {
      commentLines++;
      if (patterns.multiLineEnd.test(trimmed)) {
        inMultiLineComment = false;
      }
      continue;
    }

    // Check for multi-line comment start
    if (patterns.multiLineStart.test(trimmed)) {
      commentLines++;
      // Check if multi-line comment ends on same line
      if (!patterns.multiLineEnd.test(trimmed) || trimmed === '/**/') {
        // For patterns where start and end are the same (Python docstrings)
        if (patterns.multiLineStart.source === patterns.multiLineEnd.source) {
          // Count opening triple-quotes on the line
          const startMatches = trimmed.match(patterns.multiLineStart);
          if (startMatches && (trimmed.match(/"""/g) || []).length < 2 && (trimmed.match(/'''/g) || []).length < 2) {
            inMultiLineComment = true;
          }
        } else if (!patterns.multiLineEnd.test(trimmed.substring(trimmed.indexOf('/*') + 2))) {
          inMultiLineComment = true;
        }
      }
      continue;
    }

    // Single-line comment
    let isComment = false;
    for (const singlePattern of patterns.singleLine) {
      if (singlePattern.test(trimmed)) {
        commentLines++;
        isComment = true;
        break;
      }
    }
    if (isComment) continue;

    // Code line (may contain inline comment but still counts as code)
    codeLines++;
  }

  const totalLines = lines.length;
  const commentRatio = totalLines > 0 ? commentLines / totalLines : 0;

  return {
    totalLines,
    codeLines,
    commentLines,
    blankLines,
    commentRatio,
  };
}

// ─── Main Analyzer Function ────────────────────────────────────────────────

/**
 * Analyze source code and calculate metrics, generating findings if thresholds are breached.
 * Phân tích mã nguồn, tính toán chỉ số và tạo finding nếu vượt ngưỡng
 */
export function analyzeMetrics(context: ScanFileContext): Finding[] {
  const findings: Finding[] = [];
  const { content, filePath, language, config } = context;

  if (content.length < 10) return findings;

  const thresholds = config?.scanners?.quality?.thresholds;
  const minCommentRatio = thresholds?.minCommentRatio ?? DEFAULT_MIN_COMMENT_RATIO;

  const metrics = calculateMetrics(content, language);

  // Generate info finding with metrics summary
  findings.push(
    createFinding({
      ruleId: 'QUA-METRICS-001',
      scanner: 'quality',
      severity: 'low',
      confidence: 'high',
      category: 'metrics',
      subcategory: 'code-metrics',
      title: 'Code Metrics',
      message: `Lines: ${metrics.totalLines} total, ${metrics.codeLines} code, ${metrics.commentLines} comments, ${metrics.blankLines} blank. Comment ratio: ${(metrics.commentRatio * 100).toFixed(1)}%`,
      filePath,
      lineNumber: 1,
      snippet: '',
      tags: ['metrics'],
    }),
  );

  // Warn if comment ratio is below threshold (only for files with enough code)
  if (metrics.codeLines > 50 && metrics.commentRatio < minCommentRatio) {
    findings.push(
      createFinding({
        ruleId: 'QUA-METRICS-002',
        scanner: 'quality',
        severity: 'low',
        confidence: 'medium',
        category: 'metrics',
        subcategory: 'comment-ratio',
        title: 'Low Comment Ratio',
        message: `Comment ratio is ${(metrics.commentRatio * 100).toFixed(1)}% (threshold: ${(minCommentRatio * 100).toFixed(1)}%). Consider adding documentation comments.`,
        filePath,
        lineNumber: 1,
        snippet: '',
        tags: ['metrics', 'documentation'],
        fix: {
          description: 'Add JSDoc/docstring comments to exported functions, classes, and complex logic. Focus on "why" rather than "what".',
          references: [],
        },
      }),
    );
  }

  return findings;
}
