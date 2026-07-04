// ─── Duplication Analyzer ──────────────────────────────────────────────────
// Phát hiện mã nguồn trùng lặp sử dụng token-based comparison
// Token-based code duplication detection

import type { Finding } from '../../../types/finding.js';
import type { ScanFileContext } from '../../../types/scanner.js';
import { createFinding, extractSnippet } from '../../base-scanner.js';

// ─── Configuration ─────────────────────────────────────────────────────────

/** Default minimum number of lines for a block to be considered a duplicate */
const DEFAULT_MIN_LINES = 6;

/** Default minimum token count for a match */
const DEFAULT_MIN_TOKENS = 30;

// ─── Token Normalization ───────────────────────────────────────────────────

/**
 * Normalize a line of code into a token sequence.
 * Removes whitespace, comments, and normalizes identifiers to detect structural duplicates.
 * Chuẩn hóa dòng mã thành chuỗi token
 */
function tokenizeLine(line: string): string {
  let normalized = line.trim();

  // Remove single-line comments
  normalized = normalized.replace(/\/\/.*$/, '');
  normalized = normalized.replace(/#.*$/, '');

  // Remove inline comments
  normalized = normalized.replace(/\/\*.*?\*\//g, '');

  // Normalize whitespace
  normalized = normalized.replace(/\s+/g, ' ').trim();

  // Skip empty lines after normalization
  if (normalized.length === 0) return '';

  // Normalize string literals to a placeholder
  normalized = normalized.replace(/"[^"]*"/g, '"STR"');
  normalized = normalized.replace(/'[^']*'/g, "'STR'");
  normalized = normalized.replace(/`[^`]*`/g, '`STR`');

  // Normalize numeric literals
  normalized = normalized.replace(/\b\d+\.?\d*\b/g, 'NUM');

  return normalized;
}

// ─── Block Hashing ─────────────────────────────────────────────────────────

interface CodeBlock {
  startLine: number;
  endLine: number;
  hash: string;
  tokenCount: number;
}

/**
 * Generate rolling hashes for blocks of normalized code.
 * Tạo hash cuốn cho các khối mã đã chuẩn hóa
 */
function generateBlocks(lines: string[], minLines: number): CodeBlock[] {
  const blocks: CodeBlock[] = [];
  const tokenizedLines: Array<{ line: number; tokens: string }> = [];

  // Tokenize each line, skipping empty and trivial lines
  for (let i = 0; i < lines.length; i++) {
    const tokens = tokenizeLine(lines[i]);
    if (tokens.length > 0 && tokens !== '}' && tokens !== '{' && tokens !== ');') {
      tokenizedLines.push({ line: i + 1, tokens });
    }
  }

  // Create sliding windows of minLines
  for (let i = 0; i <= tokenizedLines.length - minLines; i++) {
    const blockTokens: string[] = [];
    let totalTokenCount = 0;

    for (let j = 0; j < minLines; j++) {
      blockTokens.push(tokenizedLines[i + j].tokens);
      totalTokenCount += tokenizedLines[i + j].tokens.split(' ').length;
    }

    const hash = blockTokens.join('\n');
    blocks.push({
      startLine: tokenizedLines[i].line,
      endLine: tokenizedLines[i + minLines - 1].line,
      hash,
      tokenCount: totalTokenCount,
    });
  }

  return blocks;
}

// ─── Duplicate Detection ───────────────────────────────────────────────────

interface DuplicatePair {
  blockA: CodeBlock;
  blockB: CodeBlock;
}

/**
 * Find duplicate blocks within a file.
 * Tìm các khối mã trùng lặp trong tệp
 */
function findDuplicates(blocks: CodeBlock[], minTokens: number): DuplicatePair[] {
  const hashMap = new Map<string, CodeBlock[]>();
  const duplicates: DuplicatePair[] = [];

  for (const block of blocks) {
    if (block.tokenCount < minTokens) continue;

    const existing = hashMap.get(block.hash);
    if (existing) {
      existing.push(block);
    } else {
      hashMap.set(block.hash, [block]);
    }
  }

  // Track reported line ranges to avoid overlapping reports
  const reportedRanges = new Set<string>();

  for (const [, blockGroup] of hashMap) {
    if (blockGroup.length < 2) continue;

    // Report pairs (only report first duplicate pair per unique block)
    for (let i = 0; i < blockGroup.length - 1; i++) {
      for (let j = i + 1; j < blockGroup.length; j++) {
        const blockA = blockGroup[i];
        const blockB = blockGroup[j];

        // Skip overlapping blocks
        if (
          (blockA.startLine >= blockB.startLine && blockA.startLine <= blockB.endLine) ||
          (blockB.startLine >= blockA.startLine && blockB.startLine <= blockA.endLine)
        ) {
          continue;
        }

        const rangeKey = `${blockA.startLine}-${blockA.endLine}:${blockB.startLine}-${blockB.endLine}`;
        const reverseKey = `${blockB.startLine}-${blockB.endLine}:${blockA.startLine}-${blockA.endLine}`;

        if (reportedRanges.has(rangeKey) || reportedRanges.has(reverseKey)) continue;

        reportedRanges.add(rangeKey);
        duplicates.push({ blockA, blockB });
      }
    }
  }

  return duplicates;
}

// ─── Main Analyzer Function ────────────────────────────────────────────────

/**
 * Analyze source code for duplicated blocks.
 * Phân tích mã nguồn để tìm các khối mã trùng lặp
 */
export function analyzeDuplication(context: ScanFileContext): Finding[] {
  const findings: Finding[] = [];
  const { content, filePath } = context;

  if (content.length < 100) return findings;

  const lines = content.split('\n');

  // Skip very short files
  if (lines.length < DEFAULT_MIN_LINES * 2) return findings;

  // Generate normalized code blocks
  const blocks = generateBlocks(lines, DEFAULT_MIN_LINES);

  // Find duplicates
  const duplicates = findDuplicates(blocks, DEFAULT_MIN_TOKENS);

  // Cap the number of findings per file to avoid noise
  const maxFindings = 10;
  const limitedDuplicates = duplicates.slice(0, maxFindings);

  for (const dup of limitedDuplicates) {
    const snippet = extractSnippet(content, dup.blockA.startLine, dup.blockA.endLine, 1);
    const snippetStartLine = Math.max(1, dup.blockA.startLine - 1);
    const lineCount = dup.blockA.endLine - dup.blockA.startLine + 1;

    findings.push(
      createFinding({
        ruleId: 'QUA-DUP-001',
        scanner: 'quality',
        severity: lineCount > 20 ? 'medium' : 'low',
        confidence: 'high',
        category: 'duplication',
        subcategory: 'code-clone',
        title: 'Duplicated Code Block',
        message: `Duplicated code block (${lineCount} lines): lines ${dup.blockA.startLine}-${dup.blockA.endLine} and lines ${dup.blockB.startLine}-${dup.blockB.endLine}`,
        filePath,
        lineNumber: dup.blockA.startLine,
        endLine: dup.blockA.endLine,
        snippet,
        snippetStartLine,
        tags: ['duplication', 'maintainability'],
        fix: {
          description: 'Extract the duplicated code into a shared function or utility. Follow the DRY principle.',
          references: [],
        },
      }),
    );
  }

  return findings;
}
