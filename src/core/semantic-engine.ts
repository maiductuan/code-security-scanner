import { consola } from 'consola';

/**
 * Semantic Engine - Code comparison at the semantic level
 *
 * Instead of comparing code by exact text match, this engine normalizes
 * code to its semantic meaning and compares structures.
 */

/** A normalized code token */
interface NormalizedToken {
  type: 'keyword' | 'operator' | 'identifier' | 'literal' | 'delimiter' | 'call' | 'other';
  value: string;
  normalized: string;
}

/**
 * Normalize code for semantic comparison
 * - Renames all variables to generic placeholders (v1, v2, ...)
 * - Normalizes string/number literals
 * - Preserves structure (keywords, operators, calls)
 */
export function normalizeCode(code: string): string {
  const lines = code.split('\n');
  const varMap = new Map<string, string>();
  let varCounter = 0;

  const normalized = lines.map(line => {
    let result = line.trim();
    if (!result || result.startsWith('//') || result.startsWith('#') || result.startsWith('*')) {
      return ''; // Remove comments and empty lines
    }

    // Normalize string literals
    result = result.replace(/(["'`])(?:(?!\1|\\).|\\.)*\1/g, '"__STR__"');

    // Normalize number literals
    result = result.replace(/\b\d+(?:\.\d+)?\b/g, '__NUM__');

    // Normalize variable names (but keep keywords and function calls)
    const keywords = new Set([
      'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'break', 'continue',
      'return', 'function', 'class', 'const', 'let', 'var', 'import', 'export',
      'from', 'default', 'async', 'await', 'try', 'catch', 'finally', 'throw',
      'new', 'this', 'super', 'typeof', 'instanceof', 'void', 'delete',
      'true', 'false', 'null', 'undefined', 'in', 'of', 'yield',
      'def', 'elif', 'except', 'raise', 'pass', 'lambda', 'with', 'as',
      'public', 'private', 'protected', 'static', 'final', 'abstract',
      'interface', 'extends', 'implements', 'package', 'type', 'enum',
    ]);

    result = result.replace(/\b([a-zA-Z_]\w*)\b/g, (match) => {
      if (keywords.has(match)) return match;
      if (match.startsWith('__') && match.endsWith('__')) return match;
      if (!varMap.has(match)) {
        varMap.set(match, `v${varCounter++}`);
      }
      return varMap.get(match)!;
    });

    return result;
  }).filter(l => l.length > 0);

  return normalized.join('\n');
}

/**
 * Calculate semantic similarity between two code blocks (0-1)
 */
export function calculateSemanticSimilarity(code1: string, code2: string): number {
  const normalized1 = normalizeCode(code1);
  const normalized2 = normalizeCode(code2);

  if (normalized1 === normalized2) return 1.0;

  // Use token-based comparison
  const tokens1 = tokenize(normalized1);
  const tokens2 = tokenize(normalized2);

  if (tokens1.length === 0 || tokens2.length === 0) return 0;

  // Calculate Jaccard similarity on token n-grams
  const ngrams1 = getNGrams(tokens1, 3);
  const ngrams2 = getNGrams(tokens2, 3);

  const intersection = new Set([...ngrams1].filter(x => ngrams2.has(x)));
  const union = new Set([...ngrams1, ...ngrams2]);

  if (union.size === 0) return 0;
  return intersection.size / union.size;
}

/**
 * Detect semantically equivalent patterns
 */
export function detectSemanticEquivalence(code: string): SemanticPattern[] {
  const patterns: SemanticPattern[] = [];

  // Detect DeMorgan's law violations: !(a && b) vs !a || !b
  const demorganPattern = /!\s*\(([^)]+)\s*&&\s*([^)]+)\)/g;
  let match;
  while ((match = demorganPattern.exec(code)) !== null) {
    patterns.push({
      type: 'demorgan',
      original: match[0],
      suggestion: `!${match[1].trim()} || !${match[2].trim()}`,
      line: code.substring(0, match.index).split('\n').length,
    });
  }

  // Detect ternary that could be simplified: condition ? true : false → condition
  const ternaryBoolPattern = /(\w+)\s*\?\s*true\s*:\s*false/g;
  while ((match = ternaryBoolPattern.exec(code)) !== null) {
    patterns.push({
      type: 'unnecessary-ternary',
      original: match[0],
      suggestion: match[1],
      line: code.substring(0, match.index).split('\n').length,
    });
  }

  // Detect: if (condition) return true; else return false; → return condition;
  const ifReturnBoolPattern = /if\s*\([^)]+\)\s*(?:return\s+true|{\s*return\s+true\s*;?\s*})\s*;?\s*(?:else\s*)?(?:return\s+false|{\s*return\s+false\s*;?\s*})/g;
  while ((match = ifReturnBoolPattern.exec(code)) !== null) {
    patterns.push({
      type: 'simplify-boolean-return',
      original: match[0],
      suggestion: 'return <condition>;',
      line: code.substring(0, match.index).split('\n').length,
    });
  }

  // Detect double negation: !!variable → Boolean(variable)
  const doubleNegPattern = /!!(\w+)/g;
  while ((match = doubleNegPattern.exec(code)) !== null) {
    patterns.push({
      type: 'double-negation',
      original: match[0],
      suggestion: `Boolean(${match[1]})`,
      line: code.substring(0, match.index).split('\n').length,
    });
  }

  return patterns;
}

/** Tokenize normalized code */
function tokenize(code: string): string[] {
  return code.split(/\s+|(?=[{}()[\],;.])|(?<=[{}()[\],;.])/).filter(t => t.length > 0);
}

/** Generate n-grams from token array */
function getNGrams(tokens: string[], n: number): Set<string> {
  const ngrams = new Set<string>();
  for (let i = 0; i <= tokens.length - n; i++) {
    ngrams.add(tokens.slice(i, i + n).join(' '));
  }
  return ngrams;
}

export interface SemanticPattern {
  type: string;
  original: string;
  suggestion: string;
  line: number;
}
