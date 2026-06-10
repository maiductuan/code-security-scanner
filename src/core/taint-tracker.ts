import { consola } from 'consola';
import type { TaintFlowStep, SourceLocation } from '../types/finding.js';
import type { TaintSource, TaintSink, Sanitizer } from '../types/scanner.js';
import { getLanguageConfig } from '../languages/registry.js';

/**
 * Taint Tracker - Cross-file data flow analysis
 *
 * Tracks tainted (untrusted) data from sources to sinks,
 * detecting when user input reaches dangerous functions
 * without passing through sanitizers.
 */

/** A tracked taint value */
interface TaintedValue {
  id: string;
  sourceType: string;
  originLocation: SourceLocation;
  currentVariable: string;
  propagationPath: TaintFlowStep[];
  sanitized: Set<string>;
}

/** Result of taint analysis */
export interface TaintResult {
  hasTaintedSink: boolean;
  sourceType: string;
  sinkType: string;
  flow: TaintFlowStep[];
}

/**
 * Analyze a file for taint flow issues
 */
export function analyzeTaintFlow(
  content: string,
  filePath: string,
  language: string,
): TaintResult[] {
  const langConfig = getLanguageConfig(language);
  if (!langConfig) return [];

  const results: TaintResult[] = [];
  const lines = content.split('\n');

  // Find all taint sources in the file
  const taintedVars = findTaintSources(lines, langConfig.taintSources, filePath);

  // Track taint propagation through variable assignments
  propagateTaint(lines, taintedVars, filePath);

  // Check if any tainted value reaches a sink without sanitization
  for (const tainted of taintedVars) {
    const sinkHits = findTaintSinks(lines, tainted, langConfig.taintSinks, langConfig.sanitizers, filePath);
    results.push(...sinkHits);
  }

  return results;
}

/**
 * Find taint sources (user input, environment, etc.)
 */
function findTaintSources(
  lines: string[],
  sources: TaintSource[],
  filePath: string,
): TaintedValue[] {
  const tainted: TaintedValue[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith('//') || line.startsWith('#') || line.startsWith('*')) continue;

    for (const source of sources) {
      if (line.includes(source.pattern.replace('$TAINTED', '').replace('()', ''))) {
        // Try to extract the variable being assigned
        const assignMatch = line.match(/(?:const|let|var|final|auto)?\s*(\w+)\s*=.*$/);
        const varName = assignMatch ? assignMatch[1] : `__tainted_${i}`;

        tainted.push({
          id: `taint_${i}_${varName}`,
          sourceType: source.type,
          originLocation: {
            file: filePath,
            startLine: i + 1,
            startColumn: 0,
            endLine: i + 1,
            endColumn: line.length,
            snippet: line,
          },
          currentVariable: varName,
          propagationPath: [{
            location: {
              file: filePath,
              startLine: i + 1,
              startColumn: 0,
              endLine: i + 1,
              endColumn: line.length,
              snippet: line,
            },
            label: `Source: ${source.description} (${source.type})`,
            kind: 'source',
          }],
          sanitized: new Set(),
        });
      }
    }
  }

  return tainted;
}

/**
 * Track taint propagation through assignments
 */
function propagateTaint(
  lines: string[],
  taintedVars: TaintedValue[],
  filePath: string,
): void {
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;

    for (const tainted of taintedVars) {
      // Check if this line uses the tainted variable in an assignment
      if (line.includes(tainted.currentVariable)) {
        const assignMatch = line.match(/(?:const|let|var|final|auto)?\s*(\w+)\s*=.*$/);
        if (assignMatch && assignMatch[1] !== tainted.currentVariable) {
          // Taint propagates to new variable
          const newVar = assignMatch[1];
          tainted.propagationPath.push({
            location: {
              file: filePath,
              startLine: i + 1,
              startColumn: 0,
              endLine: i + 1,
              endColumn: line.length,
              snippet: line,
            },
            label: `Propagated: ${tainted.currentVariable} → ${newVar}`,
            kind: 'propagator',
          });
          tainted.currentVariable = newVar;
        }
      }
    }
  }
}

/**
 * Find taint sinks and check for sanitization
 */
function findTaintSinks(
  lines: string[],
  tainted: TaintedValue,
  sinks: TaintSink[],
  sanitizers: Sanitizer[],
  filePath: string,
): TaintResult[] {
  const results: TaintResult[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;

    // Check for sanitizers first
    for (const sanitizer of sanitizers) {
      const sanitizerPattern = sanitizer.pattern.replace('$X', '').replace('()', '');
      if (line.includes(sanitizerPattern) && line.includes(tainted.currentVariable)) {
        for (const cleansed of sanitizer.cleanses) {
          tainted.sanitized.add(cleansed);
        }
        tainted.propagationPath.push({
          location: {
            file: filePath,
            startLine: i + 1,
            startColumn: 0,
            endLine: i + 1,
            endColumn: line.length,
            snippet: line,
          },
          label: `Sanitized: ${sanitizer.description}`,
          kind: 'sanitizer',
        });
      }
    }

    // Check for sinks
    for (const sink of sinks) {
      const sinkPattern = sink.pattern
        .replace('$TAINTED', '')
        .replace('$BUF', '')
        .replace('()', '')
        .replace('(', '')
        .replace(')', '');

      if (line.includes(sinkPattern) && line.includes(tainted.currentVariable)) {
        // Check if this sink type has been sanitized
        if (tainted.sanitized.has(sink.type)) {
          continue; // Sanitized, skip
        }

        const flow: TaintFlowStep[] = [
          ...tainted.propagationPath,
          {
            location: {
              file: filePath,
              startLine: i + 1,
              startColumn: 0,
              endLine: i + 1,
              endColumn: line.length,
              snippet: line,
            },
            label: `Sink: ${sink.description} (${sink.type})`,
            kind: 'sink',
          },
        ];

        results.push({
          hasTaintedSink: true,
          sourceType: tainted.sourceType,
          sinkType: sink.type,
          flow,
        });
      }
    }
  }

  return results;
}
