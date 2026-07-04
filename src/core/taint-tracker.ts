import { consola } from 'consola';
import type { TaintFlowStep, SourceLocation } from '../types/finding.js';
import type { TaintSource, TaintSink, Sanitizer } from '../types/scanner.js';
import { getLanguageConfig } from '../languages/registry.js';
import type { Tree, Node } from 'web-tree-sitter';

/**
 * Taint Tracker - Data flow analysis
 *
 * Tracks tainted (untrusted) data from sources to sinks.
 * Uses AST traversal when tree-sitter is available for high accuracy,
 * falls back to regex-based heuristics if no AST.
 */

export interface TaintResult {
  hasTaintedSink: boolean;
  sourceType: string;
  sinkType: string;
  flow: TaintFlowStep[];
}

interface TaintedValue {
  id: string;
  sourceType: string;
  originLocation: SourceLocation;
  currentVariable: string;
  propagationPath: TaintFlowStep[];
  sanitized: Set<string>;
}

/**
 * Analyze a file for taint flow issues
 */
export function analyzeTaintFlow(
  content: string,
  filePath: string,
  language: string,
  tree?: Tree | null
): TaintResult[] {
  const langConfig = getLanguageConfig(language);
  if (!langConfig) return [];

  if (tree) {
    return analyzeTaintFlowAST(tree, content, filePath, langConfig.taintSources, langConfig.taintSinks, langConfig.sanitizers);
  } else {
    // Fallback to old regex-based tracker
    return analyzeTaintFlowRegex(content, filePath, langConfig.taintSources, langConfig.taintSinks, langConfig.sanitizers);
  }
}

// ─── AST-Based Tracker ───────────────────────────────────────────────────────

function analyzeTaintFlowAST(
  tree: Tree,
  content: string,
  filePath: string,
  sources: TaintSource[],
  sinks: TaintSink[],
  sanitizers: Sanitizer[]
): TaintResult[] {
  const results: TaintResult[] = [];
  
  // A map of tainted variable names to their tracking data within the current file
  const taintedVars = new Map<string, TaintedValue>();

  // A helper to create a SourceLocation from a SyntaxNode
  const getLocation = (node: Node): SourceLocation => ({
    file: filePath,
    startLine: node.startPosition.row + 1,
    startColumn: node.startPosition.column,
    endLine: node.endPosition.row + 1,
    endColumn: node.endPosition.column,
    snippet: node.text.split('\n')[0],
  });

  // Pre-process sink names for quick lookup
  const sinkNames = sinks.map(s => s.pattern.replace(/\$TAINTED|\(|\)/g, '').replace(/[^a-zA-Z0-9_.]/g, ''));
  const sourceNames = sources.map(s => s.pattern.replace(/\$TAINTED|\(|\)/g, '').replace(/[^a-zA-Z0-9_.]/g, ''));

  // First pass: Find sources and track assignments (Simulating control flow simply via tree order)
  function traverse(node: Node) {
    // 1. Variable Declarations (var/let/const x = y)
    if (node.type === 'variable_declarator') {
      const idNode = node.childForFieldName('name') || node.children.find(n => n.type === 'identifier');
      const valueNode = node.childForFieldName('value');
      
      if (idNode && valueNode) {
        checkAssignment(idNode, valueNode);
      }
    }

    // 2. Assignments (x = y)
    if (node.type === 'assignment_expression') {
      const leftNode = node.childForFieldName('left');
      const rightNode = node.childForFieldName('right');
      
      if (leftNode && rightNode) {
        checkAssignment(leftNode, rightNode);
      }
    }

    // 3. Sinks (eval, db.query, etc.)
    if (node.type === 'call_expression') {
      const funcNode = node.childForFieldName('function');
      const argsNode = node.childForFieldName('arguments');

      if (funcNode && argsNode) {
        const funcName = funcNode.text;
        
        // Is this function a known sink?
        const matchedSink = sinks.find(s => {
          const sName = s.pattern.replace(/\$TAINTED|\(|\)/g, '').replace(/[^a-zA-Z0-9_.]/g, '');
          return funcName === sName || funcName.endsWith(`.${sName}`);
        });

        if (matchedSink) {
          // Check if any argument is tainted
          for (let i = 0; i < argsNode.childCount; i++) {
            const arg = argsNode.child(i);
            if (!arg || arg.type === '(' || arg.type === ')' || arg.type === ',') continue;

            const taintedArg = findTaintedVarInExpression(arg, taintedVars);
            if (taintedArg) {
              // Found a vulnerable flow!
              results.push({
                hasTaintedSink: true,
                sourceType: taintedArg.sourceType,
                sinkType: matchedSink.type,
                flow: [
                  ...taintedArg.propagationPath,
                  {
                    location: getLocation(node),
                    label: `Sink: ${matchedSink.description} (${matchedSink.type})`,
                    kind: 'sink'
                  }
                ]
              });
            }
          }
        }
      }
    }

    for (let i = 0; i < node.childCount; i++) {
      traverse(node.child(i)!);
    }
  }

  function checkAssignment(leftNode: Node, rightNode: Node) {
    const varName = leftNode.text;
    const rightText = rightNode.text;

    // Is the right side directly a source? (e.g., req.query)
    const matchedSource = sources.find(s => {
      const sName = s.pattern.replace(/\$TAINTED|\(|\)/g, '').replace(/[^a-zA-Z0-9_.]/g, '');
      return rightText.includes(sName);
    });

    if (matchedSource) {
      taintedVars.set(varName, {
        id: `taint_${varName}`,
        sourceType: matchedSource.type,
        originLocation: getLocation(rightNode),
        currentVariable: varName,
        sanitized: new Set(),
        propagationPath: [{
          location: getLocation(rightNode),
          label: `Source: ${matchedSource.description}`,
          kind: 'source'
        }]
      });
      return;
    }

    // Is the right side a previously tainted variable? (Propagation)
    const taintedSource = findTaintedVarInExpression(rightNode, taintedVars);
    if (taintedSource) {
      // Check for sanitizers
      const isSanitized = sanitizers.some(s => {
        const sName = s.pattern.replace(/\$TAINTED|\(|\)/g, '').replace(/[^a-zA-Z0-9_.]/g, '');
        return rightText.includes(sName);
      });

      if (!isSanitized) {
        // Propagate
        taintedVars.set(varName, {
          ...taintedSource,
          currentVariable: varName,
          propagationPath: [
            ...taintedSource.propagationPath,
            {
              location: getLocation(leftNode),
              label: `Propagated to ${varName}`,
              kind: 'propagator'
            }
          ]
        });
      }
    }
  }

  function findTaintedVarInExpression(node: Node, map: Map<string, TaintedValue>): TaintedValue | null {
    if (node.type === 'identifier' && map.has(node.text)) {
      return map.get(node.text)!;
    }
    // Deep check for binary expressions (e.g., "SELECT * FROM users WHERE id = '" + req.query.id + "'")
    if (node.type === 'binary_expression' || node.type === 'template_string') {
      // Just check if any identifier in this subtree is tainted
      let found: TaintedValue | null = null;
      function walk(n: Node) {
        if (found) return;
        if (n.type === 'identifier' && map.has(n.text)) {
          found = map.get(n.text)!;
        }
        for (let i = 0; i < n.childCount; i++) walk(n.child(i)!);
      }
      walk(node);
      return found;
    }
    return null;
  }

  traverse(tree.rootNode);
  return results;
}

// ─── Regex-Based Tracker (Fallback) ──────────────────────────────────────────

function analyzeTaintFlowRegex(
  content: string,
  filePath: string,
  sources: TaintSource[],
  sinks: TaintSink[],
  sanitizers: Sanitizer[]
): TaintResult[] {
  const results: TaintResult[] = [];
  const lines = content.split('\n');
  const taintedVars = findTaintSourcesRegex(lines, sources, filePath);
  propagateTaintRegex(lines, taintedVars, filePath);
  
  for (const tainted of taintedVars) {
    const sinkHits = findTaintSinksRegex(lines, tainted, sinks, sanitizers, filePath);
    results.push(...sinkHits);
  }
  return results;
}

function findTaintSourcesRegex(lines: string[], sources: TaintSource[], filePath: string): TaintedValue[] {
  const tainted: TaintedValue[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith('//') || line.startsWith('#')) continue;
    
    for (const source of sources) {
      if (line.includes(source.pattern.replace('$TAINTED', '').replace('()', ''))) {
        const assignMatch = line.match(/(?:const|let|var|final|auto)?\s*(\w+)\s*=.*$/);
        const varName = assignMatch ? assignMatch[1] : `__tainted_${i}`;
        tainted.push({
          id: `taint_${i}_${varName}`,
          sourceType: source.type,
          originLocation: { file: filePath, startLine: i + 1, startColumn: 0, endLine: i + 1, endColumn: line.length, snippet: line },
          currentVariable: varName,
          propagationPath: [{ location: { file: filePath, startLine: i + 1, startColumn: 0, endLine: i + 1, endColumn: line.length, snippet: line }, label: `Source: ${source.description}`, kind: 'source' }],
          sanitized: new Set(),
        });
      }
    }
  }
  return tainted;
}

function propagateTaintRegex(lines: string[], taintedVars: TaintedValue[], filePath: string): void {
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    for (const tainted of taintedVars) {
      if (line.includes(tainted.currentVariable)) {
        const assignMatch = line.match(/(?:const|let|var|final|auto)?\s*(\w+)\s*=.*$/);
        if (assignMatch && assignMatch[1] !== tainted.currentVariable) {
          const newVar = assignMatch[1];
          tainted.propagationPath.push({ location: { file: filePath, startLine: i + 1, startColumn: 0, endLine: i + 1, endColumn: line.length, snippet: line }, label: `Propagated: ${tainted.currentVariable} → ${newVar}`, kind: 'propagator' });
          tainted.currentVariable = newVar;
        }
      }
    }
  }
}

function findTaintSinksRegex(lines: string[], tainted: TaintedValue, sinks: TaintSink[], sanitizers: Sanitizer[], filePath: string): TaintResult[] {
  const results: TaintResult[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith('//') || line.startsWith('#')) continue;
    
    // Check sanitizers
    for (const sanitizer of sanitizers) {
      if (line.includes(sanitizer.pattern.replace('$TAINTED', tainted.currentVariable))) {
        for (const c of sanitizer.cleanses) {
          tainted.sanitized.add(c);
        }
      }
    }
    
    // Check sinks
    if (line.includes(tainted.currentVariable)) {
      for (const sink of sinks) {
        if (tainted.sanitized.has(sink.type)) continue;
        const sinkPattern = sink.pattern.replace('$TAINTED', '');
        if (line.includes(sinkPattern)) {
          results.push({
            hasTaintedSink: true,
            sourceType: tainted.sourceType,
            sinkType: sink.type,
            flow: [...tainted.propagationPath, { location: { file: filePath, startLine: i + 1, startColumn: 0, endLine: i + 1, endColumn: line.length, snippet: line }, label: `Sink: ${sink.description}`, kind: 'sink' }],
          });
        }
      }
    }
  }
  return results;
}
