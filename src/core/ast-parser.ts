// ─── AST Parser ─────────────────────────────────────────────────────────────
// Tree-sitter based AST parsing for context-aware analysis.
// Uses web-tree-sitter (WASM) for cross-platform compatibility.

import { Parser, Language, Tree, Node } from 'web-tree-sitter';
import { resolve, join } from 'node:path';
import { existsSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { consola } from 'consola';

/** Supported language grammars and their npm package names */
const LANGUAGE_GRAMMAR_MAP: Record<string, string> = {
  javascript: 'tree-sitter-javascript',
  typescript: 'tree-sitter-typescript',
  typescriptreact: 'tree-sitter-typescript',
  python: 'tree-sitter-python',
  java: 'tree-sitter-java',
  go: 'tree-sitter-go',
  php: 'tree-sitter-php',
  ruby: 'tree-sitter-ruby',
  c: 'tree-sitter-c',
  cpp: 'tree-sitter-cpp',
  csharp: 'tree-sitter-c-sharp',
  rust: 'tree-sitter-rust',
};

/** Cache directory for downloaded grammars */
const GRAMMAR_CACHE_DIR = resolve('node_modules', '.cache', 'deepscan', 'grammars');

/**
 * AST Parser manager using web-tree-sitter.
 * Provides utilities to parse source code and query AST node context.
 */
export class ASTParser {
  private parser: Parser | null = null;
  private languages: Map<string, Language> = new Map();
  private initialized = false;

  /**
   * Initialize the tree-sitter WASM runtime.
   */
  async initialize(): Promise<void> {
    if (this.initialized) return;

    try {
      await Parser.init();
      this.parser = new Parser();
      this.initialized = true;
      consola.debug('AST Parser initialized (web-tree-sitter WASM)');
    } catch (error) {
      consola.debug('Failed to initialize tree-sitter:', error);
      this.parser = null;
    }
  }

  /**
   * Parse source code into an AST tree.
   * Returns null if the language grammar is not available.
   */
  async parse(content: string, language: string, filePath?: string): Promise<Tree | null> {
    if (!this.parser) return null;

    const isTsx = filePath?.endsWith('.tsx') ?? false;
    const langKey = isTsx ? 'typescriptreact' : language;
    const lang = await this.loadLanguage(langKey);
    if (!lang) return null;

    try {
      this.parser.setLanguage(lang);
      return this.parser.parse(content);
    } catch (error) {
      console.error(`Failed to parse ${language} code:`, error);
      return null;
    }
  }

  /**
   * Get the inner parser instance.
   */
  getParser(): Parser | null {
    return this.parser;
  }

  /**
   * Get the AST node at a specific (0-indexed) line and column position.
   */
  getNodeAt(tree: Tree, line: number, column: number): Node | null {
    try {
      return tree.rootNode.descendantForPosition({ row: line, column });
    } catch {
      return null;
    }
  }

  /**
   * Check if a (1-indexed) position falls inside a string literal AST node.
   */
  isInStringLiteral(tree: Tree, line: number, column: number): boolean {
    const node = this.getNodeAt(tree, line - 1, column - 1);
    return node ? this.isStringNode(node) : false;
  }

  /**
   * Check if a (1-indexed) position falls inside a comment AST node.
   */
  isInComment(tree: Tree, line: number, column: number): boolean {
    const node = this.getNodeAt(tree, line - 1, column - 1);
    return node ? this.isCommentNode(node) : false;
  }

  /**
   * Check if a (1-indexed) position falls inside an import/require statement.
   */
  isInImport(tree: Tree, line: number, column: number): boolean {
    const node = this.getNodeAt(tree, line - 1, column - 1);
    if (!node) return false;

    let current: Node | null = node;
    while (current) {
      const type = current.type;
      if (
        type === 'import_statement' ||
        type === 'import_declaration' ||
        type === 'import_from_statement' ||
        type === 'import' ||
        type === 'require' ||
        type === 'call_expression' && current.firstChild?.text === 'require'
      ) {
        return true;
      }
      current = current.parent;
    }
    return false;
  }

  /**
   * Check if a (1-indexed) position falls inside a type annotation.
   */
  isInTypeAnnotation(tree: Tree, line: number, column: number): boolean {
    const node = this.getNodeAt(tree, line - 1, column - 1);
    if (!node) return false;

    let current: Node | null = node;
    while (current) {
      const type = current.type;
      if (
        type === 'type_annotation' ||
        type === 'type_alias_declaration' ||
        type === 'interface_declaration' ||
        type === 'type_parameter' ||
        type === 'type_parameters'
      ) {
        return true;
      }
      current = current.parent;
    }
    return false;
  }

  /**
   * Check if a position is in a "safe" AST context (string, comment, import, type).
   * Returns false if no tree is available (falls back to regex heuristics).
   */
  isInSafeContext(tree: Tree | null, line: number, column: number): boolean {
    if (!tree) return false;

    const node = this.getNodeAt(tree, line - 1, column - 1);
    if (!node) return false;

    // Walk up ancestors to check context
    let current: Node | null = node;
    while (current) {
      const type = current.type;

      // Comments
      if (type === 'comment' || type === 'line_comment' || type === 'block_comment') return true;

      // Bare string statements (docstrings and directives)
      if (
        this.isStringNode(current) &&
        (current.parent?.type === 'expression_statement' || current.parent?.parent?.type === 'expression_statement')
      ) return true;

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
    return false;
  }

  /**
   * Clean up resources.
   */
  async destroy(): Promise<void> {
    if (this.parser) {
      this.parser.delete();
      this.parser = null;
    }
    this.languages.clear();
    this.initialized = false;
  }

  // ─── Private Helpers ──────────────────────────────────────────────────────

  /**
   * Load a language grammar WASM. Try local node_modules first, then cache.
   */
  private async loadLanguage(language: string): Promise<Language | null> {
    // Check cache
    if (this.languages.has(language)) {
      return this.languages.get(language)!;
    }

    const grammarName = LANGUAGE_GRAMMAR_MAP[language];
    if (!grammarName) {
      consola.debug(`No tree-sitter grammar available for: ${language}`);
      return null;
    }

    try {
      // Try loading from node_modules (if installed as a dependency)
      let wasmPath: string | null = null;
      let wasmFileName = `${grammarName}.wasm`;
      if (language === 'typescriptreact') {
        wasmFileName = 'tree-sitter-tsx.wasm';
      }

      // For TypeScript, the WASM is usually at tree-sitter-typescript/tree-sitter-typescript.wasm
      const possiblePaths = [
        resolve('node_modules', grammarName, wasmFileName),
        resolve('node_modules', grammarName, `${language}.wasm`),
        resolve('node_modules', grammarName, 'wasm', wasmFileName),
        join(GRAMMAR_CACHE_DIR, wasmFileName),
      ];

      for (const p of possiblePaths) {
        if (existsSync(p)) {
          wasmPath = p;
          break;
        }
      }

      if (!wasmPath) {
        consola.debug(`Grammar WASM not found for ${language}. Checked: ${possiblePaths.join(', ')}`);
        return null;
      }

      const lang = await Language.load(wasmPath);
      this.languages.set(language, lang);
      consola.debug(`Loaded tree-sitter grammar: ${language}`);
      return lang;
    } catch (error) {
      console.error(`Failed to load grammar for ${language} at ${grammarName}:`, error);
      return null;
    }
  }

  /** Check if a node is a string literal */
  private isStringNode(node: Node): boolean {
    const type = node.type;
    return (
      type === 'string' ||
      type === 'string_literal' ||
      type === 'template_string' ||
      type === 'string_content' ||
      type === 'concatenated_string' ||
      type === 'interpreted_string_literal'
    );
  }

  /** Check if a node is a comment */
  private isCommentNode(node: Node): boolean {
    const type = node.type;
    return type === 'comment' || type === 'line_comment' || type === 'block_comment';
  }

  /** Check if a template string has interpolation (${...}) */
  private isTemplateWithInterpolation(node: Node): boolean {
    if (node.type !== 'template_string') return false;
    // If it has template_substitution children, it has interpolation
    for (let i = 0; i < node.childCount; i++) {
      if (node.child(i)?.type === 'template_substitution') return true;
    }
    return false;
  }
}

/** Singleton instance */
let astParserInstance: ASTParser | null = null;

/**
 * Get the singleton AST parser instance.
 */
export function getASTParser(): ASTParser {
  if (!astParserInstance) {
    astParserInstance = new ASTParser();
  }
  return astParserInstance;
}
