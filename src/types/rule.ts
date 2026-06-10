import type { Severity, Confidence } from './finding.js';

// ─── Rule Types ────────────────────────────────────────────────────────────

/** Pattern definition within a rule */
export interface RulePattern {
  /** Tree-sitter query or code pattern */
  pattern?: string;
  /** Message to display when this pattern matches */
  message?: string;
  /** Regex pattern (for non-AST matching) */
  regex?: string;
  /** Flags for regex */
  regexFlags?: string;
}

/** Condition for advanced rule logic */
export interface RuleCondition {
  type: 'taint-check' | 'context-check' | 'scope-check' | 'ast-check';
  /** For taint-check: source type */
  source?: string;
  /** For taint-check: sink variable */
  sink?: string;
  /** For context-check: contexts to include/exclude */
  in?: string[];
  notIn?: string[];
  /** For scope-check */
  scope?: string;
}

/** Fix suggestion within a rule */
export interface RuleFix {
  description: string;
  replacement?: string;
}

/** A single rule definition */
export interface Rule {
  id: string;
  name: string;
  description: string;
  category: string;
  subcategory?: string;
  severity: Severity;
  confidence: Confidence;
  cwe?: string[];
  owasp?: string[];
  languages: string[];
  patterns: RulePattern[];
  conditions?: RuleCondition[];
  fix?: RuleFix;
  tags?: string[];
  references?: string[];
  enabled?: boolean;
}

/** Collection of rules in a YAML file */
export interface RuleFile {
  rules: Rule[];
}

/** Rule category for organization */
export interface RuleCategory {
  id: string;
  name: string;
  description: string;
  scanner: 'security' | 'quality';
}

/** Default rule categories */
export const RULE_CATEGORIES: RuleCategory[] = [
  // Security categories
  { id: 'injection', name: 'Injection', description: 'SQL, Command, LDAP, XPath injection vulnerabilities', scanner: 'security' },
  { id: 'xss', name: 'Cross-Site Scripting', description: 'XSS vulnerabilities including DOM-based and reflected', scanner: 'security' },
  { id: 'secrets', name: 'Secrets & Credentials', description: 'Hardcoded passwords, API keys, tokens', scanner: 'security' },
  { id: 'auth', name: 'Authentication & Authorization', description: 'Weak auth patterns, missing authorization', scanner: 'security' },
  { id: 'crypto', name: 'Cryptography', description: 'Weak algorithms, insecure random, hardcoded keys', scanner: 'security' },
  { id: 'file-ops', name: 'File Operations', description: 'Path traversal, unsafe uploads, directory listing', scanner: 'security' },
  // Quality categories
  { id: 'complexity', name: 'Complexity', description: 'Cyclomatic and cognitive complexity issues', scanner: 'quality' },
  { id: 'duplication', name: 'Code Duplication', description: 'Duplicated code blocks', scanner: 'quality' },
  { id: 'code-smells', name: 'Code Smells', description: 'Long methods, large files, dead code', scanner: 'quality' },
  { id: 'naming', name: 'Naming Conventions', description: 'Inconsistent or unclear naming', scanner: 'quality' },
  { id: 'metrics', name: 'Code Metrics', description: 'Lines of code, comment ratio, maintainability', scanner: 'quality' },
];
