// ─── Injection Analyzer ────────────────────────────────────────────────────
// Detects injection vulnerabilities (SQL, Command, LDAP, SSTI) using regex patterns

import type { Finding } from '../../../types/finding.js';
import type { ScanFileContext } from '../../../types/scanner.js';
import { createFinding, extractSnippet, matchPattern } from '../../base-scanner.js';

// ─── SQL Injection Detection ───────────────────────────────────────────────

/** Patterns that indicate SQL injection via string concatenation */
const SQL_CONCAT_PATTERNS: Array<{ regex: RegExp; message: string }> = [
  {
    // query("SELECT * FROM users WHERE id = " + userId)
    regex: /(?:query|execute|exec|raw|prepare)\s*\(\s*["'`](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION|EXEC)\b[^"'`]*["'`]\s*\+/i,
    message: 'SQL query built with string concatenation – vulnerable to SQL injection',
  },
  {
    // "SELECT * FROM " + table + " WHERE id = " + id
    regex: /["'`](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s+[\w\s*,]+(?:FROM|INTO|SET|TABLE)\s+["'`]\s*\+\s*\w+/i,
    message: 'SQL query built with string concatenation – use parameterized queries',
  },
  {
    // `SELECT * FROM users WHERE id = ${userId}`  (template literal)
    regex: /(?:query|execute|exec|raw)\s*\(\s*`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^`]*\$\{[^}]+\}[^`]*`/i,
    message: 'SQL query with template literal interpolation – vulnerable to SQL injection',
  },
  {
    // query(`...${req.body.id}...`)
    regex: /(?:query|execute|exec|raw)\s*\(\s*`[^`]*\$\{\s*(?:req|request|params|query|body|args|input|user)\b[^}]*\}[^`]*`/i,
    message: 'SQL query interpolates user-controlled input directly',
  },
  {
    // f"SELECT * FROM users WHERE name = '{name}'"  (Python f-string)
    regex: /f["'](?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+[^"']*\{[^}]+\}[^"']*["']/i,
    message: 'Python f-string used in SQL query – vulnerable to SQL injection',
  },
  {
    // "SELECT ... WHERE id = %s" % user_id  (Python % formatting)
    regex: /["'](?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^"']*%s[^"']*["']\s*%/i,
    message: 'Python %-format used in SQL query – use parameterized queries instead',
  },
  {
    // "SELECT ... WHERE id = #{id}"  (Ruby interpolation)
    regex: /["'](?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^"']*#\{[^}]+\}[^"']*["']/i,
    message: 'String interpolation in SQL query – vulnerable to SQL injection',
  },
  {
    // .where("name = '" + params[:name] + "'")
    regex: /\.where\s*\(\s*["'][^"']*["']\s*\+/i,
    message: 'ORM .where() with string concatenation – use parameterized form',
  },
];

/** Patterns for SQL injection in various ORMs/frameworks */
const SQL_ORM_PATTERNS: Array<{ regex: RegExp; message: string }> = [
  {
    // sequelize.query("SELECT ..." + input)
    regex: /sequelize\.query\s*\(\s*["'`][^"'`]*["'`]\s*\+/i,
    message: 'Sequelize raw query with string concatenation',
  },
  {
    // knex.raw("SELECT ..." + input)
    regex: /knex\.raw\s*\(\s*["'`][^"'`]*["'`]\s*\+/i,
    message: 'Knex raw query with string concatenation',
  },
  {
    // connection.query("..." + userInput)
    regex: /(?:connection|conn|db|client|pool)\.query\s*\(\s*["'`][^"'`]*["'`]\s*\+/i,
    message: 'Database query with string concatenation',
  },
  {
    // cursor.execute("..." + var)  (Python)
    regex: /cursor\.execute\s*\(\s*["'][^"']*["']\s*(?:\+|%)/i,
    message: 'Cursor execute with string concatenation or format – use parameterized queries',
  },
  {
    // PHP/Laravel DB raw queries with string concatenation using dot (.)
    regex: /(?:DB\s*::\s*(?:select|statement|insert|update|delete|raw)|whereRaw|havingRaw|orderByRaw)\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|UNION)\b[^"']*["']\s*\.\s*\$\w+/i,
    message: 'Laravel raw SQL query built with string concatenation – vulnerable to SQL injection',
  },
];

// ─── Command Injection Detection ───────────────────────────────────────────

const COMMAND_INJECTION_PATTERNS: Array<{ regex: RegExp; message: string }> = [
  {
    // exec("rm -rf " + userInput)
    regex: /(?:child_process\s*\.\s*)?exec\s*\(\s*(?:["'`][^"'`]*["'`]\s*\+\s*\w+|\w+\s*\+\s*["'`])/i,
    message: 'Command execution with string concatenation – vulnerable to command injection',
  },
  {
    // exec(`command ${userInput}`)
    regex: /(?:child_process\s*\.\s*)?exec\s*\(\s*`[^`]*\$\{[^}]+\}[^`]*`/i,
    message: 'Command execution with template literal interpolation',
  },
  {
    // execSync(userInput)
    regex: /execSync\s*\(\s*(?:req|request|params|query|body|args|input|user)\b/i,
    message: 'execSync called with user-controlled input',
  },
  {
    // os.system(user_input) or os.popen(...)
    regex: /os\.(?:system|popen)\s*\(\s*(?:["'][^"']*["']\s*(?:\+|%|\.\s*format)|f["'])/i,
    message: 'os.system/popen with dynamic input – vulnerable to command injection',
  },
  {
    // subprocess.call(cmd, shell=True)
    regex: /subprocess\.(?:call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True/i,
    message: 'subprocess with shell=True – vulnerable to command injection',
  },
  {
    // spawn with user input in arguments  
    regex: /spawn\s*\(\s*(?:req|request|params|query|body|args|input|user)\b/i,
    message: 'spawn called with user-controlled input',
  },
  {
    // eval(userInput)
    regex: /\beval\s*\(\s*(?:req|request|params|query|body|args|input|user)\b/i,
    message: 'eval() called with user-controlled input – code injection risk',
  },
  {
    // new Function(userInput)
    regex: /new\s+Function\s*\(\s*(?:req|request|params|query|body|args|input|user)\b/i,
    message: 'new Function() with user input – code injection risk',
  },
  {
    // Runtime.getRuntime().exec(input)  (Java)
    regex: /Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(\s*\w+/i,
    message: 'Runtime.exec with potentially user-controlled argument',
  },
];

// ─── LDAP Injection Detection ──────────────────────────────────────────────

const LDAP_INJECTION_PATTERNS: Array<{ regex: RegExp; message: string }> = [
  {
    // "(uid=" + username + ")"
    regex: /["']\s*\(\s*(?:uid|cn|sn|mail|memberOf|objectClass)\s*=\s*["']\s*\+\s*\w+/i,
    message: 'LDAP filter built with string concatenation – vulnerable to LDAP injection',
  },
  {
    // `(uid=${req.body.username})`
    regex: /`\s*\([^`]*(?:uid|cn|sn|mail|memberOf)=[^`]*\$\{[^}]+\}[^`]*\)`/i,
    message: 'LDAP filter with template literal interpolation',
  },
  {
    // ldap.search("..." + input)
    regex: /ldap\w*\.(?:search|bind|modify)\s*\(\s*["'`][^"'`]*["'`]\s*\+/i,
    message: 'LDAP operation with string concatenation',
  },
];

// ─── Template Injection (SSTI) Detection ───────────────────────────────────

const TEMPLATE_INJECTION_PATTERNS: Array<{ regex: RegExp; message: string }> = [
  {
    // render_template_string(user_input)
    regex: /render_template_string\s*\(\s*(?:req|request|params|query|body|args|input|user)\b/i,
    message: 'render_template_string with user input – SSTI vulnerability',
  },
  {
    // Template(user_input).render()
    regex: /(?:Template|Jinja2?|Environment)\s*\(\s*(?:req|request|params|query|body|args|input|user)\b/i,
    message: 'Template engine initialized with user-controlled input',
  },
  {
    // nunjucks.renderString(userInput)
    regex: /(?:nunjucks|swig|pug|ejs|handlebars|mustache)\s*\.(?:render|renderString|compile)\s*\(\s*(?:req|request|params|query|body|args|input|user)\b/i,
    message: 'Template engine renders user-controlled input – SSTI risk',
  },
  {
    // res.render with user-controlled template name
    regex: /res\.render\s*\(\s*(?:req|request|params|query|body|args|input|user)\b/i,
    message: 'res.render with user-controlled template name',
  },
  {
    // Jinja2 Environment with user input
    regex: /Environment\s*\([^)]*\)\s*\.from_string\s*\(\s*(?:req|request|params|query|body|args|input|user)\b/i,
    message: 'Jinja2 Environment.from_string with user input – SSTI',
  },
];

// ─── Main Analyzer Function ────────────────────────────────────────────────

/**
 * Analyze source code for injection vulnerabilities.
 */
export function analyzeInjection(context: ScanFileContext): Finding[] {
  const findings: Finding[] = [];
  const { content, filePath } = context;

  // Skip empty files or very small files
  if (content.length < 10) return findings;

  // Run SQL injection detection
  findings.push(...detectPatterns(content, filePath, SQL_CONCAT_PATTERNS, {
    ruleId: 'SEC-INJ-001',
    category: 'injection',
    subcategory: 'sql-injection',
    title: 'SQL Injection',
    severity: 'critical',
    confidence: 'high',
    cwe: ['CWE-89'],
    owasp: ['A03:2021'],
    tags: ['sql', 'injection', 'owasp-top10'],
    fix: {
      description: 'Use parameterized queries or prepared statements instead of string concatenation.',
      references: ['https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'],
    },
  }));

  findings.push(...detectPatterns(content, filePath, SQL_ORM_PATTERNS, {
    ruleId: 'SEC-INJ-002',
    category: 'injection',
    subcategory: 'sql-injection',
    title: 'SQL Injection via ORM',
    severity: 'critical',
    confidence: 'medium',
    cwe: ['CWE-89'],
    owasp: ['A03:2021'],
    tags: ['sql', 'injection', 'orm'],
    fix: {
      description: 'Use the ORM\'s parameterized query methods instead of raw query with concatenation.',
      references: ['https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html'],
    },
  }));

  // Run command injection detection
  findings.push(...detectPatterns(content, filePath, COMMAND_INJECTION_PATTERNS, {
    ruleId: 'SEC-INJ-003',
    category: 'injection',
    subcategory: 'command-injection',
    title: 'Command Injection',
    severity: 'critical',
    confidence: 'high',
    cwe: ['CWE-78'],
    owasp: ['A03:2021'],
    tags: ['command', 'injection', 'rce'],
    fix: {
      description: 'Use parameterized command execution (e.g., execFile, spawn with array args) and validate/sanitize user input.',
      references: ['https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html'],
    },
  }));

  // Run LDAP injection detection
  findings.push(...detectPatterns(content, filePath, LDAP_INJECTION_PATTERNS, {
    ruleId: 'SEC-INJ-004',
    category: 'injection',
    subcategory: 'ldap-injection',
    title: 'LDAP Injection',
    severity: 'high',
    confidence: 'medium',
    cwe: ['CWE-90'],
    owasp: ['A03:2021'],
    tags: ['ldap', 'injection'],
    fix: {
      description: 'Escape special LDAP characters in user input or use parameterized LDAP filters.',
      references: ['https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html'],
    },
  }));

  // Run template injection detection
  findings.push(...detectPatterns(content, filePath, TEMPLATE_INJECTION_PATTERNS, {
    ruleId: 'SEC-INJ-005',
    category: 'injection',
    subcategory: 'template-injection',
    title: 'Server-Side Template Injection (SSTI)',
    severity: 'critical',
    confidence: 'high',
    cwe: ['CWE-1336'],
    owasp: ['A03:2021'],
    tags: ['ssti', 'template', 'injection', 'rce'],
    fix: {
      description: 'Never render user-controlled strings as templates. Use static templates with data binding.',
      references: ['https://portswigger.net/web-security/server-side-template-injection'],
    },
  }));

  return findings;
}

// ─── Internal Helper ───────────────────────────────────────────────────────

interface PatternMeta {
  ruleId: string;
  category: string;
  subcategory: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  confidence: 'high' | 'medium' | 'low';
  cwe: string[];
  owasp: string[];
  tags: string[];
  fix: { description: string; references: string[] };
}

function detectPatterns(
  source: string,
  filePath: string,
  patterns: Array<{ regex: RegExp; message: string }>,
  meta: PatternMeta,
): Finding[] {
  const findings: Finding[] = [];

  for (const { regex, message } of patterns) {
    const matches = matchPattern(source, regex);
    for (const match of matches) {
      const snippet = extractSnippet(source, match.line);
      findings.push(
        createFinding({
          ruleId: meta.ruleId,
          scanner: 'security',
          severity: meta.severity,
          confidence: meta.confidence,
          category: meta.category,
          subcategory: meta.subcategory,
          title: meta.title,
          message,
          filePath,
          lineNumber: match.line,
          column: match.column,
          snippet,
          cwe: meta.cwe,
          owasp: meta.owasp,
          fix: meta.fix,
          tags: meta.tags,
        }),
      );
    }
  }

  return findings;
}
