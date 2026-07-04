// ─── File Operations Analyzer ──────────────────────────────────────────────
// Phát hiện lỗ hổng thao tác tệp: path traversal, quyền truy cập không an toàn
// Detects path traversal, unsafe permissions, temp file issues

import type { Finding, Severity, Confidence } from '../../../types/finding.js';
import type { ScanFileContext } from '../../../types/scanner.js';
import { createFinding, extractSnippet, matchPattern, isPatternDefinitionContext } from '../../base-scanner.js';

// ─── Pattern Definitions ───────────────────────────────────────────────────

interface FileOpsPattern {
  regex: RegExp;
  message: string;
  severity: Severity;
  confidence: Confidence;
  subcategory: string;
  ruleId: string;
  cwe: string[];
}

const FILE_OPS_PATTERNS: FileOpsPattern[] = [
  // ── Path Traversal ──
  {
    regex: /(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|appendFile|unlink|unlinkSync|stat|statSync|access|accessSync|open|openSync)\s*\(\s*(?:req|request|params|query|body|args|input|user)\b/i,
    message: 'File operation with user-controlled path – vulnerable to path traversal',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'path-traversal',
    ruleId: 'SEC-FILE-001',
    cwe: ['CWE-22'],
  },
  {
    regex: /(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync)\s*\(\s*(?:["'`][^"'`]*["'`]\s*\+\s*\w+|\w+\s*\+\s*["'`])/i,
    message: 'File path built with string concatenation – potential path traversal',
    severity: 'high',
    confidence: 'medium',
    subcategory: 'path-traversal',
    ruleId: 'SEC-FILE-001',
    cwe: ['CWE-22'],
  },
  {
    regex: /(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync)\s*\(\s*`[^`]*\$\{[^}]+\}[^`]*`/i,
    message: 'File path with template literal interpolation – potential path traversal',
    severity: 'high',
    confidence: 'medium',
    subcategory: 'path-traversal',
    ruleId: 'SEC-FILE-001',
    cwe: ['CWE-22'],
  },
  {
    regex: /path\.(?:join|resolve)\s*\(\s*[^,)]+,\s*(?:req|request|params|query|body|args|input|user)\b/i,
    message: 'path.join/resolve with user input – validate that the result stays within allowed directory',
    severity: 'medium',
    confidence: 'high',
    subcategory: 'path-traversal',
    ruleId: 'SEC-FILE-001',
    cwe: ['CWE-22'],
  },
  {
    regex: /\.\.(?:\/|\\)/,
    message: 'Relative path traversal pattern (../) detected – verify this is safe',
    severity: 'low',
    confidence: 'low',
    subcategory: 'path-traversal',
    ruleId: 'SEC-FILE-001',
    cwe: ['CWE-22'],
  },
  {
    // Python open() with user input
    regex: /open\s*\(\s*(?:request\.|req\.|params|user_input|filename)\b/i,
    message: 'Python open() with potentially user-controlled path – path traversal risk',
    severity: 'high',
    confidence: 'medium',
    subcategory: 'path-traversal',
    ruleId: 'SEC-FILE-001',
    cwe: ['CWE-22'],
  },
  {
    // Express static file serving with user input
    regex: /res\.sendFile\s*\(\s*(?:req|request)\b/i,
    message: 'res.sendFile with user-controlled path – path traversal risk',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'path-traversal',
    ruleId: 'SEC-FILE-001',
    cwe: ['CWE-22'],
  },
  {
    // PHP file inclusion
    regex: /(?:include|require|include_once|require_once)\s*\(\s*\$_(?:GET|POST|REQUEST)/i,
    message: 'PHP file inclusion with user input – Local/Remote File Inclusion vulnerability',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'path-traversal',
    ruleId: 'SEC-FILE-001',
    cwe: ['CWE-98'],
  },

  // ── Unsafe File Permissions ──
  {
    regex: /chmod\s*\(\s*[^,]+,\s*(?:0o?777|0o?766|0o?667|511|438)/i,
    message: 'File permissions set to world-writable (777/766) – restrict to minimum necessary',
    severity: 'high',
    confidence: 'high',
    subcategory: 'permissions',
    ruleId: 'SEC-FILE-002',
    cwe: ['CWE-732'],
  },
  {
    regex: /chmod\s*\(\s*[^,]+,\s*(?:0o?666|0o?664|0o?646)/i,
    message: 'File permissions set to world-readable/writable (666) – restrict permissions',
    severity: 'medium',
    confidence: 'high',
    subcategory: 'permissions',
    ruleId: 'SEC-FILE-002',
    cwe: ['CWE-732'],
  },
  {
    regex: /(?:writeFile|writeFileSync|appendFile)\s*\([^)]*mode\s*:\s*(?:0o?777|0o?766|0o?666)/i,
    message: 'File created with overly permissive mode',
    severity: 'high',
    confidence: 'high',
    subcategory: 'permissions',
    ruleId: 'SEC-FILE-002',
    cwe: ['CWE-732'],
  },
  {
    regex: /umask\s*\(\s*0+\s*\)/i,
    message: 'umask set to 0 – all new files will have maximum permissions',
    severity: 'high',
    confidence: 'high',
    subcategory: 'permissions',
    ruleId: 'SEC-FILE-002',
    cwe: ['CWE-732'],
  },

  // ── Temporary File Issues ──
  {
    regex: /(?:\/tmp\/|\\temp\\|tempnam|tmpnam|mktemp(?!dir))\b/i,
    message: 'Use of predictable temporary file path – use mkdtemp/mkstemp for secure temp files',
    severity: 'medium',
    confidence: 'medium',
    subcategory: 'temp-files',
    ruleId: 'SEC-FILE-003',
    cwe: ['CWE-377'],
  },
  {
    regex: /(?:tmpfile|tempfile\.NamedTemporaryFile)\s*\([^)]*delete\s*=\s*False/i,
    message: 'Temporary file not auto-deleted – may leave sensitive data on disk',
    severity: 'medium',
    confidence: 'medium',
    subcategory: 'temp-files',
    ruleId: 'SEC-FILE-003',
    cwe: ['CWE-459'],
  },
  {
    regex: /(?:writeFile|writeFileSync)\s*\(\s*["']\/tmp\//i,
    message: 'Writing to predictable /tmp path – may be vulnerable to symlink attacks',
    severity: 'medium',
    confidence: 'medium',
    subcategory: 'temp-files',
    ruleId: 'SEC-FILE-003',
    cwe: ['CWE-377'],
  },

  // ── Unsafe file upload ──
  {
    regex: /multer\s*\(\s*\{[^}]*(?:dest|storage)[^}]*\}/i,
    message: 'File upload detected – ensure proper validation of file type, size, and content',
    severity: 'low',
    confidence: 'low',
    subcategory: 'file-upload',
    ruleId: 'SEC-FILE-004',
    cwe: ['CWE-434'],
  },
  {
    regex: /\.(?:originalname|filename)\s*(?:;|\))/i,
    message: 'Original filename used directly – sanitize filenames to prevent directory traversal in uploads',
    severity: 'medium',
    confidence: 'medium',
    subcategory: 'file-upload',
    ruleId: 'SEC-FILE-004',
    cwe: ['CWE-434'],
  },
  {
    // Go/Generic path traversal with variables in ReadFile/Open/etc.
    regex: /(?:ioutil\.|os\.)(?:ReadFile|Open|OpenFile|Create|Remove)\s*\(\s*[^'"`)]*\b(?:req|request|params|query|body|args|input|user|filename|file|path|uri|url)\b/i,
    message: 'File read/open using dynamic path – potential path traversal risk',
    severity: 'high',
    confidence: 'medium',
    subcategory: 'path-traversal',
    ruleId: 'SEC-FILE-001',
    cwe: ['CWE-22'],
  },
  {
    // Python/Go/Generic path construction with potentially user-controlled variables
    regex: /(?:filepath\.|path\.|os\.path\.)Join\s*\(\s*[^,]+,\s*\b(?:req|request|params|query|body|args|input|user|filename|file|path|uri|url)\b/i,
    message: 'Path construction using variables – verify input is sanitized to prevent path traversal',
    severity: 'medium',
    confidence: 'medium',
    subcategory: 'path-traversal',
    ruleId: 'SEC-FILE-001',
    cwe: ['CWE-22'],
  }
];

// ─── Main Analyzer Function ────────────────────────────────────────────────

/**
 * Analyze source code for file operation vulnerabilities.
 */
export function analyzeFileOps(context: ScanFileContext): Finding[] {
  const findings: Finding[] = [];
  const { content, filePath } = context;

  if (content.length < 10) return findings;

  for (const pattern of FILE_OPS_PATTERNS) {
    const matches = matchPattern(content, pattern.regex);
    for (const match of matches) {
      // Skip comments and import/export statements
      const trimmed = match.lineContent.trimStart();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('#') || trimmed.startsWith('/*')) {
        continue;
      }

      // Skip matches inside pattern/rule definition contexts
      if (isPatternDefinitionContext(match.lineContent, match.column)) continue;
      const isConfigFile = 
        filePath.endsWith('.config.js') || 
        filePath.endsWith('.config.ts') || 
        filePath.includes('vite.config') || 
        filePath.includes('webpack.') || 
        filePath.includes('tailwind.');

      if (
        trimmed.startsWith('import ') ||
        trimmed.startsWith('export ') ||
        trimmed.startsWith('from ') ||
        trimmed.includes('require(') ||
        trimmed.includes('require ') ||
        trimmed.includes('require_once ') ||
        trimmed.includes('include ') ||
        trimmed.includes('include_once ') ||
        isConfigFile
      ) {
        continue;
      }

      // Skip static path constants starting points
      if (
        trimmed.includes('__DIR__') ||
        trimmed.includes('__dirname') ||
        trimmed.includes('__filename') ||
        trimmed.includes('__FILE__') ||
        trimmed.includes('import.meta.url')
      ) {
        if (!/(?:req|request|params|query|body|args|input|user|GET|POST|REQUEST)\b/i.test(trimmed)) {
          continue;
        }
      }

      // For the generic ../ pattern, reduce noise – only flag if in a file ops context
      if (pattern.ruleId === 'SEC-FILE-001' && pattern.confidence === 'low') {
        if (!/(?:read|write|open|include|require|send|path|fs|file)\b/i.test(match.lineContent)) {
          continue;
        }
      }

      const snippet = extractSnippet(content, match.line);
      findings.push(
        createFinding({
          ruleId: pattern.ruleId,
          scanner: 'security',
          severity: pattern.severity,
          confidence: pattern.confidence,
          category: 'file-ops',
          subcategory: pattern.subcategory,
          title: 'File Operation Issue',
          message: pattern.message,
          filePath,
          lineNumber: match.line,
          column: match.column,
          snippet,
          cwe: pattern.cwe,
          owasp: ['A01:2021'],
          fix: {
            description: 'Validate and sanitize file paths. Use path.resolve() and verify the resolved path is within the allowed directory. Set restrictive file permissions.',
            references: [
              'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html',
              'https://owasp.org/www-community/attacks/Path_Traversal',
            ],
          },
          tags: ['file-ops'],
        }),
      );
    }
  }

  return findings;
}
