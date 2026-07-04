// ─── Auth Analyzer ─────────────────────────────────────────────────────────
// Phát hiện lỗ hổng xác thực và phân quyền
// Detects weak authentication, missing CSRF, insecure sessions, hardcoded JWT secrets

import type { Finding, Severity, Confidence } from '../../../types/finding.js';
import type { ScanFileContext } from '../../../types/scanner.js';
import { createFinding, extractSnippet, matchPattern, isPatternDefinitionContext } from '../../base-scanner.js';

// ─── Pattern Definitions ───────────────────────────────────────────────────

interface AuthPattern {
  regex: RegExp;
  message: string;
  severity: Severity;
  confidence: Confidence;
  subcategory: string;
  ruleId: string;
  cwe: string[];
}

const AUTH_PATTERNS: AuthPattern[] = [
  // ── Weak password comparison ──
  {
    regex: /(?:password|passwd|pwd)\s*===?\s*["'][^"']+["']/i,
    message: 'Password compared against hardcoded string – use proper hashing (bcrypt, argon2)',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'weak-password',
    ruleId: 'SEC-AUTH-001',
    cwe: ['CWE-798', 'CWE-259'],
  },
  {
    regex: /if\s*\(\s*(?:password|passwd|pwd|pass)\s*===?\s*(?:req|request|params|body)\b[^)]*\)/i,
    message: 'Direct password comparison without hashing – timing attack and plaintext storage risk',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'weak-password',
    ruleId: 'SEC-AUTH-001',
    cwe: ['CWE-916'],
  },
  {
    regex: /(?:password|passwd|pwd)\s*==\s*(?!null|undefined|"")\w+/i,
    message: 'Loose equality (==) used for password comparison – use constant-time comparison',
    severity: 'high',
    confidence: 'medium',
    subcategory: 'weak-password',
    ruleId: 'SEC-AUTH-001',
    cwe: ['CWE-208'],
  },
  {
    regex: /\.(?:compare|equals)\s*\(\s*(?:password|passwd|pwd)\s*,\s*(?:password|passwd|pwd)\s*\)/i,
    message: 'Verify that password comparison uses a constant-time function (e.g., bcrypt.compare)',
    severity: 'low',
    confidence: 'low',
    subcategory: 'weak-password',
    ruleId: 'SEC-AUTH-001',
    cwe: ['CWE-208'],
  },

  // ── Missing CSRF protection ──
  {
    regex: /(?:csrf|xsrf)\s*[:=]\s*(?:false|disabled|off)/i,
    message: 'CSRF protection explicitly disabled',
    severity: 'high',
    confidence: 'high',
    subcategory: 'csrf',
    ruleId: 'SEC-AUTH-002',
    cwe: ['CWE-352'],
  },
  {
    regex: /app\.(?:disable|set)\s*\(\s*["']csrf["']\s*(?:,\s*false)?\s*\)/i,
    message: 'CSRF protection disabled in application configuration',
    severity: 'high',
    confidence: 'high',
    subcategory: 'csrf',
    ruleId: 'SEC-AUTH-002',
    cwe: ['CWE-352'],
  },
  {
    regex: /@csrf_exempt/i,
    message: 'Django @csrf_exempt decorator – endpoint lacks CSRF protection',
    severity: 'medium',
    confidence: 'high',
    subcategory: 'csrf',
    ruleId: 'SEC-AUTH-002',
    cwe: ['CWE-352'],
  },
  {
    regex: /verify_authenticity_token\s*.*skip/i,
    message: 'Rails authenticity token verification skipped',
    severity: 'high',
    confidence: 'high',
    subcategory: 'csrf',
    ruleId: 'SEC-AUTH-002',
    cwe: ['CWE-352'],
  },

  // ── Insecure session configuration ──
  {
    regex: /(?:session|cookie)\s*(?::\s*\{[^}]*|\.)\s*(?:secure\s*[:=]\s*false)/i,
    message: 'Session cookie Secure flag set to false – cookie sent over HTTP',
    severity: 'high',
    confidence: 'high',
    subcategory: 'session',
    ruleId: 'SEC-AUTH-003',
    cwe: ['CWE-614'],
  },
  {
    regex: /(?:session|cookie)\s*(?::\s*\{[^}]*|\.)\s*(?:httpOnly\s*[:=]\s*false)/i,
    message: 'Session cookie HttpOnly flag set to false – cookie accessible via JavaScript',
    severity: 'high',
    confidence: 'high',
    subcategory: 'session',
    ruleId: 'SEC-AUTH-003',
    cwe: ['CWE-1004'],
  },
  {
    regex: /sameSite\s*[:=]\s*["'](?:none|None)["']/i,
    message: 'SameSite cookie attribute set to None – may enable CSRF',
    severity: 'medium',
    confidence: 'medium',
    subcategory: 'session',
    ruleId: 'SEC-AUTH-003',
    cwe: ['CWE-1275'],
  },
  {
    regex: /(?:express-session|session)\s*\(\s*\{[^}]*secret\s*:\s*["'][^"']{1,10}["']/i,
    message: 'Session secret is too short – use a strong, random secret',
    severity: 'high',
    confidence: 'medium',
    subcategory: 'session',
    ruleId: 'SEC-AUTH-003',
    cwe: ['CWE-331'],
  },
  {
    regex: /SESSION_COOKIE_SECURE\s*=\s*False/i,
    message: 'Django SESSION_COOKIE_SECURE set to False',
    severity: 'high',
    confidence: 'high',
    subcategory: 'session',
    ruleId: 'SEC-AUTH-003',
    cwe: ['CWE-614'],
  },

  // ── Hardcoded JWT secrets ──
  {
    regex: /jwt\.sign\s*\([^,]+,\s*["'][^"']{1,30}["']/i,
    message: 'JWT signed with hardcoded secret – use environment variable',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'jwt',
    ruleId: 'SEC-AUTH-004',
    cwe: ['CWE-798'],
  },
  {
    regex: /jwt\.verify\s*\([^,]+,\s*["'][^"']+["']/i,
    message: 'JWT verified with hardcoded secret – use environment variable',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'jwt',
    ruleId: 'SEC-AUTH-004',
    cwe: ['CWE-798'],
  },
  {
    regex: /(?:jwt_secret|JWT_SECRET|jwtSecret)\s*[:=]\s*["'][^"']+["']/i,
    message: 'JWT secret hardcoded in source code',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'jwt',
    ruleId: 'SEC-AUTH-004',
    cwe: ['CWE-798'],
  },
  {
    regex: /algorithm\s*[:=]\s*["']none["']/i,
    message: 'JWT algorithm set to "none" – tokens are unsigned and easily forged',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'jwt',
    ruleId: 'SEC-AUTH-004',
    cwe: ['CWE-327'],
  },

  // ── Disabled security middleware ──
  {
    regex: /(?:helmet|cors|csurf|rate.?limit)\s*\(\s*\{[^}]*disable[^}]*\}/i,
    message: 'Security middleware explicitly disabled or misconfigured',
    severity: 'medium',
    confidence: 'medium',
    subcategory: 'middleware',
    ruleId: 'SEC-AUTH-005',
    cwe: ['CWE-693'],
  },
  {
    regex: /cors\s*\(\s*\{[^}]*origin\s*:\s*(?:true|["']\*["'])/i,
    message: 'CORS configured with wildcard origin (*) or all origins – may allow unauthorized cross-origin requests',
    severity: 'medium',
    confidence: 'high',
    subcategory: 'middleware',
    ruleId: 'SEC-AUTH-005',
    cwe: ['CWE-942'],
  },
  {
    regex: /\.disable\s*\(\s*["'](?:x-powered-by|etag)["']\s*\)/i,
    message: 'Security header disabled – verify this is intentional',
    severity: 'low',
    confidence: 'low',
    subcategory: 'middleware',
    ruleId: 'SEC-AUTH-005',
    cwe: ['CWE-693'],
  },
  {
    regex: /ALLOWED_HOSTS\s*=\s*\[\s*["']\*["']\s*\]/i,
    message: 'Django ALLOWED_HOSTS set to wildcard – host header injection risk',
    severity: 'high',
    confidence: 'high',
    subcategory: 'middleware',
    ruleId: 'SEC-AUTH-005',
    cwe: ['CWE-20'],
  },
  {
    regex: /DEBUG\s*=\s*True/,
    message: 'Debug mode enabled in production configuration',
    severity: 'medium',
    confidence: 'medium',
    subcategory: 'middleware',
    ruleId: 'SEC-AUTH-005',
    cwe: ['CWE-489'],
  },
];

// ─── Main Analyzer Function ────────────────────────────────────────────────

/**
 * Analyze source code for authentication and authorization vulnerabilities.
 * Phân tích mã nguồn để phát hiện lỗ hổng xác thực và phân quyền
 */
export function analyzeAuth(context: ScanFileContext): Finding[] {
  const findings: Finding[] = [];
  const { content, filePath } = context;

  if (content.length < 10) return findings;

  for (const pattern of AUTH_PATTERNS) {
    const matches = matchPattern(content, pattern.regex);
    for (const match of matches) {
      // Skip comments
      const trimmed = match.lineContent.trimStart();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('#') || trimmed.startsWith('/*')) {
        continue;
      }

      // Skip matches inside pattern/rule definition contexts
      if (isPatternDefinitionContext(match.lineContent, match.column)) continue;

      const snippet = extractSnippet(content, match.line);
      findings.push(
        createFinding({
          ruleId: pattern.ruleId,
          scanner: 'security',
          severity: pattern.severity,
          confidence: pattern.confidence,
          category: 'auth',
          subcategory: pattern.subcategory,
          title: 'Authentication / Authorization Issue',
          message: pattern.message,
          filePath,
          lineNumber: match.line,
          column: match.column,
          snippet,
          cwe: pattern.cwe,
          owasp: ['A07:2021'],
          fix: {
            description: 'Follow secure authentication best practices: use bcrypt/argon2 for passwords, enable CSRF, set secure cookie flags, and use strong JWT secrets from environment variables.',
            references: [
              'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html',
              'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
            ],
          },
          tags: ['auth', 'owasp-top10'],
        }),
      );
    }
  }

  return findings;
}
