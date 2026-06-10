// ─── Secrets Analyzer ──────────────────────────────────────────────────────
// Detects hardcoded secrets: passwords, API keys, private keys, high-entropy strings

import type { Finding, Severity, Confidence } from '../../../types/finding.js';
import type { ScanFileContext } from '../../../types/scanner.js';
import { createFinding, extractSnippet, matchPattern } from '../../base-scanner.js';

// ─── Pattern Definitions ───────────────────────────────────────────────────

interface SecretPattern {
  id: string;
  regex: RegExp;
  message: string;
  severity: Severity;
  confidence: Confidence;
  subcategory: string;
  service?: string;
}

// ── Hardcoded password patterns ──
const PASSWORD_PATTERNS: SecretPattern[] = [
  {
    id: 'SEC-SEC-001',
    regex: /(?:password|passwd|pwd|pass|secret|credential)\s*[:=]\s*["'][^"']{4,}["']/i,
    message: 'Hardcoded password or secret detected in source code',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'hardcoded-password',
  },
  {
    id: 'SEC-SEC-001',
    regex: /(?:password|passwd|pwd|pass)\s*=\s*["'][^"']{4,}["']/i,
    message: 'Hardcoded password assignment detected',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'hardcoded-password',
  },
  {
    id: 'SEC-SEC-001',
    regex: /(?:db_password|database_password|DB_PASS|mysql_pwd|pg_password)\s*[:=]\s*["'][^"']{4,}["']/i,
    message: 'Hardcoded database password detected',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'hardcoded-password',
  },
  {
    id: 'SEC-SEC-002',
    regex: /(?:admin_password|root_password|master_password|default_password)\s*[:=]\s*["'][^"']+["']/i,
    message: 'Hardcoded admin/root password detected',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'hardcoded-password',
  },
];

// ── API key and token patterns for 20+ services ──
const API_KEY_PATTERNS: SecretPattern[] = [
  // AWS
  {
    id: 'SEC-SEC-010',
    regex: /(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/,
    message: 'AWS Access Key ID detected',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'api-key',
    service: 'AWS',
  },
  {
    id: 'SEC-SEC-010',
    regex: /(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*["'][A-Za-z0-9/+=]{40}["']/i,
    message: 'AWS Secret Access Key detected',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'api-key',
    service: 'AWS',
  },
  // GitHub
  {
    id: 'SEC-SEC-011',
    regex: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/,
    message: 'GitHub personal access token detected',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'api-key',
    service: 'GitHub',
  },
  {
    id: 'SEC-SEC-011',
    regex: /github_token\s*[:=]\s*["'][^"']{20,}["']/i,
    message: 'GitHub token detected in source code',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'api-key',
    service: 'GitHub',
  },
  // Slack
  {
    id: 'SEC-SEC-012',
    regex: /xox[bpors]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*/,
    message: 'Slack token detected',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'api-key',
    service: 'Slack',
  },
  {
    id: 'SEC-SEC-012',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{24}/,
    message: 'Slack webhook URL detected',
    severity: 'high',
    confidence: 'high',
    subcategory: 'api-key',
    service: 'Slack',
  },
  // Stripe
  {
    id: 'SEC-SEC-013',
    regex: /sk_live_[0-9a-zA-Z]{24,}/,
    message: 'Stripe live secret key detected',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'api-key',
    service: 'Stripe',
  },
  {
    id: 'SEC-SEC-013',
    regex: /rk_live_[0-9a-zA-Z]{24,}/,
    message: 'Stripe live restricted key detected',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'api-key',
    service: 'Stripe',
  },
  // Google
  {
    id: 'SEC-SEC-014',
    regex: /AIza[0-9A-Za-z\-_]{35}/,
    message: 'Google API key detected',
    severity: 'high',
    confidence: 'high',
    subcategory: 'api-key',
    service: 'Google',
  },
  {
    id: 'SEC-SEC-014',
    regex: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/,
    message: 'Google OAuth client ID detected',
    severity: 'medium',
    confidence: 'medium',
    subcategory: 'api-key',
    service: 'Google',
  },
  // Heroku
  {
    id: 'SEC-SEC-015',
    regex: /(?:heroku_api_key|HEROKU_API_KEY)\s*[:=]\s*["'][0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}["']/i,
    message: 'Heroku API key detected',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'api-key',
    service: 'Heroku',
  },
  // Twilio
  {
    id: 'SEC-SEC-016',
    regex: /SK[0-9a-fA-F]{32}/,
    message: 'Twilio API key detected',
    severity: 'high',
    confidence: 'medium',
    subcategory: 'api-key',
    service: 'Twilio',
  },
  // Mailgun
  {
    id: 'SEC-SEC-017',
    regex: /key-[0-9a-zA-Z]{32}/,
    message: 'Mailgun API key detected',
    severity: 'high',
    confidence: 'medium',
    subcategory: 'api-key',
    service: 'Mailgun',
  },
  // SendGrid
  {
    id: 'SEC-SEC-018',
    regex: /SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}/,
    message: 'SendGrid API key detected',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'api-key',
    service: 'SendGrid',
  },
  // Square
  {
    id: 'SEC-SEC-019',
    regex: /sq0atp-[0-9A-Za-z\-_]{22}/,
    message: 'Square access token detected',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'api-key',
    service: 'Square',
  },
  // PayPal
  {
    id: 'SEC-SEC-020',
    regex: /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/,
    message: 'PayPal/Braintree production access token detected',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'api-key',
    service: 'PayPal',
  },
  // Discord
  {
    id: 'SEC-SEC-021',
    regex: /(?:discord_token|DISCORD_TOKEN|discord_bot_token)\s*[:=]\s*["'][A-Za-z0-9._-]{50,}["']/i,
    message: 'Discord bot token detected',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'api-key',
    service: 'Discord',
  },
  // NPM
  {
    id: 'SEC-SEC-022',
    regex: /npm_[A-Za-z0-9]{36}/,
    message: 'NPM access token detected',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'api-key',
    service: 'NPM',
  },
  // Databricks
  {
    id: 'SEC-SEC-023',
    regex: /dapi[0-9a-f]{32}/,
    message: 'Databricks API token detected',
    severity: 'high',
    confidence: 'high',
    subcategory: 'api-key',
    service: 'Databricks',
  },
  // Firebase
  {
    id: 'SEC-SEC-024',
    regex: /(?:firebase_api_key|FIREBASE_KEY)\s*[:=]\s*["'][A-Za-z0-9_-]{20,}["']/i,
    message: 'Firebase API key detected',
    severity: 'high',
    confidence: 'medium',
    subcategory: 'api-key',
    service: 'Firebase',
  },
  // Azure
  {
    id: 'SEC-SEC-025',
    regex: /(?:azure_storage_key|AZURE_STORAGE_KEY|azure_api_key)\s*[:=]\s*["'][A-Za-z0-9+/=]{40,}["']/i,
    message: 'Azure storage or API key detected',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'api-key',
    service: 'Azure',
  },
  // DigitalOcean
  {
    id: 'SEC-SEC-026',
    regex: /dop_v1_[0-9a-f]{64}/,
    message: 'DigitalOcean personal access token detected',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'api-key',
    service: 'DigitalOcean',
  },
  // Shopify
  {
    id: 'SEC-SEC-027',
    regex: /shpat_[0-9a-fA-F]{32}/,
    message: 'Shopify access token detected',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'api-key',
    service: 'Shopify',
  },
  // Generic API key / secret patterns
  {
    id: 'SEC-SEC-030',
    regex: /(?:api_key|apikey|api_secret|API_KEY|API_SECRET)\s*[:=]\s*["'][A-Za-z0-9_\-./+=]{16,}["']/i,
    message: 'Generic API key/secret detected in source code',
    severity: 'high',
    confidence: 'medium',
    subcategory: 'api-key',
  },
  {
    id: 'SEC-SEC-030',
    regex: /(?:access_token|auth_token|bearer_token|client_secret)\s*[:=]\s*["'][A-Za-z0-9_\-./+=]{16,}["']/i,
    message: 'Access/auth token or client secret detected',
    severity: 'high',
    confidence: 'medium',
    subcategory: 'api-key',
  },
];

// ── Private key patterns ──
const PRIVATE_KEY_PATTERNS: SecretPattern[] = [
  {
    id: 'SEC-SEC-040',
    regex: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/,
    message: 'RSA private key detected in source code',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'private-key',
  },
  {
    id: 'SEC-SEC-040',
    regex: /-----BEGIN\s+EC\s+PRIVATE\s+KEY-----/,
    message: 'EC private key detected in source code',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'private-key',
  },
  {
    id: 'SEC-SEC-040',
    regex: /-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----/,
    message: 'DSA private key detected in source code',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'private-key',
  },
  {
    id: 'SEC-SEC-040',
    regex: /-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----/,
    message: 'OpenSSH private key detected in source code',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'private-key',
  },
  {
    id: 'SEC-SEC-040',
    regex: /-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----/,
    message: 'PGP private key detected in source code',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'private-key',
  },
  {
    id: 'SEC-SEC-041',
    regex: /-----BEGIN\s+CERTIFICATE-----/,
    message: 'Certificate detected in source code – verify this is intentional',
    severity: 'medium',
    confidence: 'low',
    subcategory: 'private-key',
  },
];

// ─── Shannon Entropy Calculator ────────────────────────────────────────────

/**
 * Calculate Shannon entropy of a string.
 * High entropy indicates potentially random/secret data.
 */
function shannonEntropy(str: string): number {
  if (str.length === 0) return 0;

  const freq: Map<string, number> = new Map();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }

  let entropy = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }
  return entropy;
}

// ── Allowed file extensions for entropy scanning ──
const SKIP_ENTROPY_EXTENSIONS = new Set([
  '.min.js', '.min.css', '.map', '.lock', '.svg', '.png', '.jpg', '.gif',
  '.woff', '.woff2', '.ttf', '.eot', '.ico', '.pdf',
]);

// ── Common false positives for entropy detection ──
const ENTROPY_FALSE_POSITIVES = new Set([
  'undefined', 'null', 'true', 'false', 'localhost',
  'example.com', 'test', 'development', 'production', 'staging',
  'placeholder', 'changeme', 'your_key_here', 'TODO', 'FIXME',
  'xxxx', 'yyyy', 'zzzz', 'aaaa', 'bbbb',
  'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  '0123456789', '1234567890',
]);

// ─── Main Analyzer Function ────────────────────────────────────────────────

/**
 * Analyze source code for hardcoded secrets and credentials.
 */
export function analyzeSecrets(context: ScanFileContext): Finding[] {
  const findings: Finding[] = [];
  const { content, filePath } = context;

  if (content.length < 10) return findings;

  // Skip binary-looking or minified files
  const ext = filePath.toLowerCase();
  for (const skipExt of SKIP_ENTROPY_EXTENSIONS) {
    if (ext.endsWith(skipExt)) return findings;
  }

  // Run password patterns
  for (const pattern of PASSWORD_PATTERNS) {
    findings.push(...detectSecretPattern(content, filePath, pattern));
  }

  // Run API key patterns
  for (const pattern of API_KEY_PATTERNS) {
    findings.push(...detectSecretPattern(content, filePath, pattern));
  }

  // Run private key patterns
  for (const pattern of PRIVATE_KEY_PATTERNS) {
    findings.push(...detectSecretPattern(content, filePath, pattern));
  }

  // Detect high-entropy strings
  findings.push(...detectHighEntropyStrings(content, filePath));

  return findings;
}

// ─── Internal Helpers ──────────────────────────────────────────────────────

function detectSecretPattern(source: string, filePath: string, pattern: SecretPattern): Finding[] {
  const findings: Finding[] = [];
  const matches = matchPattern(source, pattern.regex);

  for (const match of matches) {
    // Skip lines that look like comments, docs, or test data
    const trimmed = match.lineContent.trimStart();
    if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('#') || trimmed.startsWith('/*')) {
      continue;
    }
    // Skip lines that reference environment variables (good practice)
    if (/process\.env\b|os\.environ|System\.getenv|ENV\[/i.test(match.lineContent)) {
      continue;
    }
    // Skip example/placeholder values
    if (/(?:example|placeholder|your[_-]|changeme|xxxx|TODO|FIXME)/i.test(match.match)) {
      continue;
    }

    const snippet = extractSnippet(source, match.line);
    findings.push(
      createFinding({
        ruleId: pattern.id,
        scanner: 'security',
        severity: pattern.severity,
        confidence: pattern.confidence,
        category: 'secrets',
        subcategory: pattern.subcategory,
        title: `Hardcoded Secret${pattern.service ? ` (${pattern.service})` : ''}`,
        message: pattern.message,
        filePath,
        lineNumber: match.line,
        column: match.column,
        snippet,
        cwe: ['CWE-798'],
        owasp: ['A02:2021'],
        fix: {
          description: 'Move secrets to environment variables, a vault service, or a secrets manager. Never commit secrets to source control.',
          references: [
            'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
          ],
        },
        tags: ['secrets', 'credentials', ...(pattern.service ? [pattern.service.toLowerCase()] : [])],
      }),
    );
  }

  return findings;
}

/**
 * Detect high-entropy strings that may be secrets.
 */
function detectHighEntropyStrings(source: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const lines = source.split('\n');

  // Regex to match string assignments that might contain secrets
  const stringAssignmentRegex = /(?:=|:)\s*["']([A-Za-z0-9+/=_\-]{20,})["']/g;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trimStart();

    // Skip comments
    if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('#')) continue;
    // Skip imports/requires
    if (/^\s*(?:import|require|from|use)\b/.test(line)) continue;
    // Skip lines referencing env vars
    if (/process\.env|os\.environ|System\.getenv/i.test(line)) continue;

    let m: RegExpExecArray | null;
    const regex = new RegExp(stringAssignmentRegex.source, stringAssignmentRegex.flags);
    while ((m = regex.exec(line)) !== null) {
      const value = m[1];

      // Skip known false positives
      if (ENTROPY_FALSE_POSITIVES.has(value)) continue;
      // Skip short strings or very long strings (likely not secrets)
      if (value.length < 20 || value.length > 256) continue;
      // Skip if it looks like a URL path, CSS class, or file path
      if (/^[a-z][a-z0-9-]*(?:\/[a-z][a-z0-9-]*)*$/i.test(value)) continue;
      // Skip base64-encoded images or data URIs
      if (/^data:/.test(value)) continue;

      const entropy = shannonEntropy(value);
      // High entropy threshold: base64 charset ~= 4.5, hex charset ~= 3.7
      if (entropy >= 4.2) {
        const snippet = extractSnippet(source, i + 1);
        findings.push(
          createFinding({
            ruleId: 'SEC-SEC-050',
            scanner: 'security',
            severity: 'medium',
            confidence: 'low',
            category: 'secrets',
            subcategory: 'high-entropy',
            title: 'High-Entropy String (Possible Secret)',
            message: `High-entropy string detected (entropy: ${entropy.toFixed(2)}). This may be a hardcoded secret or key.`,
            filePath,
            lineNumber: i + 1,
            column: m.index + 1,
            snippet,
            cwe: ['CWE-798'],
            owasp: ['A02:2021'],
            fix: {
              description: 'If this is a secret, move it to environment variables or a secrets manager.',
              references: [],
            },
            tags: ['secrets', 'entropy'],
          }),
        );
      }

      if (m.index === regex.lastIndex) regex.lastIndex++;
    }
  }

  return findings;
}
