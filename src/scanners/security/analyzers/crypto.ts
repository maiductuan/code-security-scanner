// ─── Crypto Analyzer ───────────────────────────────────────────────────────
// Phát hiện lỗ hổng mật mã: thuật toán yếu, khóa hardcode, TLS bị tắt
// Detects weak hash/encryption, insecure random, hardcoded keys, disabled TLS

import type { Finding, Severity, Confidence } from '../../../types/finding.js';
import type { ScanFileContext } from '../../../types/scanner.js';
import { createFinding, extractSnippet, matchPattern, isPatternDefinitionContext } from '../../base-scanner.js';

// ─── Pattern Definitions ───────────────────────────────────────────────────

interface CryptoPattern {
  regex: RegExp;
  message: string;
  severity: Severity;
  confidence: Confidence;
  subcategory: string;
  ruleId: string;
  cwe: string[];
}

const CRYPTO_PATTERNS: CryptoPattern[] = [
  // ── Weak Hash Algorithms ──
  {
    regex: /createHash\s*\(\s*["']md5["']\s*\)/i,
    message: 'MD5 hash used – MD5 is cryptographically broken, use SHA-256 or better',
    severity: 'high',
    confidence: 'high',
    subcategory: 'weak-hash',
    ruleId: 'SEC-CRYPTO-001',
    cwe: ['CWE-328'],
  },
  {
    regex: /createHash\s*\(\s*["']sha1["']\s*\)/i,
    message: 'SHA-1 hash used – SHA-1 has known collisions, use SHA-256 or better',
    severity: 'medium',
    confidence: 'high',
    subcategory: 'weak-hash',
    ruleId: 'SEC-CRYPTO-001',
    cwe: ['CWE-328'],
  },
  {
    regex: /(?:hashlib|MessageDigest)\s*\.\s*(?:md5|MD5)/i,
    message: 'MD5 hash usage detected – MD5 is cryptographically broken',
    severity: 'high',
    confidence: 'high',
    subcategory: 'weak-hash',
    ruleId: 'SEC-CRYPTO-001',
    cwe: ['CWE-328'],
  },
  {
    regex: /(?:hashlib|MessageDigest)\s*\.\s*(?:sha1|SHA1|SHA-1)/i,
    message: 'SHA-1 hash usage detected – SHA-1 has known collision attacks',
    severity: 'medium',
    confidence: 'high',
    subcategory: 'weak-hash',
    ruleId: 'SEC-CRYPTO-001',
    cwe: ['CWE-328'],
  },
  {
    regex: /DigestUtils\.md5(?:Hex)?\s*\(/i,
    message: 'Apache DigestUtils MD5 – use SHA-256 or better',
    severity: 'high',
    confidence: 'high',
    subcategory: 'weak-hash',
    ruleId: 'SEC-CRYPTO-001',
    cwe: ['CWE-328'],
  },
  {
    regex: /(?:MD5|md5)\s*\(\s*(?:password|passwd|pwd|pass|secret)\b/i,
    message: 'MD5 used for password hashing – use bcrypt, argon2, or scrypt instead',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'weak-hash',
    ruleId: 'SEC-CRYPTO-001',
    cwe: ['CWE-916'],
  },

  // ── Weak Encryption ──
  {
    regex: /createCipher(?:iv)?\s*\(\s*["'](?:des|des-ecb|des-cbc|des3|rc4|rc2|blowfish)["']/i,
    message: 'Weak encryption algorithm (DES/RC4/RC2) – use AES-256-GCM or ChaCha20',
    severity: 'high',
    confidence: 'high',
    subcategory: 'weak-encryption',
    ruleId: 'SEC-CRYPTO-002',
    cwe: ['CWE-327'],
  },
  {
    regex: /(?:DES|DESede|RC4|RC2|Blowfish)\.(?:new|getInstance)\s*\(/i,
    message: 'Weak encryption algorithm instantiated – use AES-256 instead',
    severity: 'high',
    confidence: 'high',
    subcategory: 'weak-encryption',
    ruleId: 'SEC-CRYPTO-002',
    cwe: ['CWE-327'],
  },
  {
    regex: /Cipher\.getInstance\s*\(\s*["'](?:DES|DESede|RC4|RC2|Blowfish)/i,
    message: 'Java Cipher with weak algorithm – use AES/GCM/NoPadding',
    severity: 'high',
    confidence: 'high',
    subcategory: 'weak-encryption',
    ruleId: 'SEC-CRYPTO-002',
    cwe: ['CWE-327'],
  },
  {
    regex: /(?:AES|Cipher).*(?:ECB|\/ECB\/)/i,
    message: 'ECB mode used for encryption – ECB does not provide semantic security, use CBC or GCM',
    severity: 'high',
    confidence: 'high',
    subcategory: 'weak-encryption',
    ruleId: 'SEC-CRYPTO-002',
    cwe: ['CWE-327'],
  },
  {
    regex: /createCipher\s*\(\s*["']/i,
    message: 'crypto.createCipher is deprecated and insecure – use createCipheriv with a random IV',
    severity: 'high',
    confidence: 'high',
    subcategory: 'weak-encryption',
    ruleId: 'SEC-CRYPTO-002',
    cwe: ['CWE-327'],
  },

  // ── Insecure Random Number Generation ──
  {
    regex: /Math\.random\s*\(\s*\)/i,
    message: 'Math.random() is not cryptographically secure – use crypto.randomBytes() or crypto.getRandomValues()',
    severity: 'medium',
    confidence: 'medium',
    subcategory: 'insecure-random',
    ruleId: 'SEC-CRYPTO-003',
    cwe: ['CWE-338'],
  },
  {
    regex: /(?:token|secret|key|password|nonce|salt|iv)\s*=\s*.*Math\.random/i,
    message: 'Math.random() used to generate security-sensitive value – use CSPRNG',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'insecure-random',
    ruleId: 'SEC-CRYPTO-003',
    cwe: ['CWE-338'],
  },
  {
    regex: /random\.random\s*\(\s*\)/i,
    message: 'Python random.random() is not cryptographically secure – use secrets module',
    severity: 'medium',
    confidence: 'medium',
    subcategory: 'insecure-random',
    ruleId: 'SEC-CRYPTO-003',
    cwe: ['CWE-338'],
  },
  {
    regex: /java\.util\.Random\b/i,
    message: 'java.util.Random is not cryptographically secure – use java.security.SecureRandom',
    severity: 'medium',
    confidence: 'medium',
    subcategory: 'insecure-random',
    ruleId: 'SEC-CRYPTO-003',
    cwe: ['CWE-338'],
  },
  {
    regex: /rand\s*\(\s*\)|srand\s*\(/i,
    message: 'rand()/srand() is not cryptographically secure',
    severity: 'medium',
    confidence: 'low',
    subcategory: 'insecure-random',
    ruleId: 'SEC-CRYPTO-003',
    cwe: ['CWE-338'],
  },

  // ── Hardcoded Encryption Keys ──
  {
    regex: /(?:encryption_key|encrypt_key|cipher_key|aes_key|AES_KEY)\s*[:=]\s*["'][A-Za-z0-9+/=]{8,}["']/i,
    message: 'Hardcoded encryption key – store keys in a secure key management system',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'hardcoded-key',
    ruleId: 'SEC-CRYPTO-004',
    cwe: ['CWE-321'],
  },
  {
    regex: /(?:private_key|PRIVATE_KEY|privateKey)\s*[:=]\s*["'][^"']{10,}["']/i,
    message: 'Hardcoded private key in source code',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'hardcoded-key',
    ruleId: 'SEC-CRYPTO-004',
    cwe: ['CWE-321'],
  },
  {
    regex: /(?:iv|IV|initVector|initialization_vector)\s*[:=]\s*["'][0-9a-fA-F]{16,}["']/i,
    message: 'Hardcoded initialization vector – IV should be randomly generated per encryption',
    severity: 'high',
    confidence: 'high',
    subcategory: 'hardcoded-key',
    ruleId: 'SEC-CRYPTO-004',
    cwe: ['CWE-329'],
  },
  {
    regex: /Buffer\.from\s*\(\s*["'][0-9a-fA-F]{16,}["']\s*,\s*["']hex["']\s*\)/i,
    message: 'Possible hardcoded key or IV created from hex string',
    severity: 'medium',
    confidence: 'medium',
    subcategory: 'hardcoded-key',
    ruleId: 'SEC-CRYPTO-004',
    cwe: ['CWE-321'],
  },

  // ── Disabled TLS Verification ──
  {
    regex: /rejectUnauthorized\s*[:=]\s*false/i,
    message: 'TLS certificate verification disabled (rejectUnauthorized: false) – vulnerable to MITM',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'tls',
    ruleId: 'SEC-CRYPTO-005',
    cwe: ['CWE-295'],
  },
  {
    regex: /NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*["']?0["']?/i,
    message: 'NODE_TLS_REJECT_UNAUTHORIZED set to 0 – disables all TLS verification',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'tls',
    ruleId: 'SEC-CRYPTO-005',
    cwe: ['CWE-295'],
  },
  {
    regex: /verify\s*[:=]\s*false|ssl_verify\s*[:=]\s*false|VERIFY_NONE/i,
    message: 'SSL/TLS verification disabled – vulnerable to man-in-the-middle attacks',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'tls',
    ruleId: 'SEC-CRYPTO-005',
    cwe: ['CWE-295'],
  },
  {
    regex: /InsecureRequestWarning.*disable/i,
    message: 'Insecure request warning suppressed – likely because TLS verification is disabled',
    severity: 'medium',
    confidence: 'medium',
    subcategory: 'tls',
    ruleId: 'SEC-CRYPTO-005',
    cwe: ['CWE-295'],
  },
  {
    regex: /ssl\._create_unverified_context/i,
    message: 'Python ssl._create_unverified_context() – disables certificate verification',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'tls',
    ruleId: 'SEC-CRYPTO-005',
    cwe: ['CWE-295'],
  },
  {
    regex: /checkServerIdentity\s*:\s*\(\s*\)\s*=>\s*(?:true|undefined|null|void)/i,
    message: 'Custom checkServerIdentity always returns true – disables hostname verification',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'tls',
    ruleId: 'SEC-CRYPTO-005',
    cwe: ['CWE-297'],
  },
];

// ─── Main Analyzer Function ────────────────────────────────────────────────

/**
 * Analyze source code for cryptography vulnerabilities.
 * Phân tích mã nguồn để phát hiện lỗ hổng mật mã
 */
export function analyzeCrypto(context: ScanFileContext): Finding[] {
  const findings: Finding[] = [];
  const { content, filePath } = context;

  if (content.length < 10) return findings;

  for (const pattern of CRYPTO_PATTERNS) {
    const matches = matchPattern(content, pattern.regex);
    for (const match of matches) {
      // Skip comments
      const trimmed = match.lineContent.trimStart();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('#') || trimmed.startsWith('/*')) {
        continue;
      }

      // Skip matches inside pattern/rule definition contexts
      if (isPatternDefinitionContext(match.lineContent, match.column)) continue;

      // Skip Math.random() in non-cryptographic/non-security contexts (e.g. UI key/ID generation)
      if (pattern.subcategory === 'insecure-random' && pattern.regex.source.includes('Math\\.random')) {
        const isSafeContext = 
          trimmed.includes('id:') ||
          trimmed.includes('id =') ||
          trimmed.includes('key:') ||
          trimmed.includes('key =') ||
          trimmed.includes('reactKey') ||
          trimmed.includes('index') ||
          trimmed.includes('assert') ||
          trimmed.includes('tc.') ||
          /^(?:const|let|var)\s+\w*(?:id|key|uuid|idx|index)\w*\s*=/i.test(trimmed);
        if (isSafeContext) {
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
          category: 'crypto',
          subcategory: pattern.subcategory,
          title: 'Cryptography Issue',
          message: pattern.message,
          filePath,
          lineNumber: match.line,
          column: match.column,
          snippet,
          cwe: pattern.cwe,
          owasp: ['A02:2021'],
          fix: {
            description: 'Use strong, modern cryptographic algorithms. SHA-256+ for hashing, AES-256-GCM for encryption, CSPRNG for randomness. Never hardcode keys or disable TLS.',
            references: [
              'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html',
              'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html',
            ],
          },
          tags: ['crypto', 'owasp-top10'],
        }),
      );
    }
  }

  return findings;
}
