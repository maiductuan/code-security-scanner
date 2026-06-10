import { consola } from 'consola';
import type { CodeContext } from '../types/finding.js';

/**
 * Context Analyzer - Detects business logic context in code to improve scan accuracy
 *
 * This is a unique feature of DeepScan that no other tool provides.
 * By understanding WHAT the code does (auth, payment, data handling),
 * we can apply more targeted rules and reduce false positives.
 */

/** Context detection patterns for various business domains */
const CONTEXT_PATTERNS: Record<CodeContext['type'], ContextPattern[]> = {
  auth: [
    { regex: /\b(?:login|logout|signin|signout|signup|authenticate|authorize|auth)\b/i, weight: 3 },
    { regex: /\b(?:password|passwd|pwd|credential|token|session|jwt|oauth|sso)\b/i, weight: 2 },
    { regex: /\b(?:bcrypt|argon2|pbkdf2|scrypt|hash(?:Password|Passwd))\b/i, weight: 3 },
    { regex: /\b(?:isAuthenticated|isAuthorized|requireAuth|checkAuth|verifyToken)\b/i, weight: 3 },
    { regex: /\b(?:passport|express-session|cookie-session|jsonwebtoken)\b/i, weight: 2 },
    { regex: /\b(?:access_token|refresh_token|id_token|bearer)\b/i, weight: 2 },
    { regex: /\b(?:rbac|acl|permission|role|privilege)\b/i, weight: 2 },
    { regex: /\b(?:csrf|xsrf|cors)\b/i, weight: 1 },
    { regex: /\b(?:@Secured|@PreAuthorize|@RolesAllowed|@Authenticated)\b/, weight: 3 },
  ],
  payment: [
    { regex: /\b(?:payment|pay|charge|invoice|billing|subscription|checkout)\b/i, weight: 3 },
    { regex: /\b(?:stripe|paypal|braintree|square|adyen|razorpay)\b/i, weight: 3 },
    { regex: /\b(?:credit_card|card_number|cvv|cvc|expiry|expiration)\b/i, weight: 3 },
    { regex: /\b(?:amount|price|cost|fee|total|subtotal|tax|discount)\b/i, weight: 1 },
    { regex: /\b(?:refund|chargeback|dispute|payout|transfer)\b/i, weight: 2 },
    { regex: /\b(?:pci|pci-dss|cardholder)\b/i, weight: 3 },
    { regex: /\b(?:bank_account|routing_number|iban|swift|bic)\b/i, weight: 3 },
  ],
  'data-handling': [
    { regex: /\b(?:pii|gdpr|ccpa|hipaa|ferpa|coppa)\b/i, weight: 3 },
    { regex: /\b(?:personal_data|user_data|sensitive_data|private_data)\b/i, weight: 3 },
    { regex: /\b(?:ssn|social_security|tax_id|national_id)\b/i, weight: 3 },
    { regex: /\b(?:email|phone|address|date_of_birth|dob|gender)\b/i, weight: 1 },
    { regex: /\b(?:encrypt|decrypt|anonymize|pseudonymize|mask|redact)\b/i, weight: 2 },
    { regex: /\b(?:consent|opt_in|opt_out|data_retention|data_deletion)\b/i, weight: 2 },
    { regex: /\b(?:export_data|download_data|data_portability)\b/i, weight: 2 },
    { regex: /\b(?:medical|health|diagnosis|prescription|patient)\b/i, weight: 3 },
  ],
  api: [
    { regex: /\b(?:router|route|endpoint|controller|handler|middleware)\b/i, weight: 2 },
    { regex: /\b(?:app\.(?:get|post|put|patch|delete|use|all))\b/i, weight: 3 },
    { regex: /\b(?:@(?:Get|Post|Put|Patch|Delete|Controller|RestController|RequestMapping))\b/, weight: 3 },
    { regex: /\b(?:@api_view|@action|urlpatterns|path\(|url\()\b/i, weight: 3 },
    { regex: /\b(?:req|res|request|response|ctx|context)\b/i, weight: 1 },
    { regex: /\b(?:status\(\d{3}\)|json\(|send\(|render\()\b/i, weight: 1 },
    { regex: /\b(?:rate_limit|throttle|cors|helmet|swagger|openapi)\b/i, weight: 2 },
    { regex: /\b(?:api\/v\d|REST|GraphQL|gRPC|websocket)\b/i, weight: 2 },
  ],
  crypto: [
    { regex: /\b(?:crypto|cipher|decipher|encrypt|decrypt)\b/i, weight: 3 },
    { regex: /\b(?:createHash|createHmac|createCipher|createSign|createVerify)\b/i, weight: 3 },
    { regex: /\b(?:aes|rsa|ecdsa|ed25519|chacha20|x25519)\b/i, weight: 3 },
    { regex: /\b(?:sha256|sha384|sha512|blake2|argon2)\b/i, weight: 2 },
    { regex: /\b(?:public_key|private_key|secret_key|signing_key|verification_key)\b/i, weight: 3 },
    { regex: /\b(?:certificate|x509|pem|der|pkcs)\b/i, weight: 2 },
    { regex: /\b(?:nonce|iv|initialization_vector|salt|pepper)\b/i, weight: 2 },
    { regex: /\b(?:tls|ssl|https|mtls|certificate_pinning)\b/i, weight: 2 },
  ],
  'file-io': [
    { regex: /\b(?:readFile|writeFile|createReadStream|createWriteStream)\b/i, weight: 3 },
    { regex: /\b(?:fs\.|os\.path|shutil|pathlib)\b/i, weight: 2 },
    { regex: /\b(?:upload|download|attachment|multipart|formdata)\b/i, weight: 2 },
    { regex: /\b(?:mkdir|rmdir|unlink|rename|copy|move)\b/i, weight: 2 },
    { regex: /\b(?:tempfile|tmp|temporary|temp_dir)\b/i, weight: 1 },
    { regex: /\b(?:path\.join|path\.resolve|path\.normalize)\b/i, weight: 1 },
    { regex: /\b(?:chmod|chown|permissions|mode)\b/i, weight: 2 },
  ],
  general: [],
};

interface ContextPattern {
  regex: RegExp;
  weight: number;
}

/**
 * Analyze a file's content to determine its business logic context
 */
export function analyzeContext(
  content: string,
  filePath: string,
): CodeContext {
  const scores: Record<string, number> = {};
  const indicators: Record<string, string[]> = {};

  // Score each context type
  for (const [contextType, patterns] of Object.entries(CONTEXT_PATTERNS)) {
    if (contextType === 'general') continue;

    let score = 0;
    const matched: string[] = [];

    for (const { regex, weight } of patterns) {
      const matches = content.match(new RegExp(regex.source, regex.flags + 'g'));
      if (matches) {
        score += matches.length * weight;
        matched.push(`${regex.source.slice(0, 40)}... (${matches.length} matches)`);
      }
    }

    // Also boost score based on file path hints
    const pathLower = filePath.toLowerCase();
    if (contextType === 'auth' && /auth|login|session|user/i.test(pathLower)) score += 5;
    if (contextType === 'payment' && /payment|billing|checkout|order/i.test(pathLower)) score += 5;
    if (contextType === 'api' && /route|controller|handler|endpoint|api/i.test(pathLower)) score += 5;
    if (contextType === 'crypto' && /crypto|cipher|key|cert/i.test(pathLower)) score += 5;
    if (contextType === 'file-io' && /upload|file|storage|media/i.test(pathLower)) score += 5;
    if (contextType === 'data-handling' && /user|profile|account|data/i.test(pathLower)) score += 3;

    scores[contextType] = score;
    indicators[contextType] = matched;
  }

  // Find the highest-scoring context
  let bestType: CodeContext['type'] = 'general';
  let bestScore = 0;

  for (const [type, score] of Object.entries(scores)) {
    if (score > bestScore) {
      bestScore = score;
      bestType = type as CodeContext['type'];
    }
  }

  // Calculate confidence (0-1) based on score magnitude and dominance
  const totalScore = Object.values(scores).reduce((a, b) => a + b, 0);
  const confidence = totalScore > 0
    ? Math.min(bestScore / totalScore, 1) * Math.min(bestScore / 10, 1)
    : 0;

  // If confidence is too low, default to general
  if (confidence < 0.2 || bestScore < 5) {
    bestType = 'general';
  }

  return {
    type: bestType,
    confidence: Math.round(confidence * 100) / 100,
    indicators: indicators[bestType] || [],
    relatedFiles: [],
  };
}

/**
 * Get additional rules/modifications based on detected context
 */
export function getContextAdjustments(context: CodeContext): ContextAdjustment {
  const adjustments: ContextAdjustment = {
    additionalChecks: [],
    severityOverrides: {},
    suppressions: [],
  };

  switch (context.type) {
    case 'auth':
      // Auth code requires stricter security checks
      adjustments.additionalChecks.push(
        'Verify password hashing uses bcrypt/argon2',
        'Check for timing-safe comparisons',
        'Verify session configuration security',
        'Check for rate limiting on auth endpoints',
      );
      adjustments.severityOverrides = {
        'security/weak-auth': 'critical',
        'security/hardcoded-secret': 'critical',
        'security/weak-crypto': 'critical',
      };
      break;

    case 'payment':
      // Payment code is highly sensitive
      adjustments.additionalChecks.push(
        'Verify PCI-DSS compliance patterns',
        'Check for credit card data logging',
        'Verify secure transmission (HTTPS)',
        'Check amount validation and overflow',
      );
      adjustments.severityOverrides = {
        'security/hardcoded-secret': 'critical',
        'security/weak-crypto': 'critical',
        'quality/console-log': 'high', // Logging in payment code is dangerous
      };
      break;

    case 'data-handling':
      adjustments.additionalChecks.push(
        'Verify data encryption at rest',
        'Check for proper data anonymization',
        'Verify GDPR consent handling',
        'Check for data retention policies',
      );
      adjustments.severityOverrides = {
        'security/hardcoded-secret': 'critical',
        'quality/console-log': 'medium', // Logging PII is risky
      };
      break;

    case 'api':
      adjustments.additionalChecks.push(
        'Verify input validation on all endpoints',
        'Check for authentication middleware',
        'Verify rate limiting',
        'Check CORS configuration',
      );
      break;

    case 'crypto':
      adjustments.additionalChecks.push(
        'Verify algorithm strength (AES-256, SHA-256+)',
        'Check for proper key management',
        'Verify secure random number generation',
        'Check for proper IV/nonce usage',
      );
      adjustments.severityOverrides = {
        'security/weak-crypto': 'critical',
      };
      break;
  }

  return adjustments;
}

interface ContextAdjustment {
  additionalChecks: string[];
  severityOverrides: Record<string, string>;
  suppressions: string[];
}
