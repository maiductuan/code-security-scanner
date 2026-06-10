// ─── API Security Analyzer ──────────────────────────────────────────────────
// Phát hiện lỗ hổng API & Misconfiguration: XXE, SSRF, CORS/CSRF, Rate Limiting
// Detects XXE, SSRF, unsafe CORS, disabled CSRF, and missing rate limits

import type { Finding, Severity, Confidence } from '../../../types/finding.js';
import type { ScanFileContext } from '../../../types/scanner.js';
import { createFinding, extractSnippet, matchPattern } from '../../base-scanner.js';

interface APISecPattern {
  regex: RegExp;
  message: string;
  severity: Severity;
  confidence: Confidence;
  subcategory: string;
  ruleId: string;
  cwe: string[];
  title: string;
}

const API_SEC_PATTERNS: APISecPattern[] = [
  // ── XXE (XML External Entity) ──
  {
    regex: /DocumentBuilderFactory\s*\.\s*(?:newInstance|newDefaultInstance)\s*\(/i,
    message: 'Java DocumentBuilderFactory instantiated – ensure DTD/external entities are explicitly disabled to prevent XXE',
    severity: 'critical',
    confidence: 'medium',
    subcategory: 'xxe',
    ruleId: 'SEC-XXE-001',
    cwe: ['CWE-611'],
    title: 'XML External Entity (XXE) Risk in Java',
  },
  {
    regex: /XMLInputFactory\s*\.\s*(?:newInstance|newFactory)\s*\(/i,
    message: 'Java XMLInputFactory instantiated – ensure DTD/external entities are disabled to prevent XXE',
    severity: 'critical',
    confidence: 'medium',
    subcategory: 'xxe',
    ruleId: 'SEC-XXE-001',
    cwe: ['CWE-611'],
    title: 'XML External Entity (XXE) Risk in Java',
  },
  {
    regex: /libxmljs\s*\.\s*parseXml\s*\(\s*[^,)]+\s*,\s*\{\s*noent\s*:\s*true/i,
    message: 'libxmljs parseXml with noent: true – enables entity substitution, vulnerable to XXE',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'xxe',
    ruleId: 'SEC-XXE-002',
    cwe: ['CWE-611'],
    title: 'XML External Entity (XXE) via libxmljs',
  },
  {
    regex: /xml2js\s*\.\s*Parser\s*\(\s*\{\s*explicitCharkey\s*:[^}]*\}\s*\)/i,
    message: 'xml2js parser instantiated – ensure external entity parsing is disabled',
    severity: 'medium',
    confidence: 'low',
    subcategory: 'xxe',
    ruleId: 'SEC-XXE-002',
    cwe: ['CWE-611'],
    title: 'XML Parser Misconfiguration',
  },
  {
    regex: /etree\s*\.\s*parse\s*\(/i,
    message: 'Python xml.etree.ElementTree.parse used – vulnerable to XML attacks, use defusedxml instead',
    severity: 'medium',
    confidence: 'medium',
    subcategory: 'xxe',
    ruleId: 'SEC-XXE-003',
    cwe: ['CWE-611'],
    title: 'Unsafe Python XML Parser',
  },

  // ── SSRF (Server-Side Request Forgery) ──
  {
    regex: /axios\s*\.\s*(?:get|post|request|put|delete)\s*\(\s*(?:req|request|params|query|body|args|input|user|url)\b/i,
    message: 'Axios request with user-controlled URL – vulnerable to Server-Side Request Forgery (SSRF)',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'ssrf',
    ruleId: 'SEC-SRF-001',
    cwe: ['CWE-918'],
    title: 'Server-Side Request Forgery (SSRF)',
  },
  {
    regex: /fetch\s*\(\s*(?:req|request|params|query|body|args|input|user|url)\b/i,
    message: 'Fetch request with user-controlled URL – vulnerable to SSRF',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'ssrf',
    ruleId: 'SEC-SRF-001',
    cwe: ['CWE-918'],
    title: 'Server-Side Request Forgery (SSRF)',
  },
  {
    regex: /urllib\s*\.\s*(?:request\s*\.\s*)?urlopen\s*\(\s*(?:req|request|params|user_input|url)\b/i,
    message: 'Python urlopen with potentially user-controlled URL – vulnerable to SSRF',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'ssrf',
    ruleId: 'SEC-SRF-002',
    cwe: ['CWE-918'],
    title: 'Server-Side Request Forgery (SSRF)',
  },
  {
    regex: /requests\s*\.\s*(?:get|post|request)\s*\(\s*(?:req|request|params|user_input|url)\b/i,
    message: 'Python requests with user-controlled URL – vulnerable to SSRF',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'ssrf',
    ruleId: 'SEC-SRF-002',
    cwe: ['CWE-918'],
    title: 'Server-Side Request Forgery (SSRF)',
  },
  {
    regex: /(?:HttpURLConnection|HttpClient)\b.*(?:openStream|send|execute)/i,
    message: 'Java HTTP request instantiated – verify target URL is validated against SSRF',
    severity: 'high',
    confidence: 'low',
    subcategory: 'ssrf',
    ruleId: 'SEC-SRF-003',
    cwe: ['CWE-918'],
    title: 'Potential SSRF in Java',
  },

  // ── CORS Misconfiguration ──
  {
    regex: /Access-Control-Allow-Origin["']\s*[\s,:=]\s*["']\*["']/i,
    message: 'CORS wildcard (*) origin allowed – can expose API responses to unauthorized websites',
    severity: 'high',
    confidence: 'high',
    subcategory: 'cors',
    ruleId: 'SEC-COR-001',
    cwe: ['CWE-942'],
    title: 'Unsafe CORS Wildcard Configuration',
  },
  {
    regex: /origin\s*:\s*["']\*["']/i,
    message: 'Express CORS middleware configured with wildcard origin',
    severity: 'medium',
    confidence: 'high',
    subcategory: 'cors',
    ruleId: 'SEC-COR-001',
    cwe: ['CWE-942'],
    title: 'Unsafe CORS Wildcard Configuration',
  },
  {
    regex: /Access-Control-Allow-Origin["']\s*[\s,:=]\s*req\.headers\s*\[\s*["']origin["']\s*\]/i,
    message: 'CORS origin dynamically reflected from headers without validation',
    severity: 'critical',
    confidence: 'medium',
    subcategory: 'cors',
    ruleId: 'SEC-COR-002',
    cwe: ['CWE-942'],
    title: 'Unvalidated Dynamic CORS Origin',
  },

  // ── CSRF Misconfiguration ──
  {
    regex: /csrf\s*\(\s*\)\s*\.\s*disable\s*\(\s*\)/i,
    message: 'CSRF protection explicitly disabled in Spring Security configuration',
    severity: 'high',
    confidence: 'high',
    subcategory: 'csrf',
    ruleId: 'SEC-CSRF-001',
    cwe: ['CWE-352'],
    title: 'CSRF Protection Disabled',
  },
  {
    regex: /csurf\s*\(\s*\)/i,
    message: 'csurf middleware usage detected',
    severity: 'low',
    confidence: 'high',
    subcategory: 'csrf',
    ruleId: 'SEC-CSRF-002',
    cwe: ['CWE-352'],
    title: 'CSRF Protection Enabled',
  },

  // ── Missing Rate Limiting ──
  {
    regex: /app\.(?:post|get|put|delete)\s*\(\s*["']\/api\/auth\/login["']\s*,\s*(?!(?:[a-zA-Z0-9_]+Limit|limiter)\b)/i,
    message: 'Sensitive login API endpoint defined without rate limiting middleware',
    severity: 'medium',
    confidence: 'high',
    subcategory: 'rate-limiting',
    ruleId: 'SEC-RAT-001',
    cwe: ['CWE-770'],
    title: 'Missing Rate Limiting on Login Endpoint',
  },
  {
    regex: /app\.(?:post|get|put|delete)\s*\(\s*["']\/api\/auth\/register["']\s*,\s*(?!(?:[a-zA-Z0-9_]+Limit|limiter)\b)/i,
    message: 'Sensitive registration API endpoint defined without rate limiting middleware',
    severity: 'medium',
    confidence: 'high',
    subcategory: 'rate-limiting',
    ruleId: 'SEC-RAT-001',
    cwe: ['CWE-770'],
    title: 'Missing Rate Limiting on Register Endpoint',
  },
];

/**
 * Analyze source code for API security vulnerabilities and misconfigurations.
 * Phân tích mã nguồn để phát hiện lỗi bảo mật API và cấu hình sai
 */
export function analyzeAPISec(context: ScanFileContext): Finding[] {
  const findings: Finding[] = [];
  const { content, filePath } = context;

  if (content.length < 10) return findings;

  for (const pattern of API_SEC_PATTERNS) {
    const matches = matchPattern(content, pattern.regex);
    for (const match of matches) {
      // Skip comments
      const trimmed = match.lineContent.trimStart();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('#') || trimmed.startsWith('/*')) {
        continue;
      }

      // Skip Java DocumentBuilderFactory / XMLInputFactory if safe features are explicitly configured
      if (pattern.subcategory === 'xxe' && pattern.ruleId === 'SEC-XXE-001') {
        if (
          content.includes('disallow-doctype-decl') ||
          (content.includes('external-general-entities') && content.includes('external-parameter-entities')) ||
          content.includes('SUPPORT_DTD') ||
          content.includes('IS_SUPPORTING_EXTERNAL_ENTITIES')
        ) {
          continue;
        }
      }

      // Skip SSRF if URL validation patterns are present in the file
      if (pattern.subcategory === 'ssrf' && (pattern.ruleId === 'SEC-SRF-001' || pattern.ruleId === 'SEC-SRF-002')) {
        if (
          content.includes('startsWith') ||
          content.includes('validate') ||
          content.includes('whitelist') ||
          content.includes('trusted')
        ) {
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
          category: 'api-security',
          subcategory: pattern.subcategory,
          title: pattern.title,
          message: pattern.message,
          filePath,
          lineNumber: match.line,
          column: match.column,
          snippet,
          cwe: pattern.cwe,
          owasp: ['A02:2021', 'A05:2021'], // Mapped to OWASP Categories
          fix: {
            description: 'Configure appropriate server parameters, validate target URLs, enable CSRF protection, and limit API requests.',
            references: [
              'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
              'https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html',
              'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html',
            ],
          },
          tags: ['api-security', pattern.subcategory],
        }),
      );
    }
  }

  return findings;
}
