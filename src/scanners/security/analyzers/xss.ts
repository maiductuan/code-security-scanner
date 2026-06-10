// ─── XSS Analyzer ──────────────────────────────────────────────────────────
// Detects DOM-based, reflected, and stored XSS patterns

import type { Finding, Severity, Confidence } from '../../../types/finding.js';
import type { ScanFileContext } from '../../../types/scanner.js';
import { createFinding, extractSnippet, matchPattern } from '../../base-scanner.js';

// ─── Pattern Definitions ───────────────────────────────────────────────────

interface XSSPattern {
  regex: RegExp;
  message: string;
  severity: Severity;
  confidence: Confidence;
  subcategory: string;
  cwe: string[];
}

const XSS_PATTERNS: XSSPattern[] = [
  // ── innerHTML assignments ──
  {
    regex: /\.innerHTML\s*=\s*(?!['"`]\s*['"`])\S/i,
    message: 'Direct innerHTML assignment – may allow XSS if input is not sanitized',
    severity: 'high',
    confidence: 'high',
    subcategory: 'dom-xss',
    cwe: ['CWE-79'],
  },
  {
    regex: /\.innerHTML\s*=\s*(?:req|request|params|query|body|args|input|user|data)\b/i,
    message: 'innerHTML set to user-controlled value – high risk XSS',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'dom-xss',
    cwe: ['CWE-79'],
  },
  {
    regex: /\.innerHTML\s*\+=\s*\S/i,
    message: 'innerHTML concatenation – may allow XSS if input is not sanitized',
    severity: 'high',
    confidence: 'high',
    subcategory: 'dom-xss',
    cwe: ['CWE-79'],
  },
  {
    regex: /\.outerHTML\s*=\s*(?!['"`]\s*['"`])\S/i,
    message: 'Direct outerHTML assignment – may allow XSS',
    severity: 'high',
    confidence: 'high',
    subcategory: 'dom-xss',
    cwe: ['CWE-79'],
  },

  // ── document.write ──
  {
    regex: /document\.write(?:ln)?\s*\(/i,
    message: 'document.write() usage – can introduce XSS vulnerabilities',
    severity: 'high',
    confidence: 'high',
    subcategory: 'dom-xss',
    cwe: ['CWE-79'],
  },

  // ── dangerouslySetInnerHTML (React) ──
  {
    regex: /dangerouslySetInnerHTML\s*=\s*\{/i,
    message: 'dangerouslySetInnerHTML in React component – ensure input is sanitized',
    severity: 'medium',
    confidence: 'high',
    subcategory: 'react-xss',
    cwe: ['CWE-79'],
  },
  {
    regex: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?:req|request|params|query|body|args|input|user|data|props)\b/i,
    message: 'dangerouslySetInnerHTML with user-controlled data – XSS risk',
    severity: 'critical',
    confidence: 'high',
    subcategory: 'react-xss',
    cwe: ['CWE-79'],
  },

  // ── Unescaped output in templates ──
  {
    // Jinja2 / Twig: {{ variable | safe }} or {% autoescape false %}
    regex: /\{\{[^}]*\|\s*safe\s*\}\}/i,
    message: 'Template output marked as safe/unescaped – XSS risk if user-controlled',
    severity: 'medium',
    confidence: 'medium',
    subcategory: 'template-xss',
    cwe: ['CWE-79'],
  },
  {
    // EJS: <%- variable %>  (unescaped output)
    regex: /<%[-=]\s*(?:req|request|params|query|body|args|input|user|data)\b[^%]*%>/i,
    message: 'Unescaped EJS output with user-controlled data',
    severity: 'high',
    confidence: 'high',
    subcategory: 'template-xss',
    cwe: ['CWE-79'],
  },
  {
    // {!! $variable !!} (Laravel Blade unescaped)
    regex: /\{!!\s*\$\w+\s*!!\}/i,
    message: 'Unescaped Blade output ({!! !!}) – XSS risk if user-controlled',
    severity: 'medium',
    confidence: 'medium',
    subcategory: 'template-xss',
    cwe: ['CWE-79'],
  },
  {
    // Handlebars triple-stash {{{ variable }}}
    regex: /\{\{\{\s*\w+[^}]*\}\}\}/i,
    message: 'Handlebars triple-stash ({{{ }}}) outputs unescaped HTML – XSS risk',
    severity: 'medium',
    confidence: 'medium',
    subcategory: 'template-xss',
    cwe: ['CWE-79'],
  },
  {
    // {% autoescape false %}
    regex: /\{%\s*autoescape\s+(?:false|off)\s*%\}/i,
    message: 'Template autoescaping disabled – all output is vulnerable to XSS',
    severity: 'high',
    confidence: 'high',
    subcategory: 'template-xss',
    cwe: ['CWE-79'],
  },

  // ── DOM-based XSS patterns ──
  {
    // location.hash / location.search used in DOM operations
    regex: /(?:location\.(?:hash|search|href)|document\.(?:URL|referrer|documentURI))\s*(?:;|\))/i,
    message: 'DOM source (location/document) accessed – check for XSS if used in DOM sinks',
    severity: 'low',
    confidence: 'low',
    subcategory: 'dom-xss',
    cwe: ['CWE-79'],
  },
  {
    // element.insertAdjacentHTML
    regex: /\.insertAdjacentHTML\s*\(\s*['"][^'"]*['"]\s*,\s*(?!['"`]\s*['"`])\S/i,
    message: 'insertAdjacentHTML with dynamic content – possible XSS',
    severity: 'high',
    confidence: 'medium',
    subcategory: 'dom-xss',
    cwe: ['CWE-79'],
  },
  {
    // jQuery html() with dynamic content
    regex: /\$\s*\([^)]*\)\s*\.html\s*\(\s*(?!['"`]\s*['"`]|['"`]<)(?:\w|\$)/i,
    message: 'jQuery .html() with dynamic content – XSS risk',
    severity: 'high',
    confidence: 'medium',
    subcategory: 'dom-xss',
    cwe: ['CWE-79'],
  },
  {
    // jQuery append/prepend/after/before with user data
    regex: /\$\s*\([^)]*\)\s*\.(?:append|prepend|after|before)\s*\(\s*(?:req|request|params|query|body|args|input|user|data)\b/i,
    message: 'jQuery DOM insertion with user-controlled data – XSS risk',
    severity: 'high',
    confidence: 'high',
    subcategory: 'dom-xss',
    cwe: ['CWE-79'],
  },

  // ── Response header injection / reflected ──
  {
    // res.send(req.query.xxx) or res.send(req.body.xxx)
    regex: /res\.(?:send|write|end)\s*\(\s*(?:req|request)\s*\.\s*(?:query|body|params)\b/i,
    message: 'User input sent directly in HTTP response – reflected XSS risk',
    severity: 'high',
    confidence: 'high',
    subcategory: 'reflected-xss',
    cwe: ['CWE-79'],
  },
  {
    // Response.Write(Request.QueryString)
    regex: /Response\.Write\s*\(\s*Request\.(?:QueryString|Form|Params)/i,
    message: 'ASP.NET Response.Write with request data – reflected XSS',
    severity: 'high',
    confidence: 'high',
    subcategory: 'reflected-xss',
    cwe: ['CWE-79'],
  },
  {
    // res.send/write with template literal containing HTML and interpolation
    regex: /res\.(?:send|write|end)\s*\(\s*`[^`]*<[a-zA-Z]+[^>]*>[^`]*\$\{[^}]+\}[^`]*`\s*\)/i,
    message: 'Dynamic HTML template literal sent directly in HTTP response – reflected XSS risk',
    severity: 'high',
    confidence: 'medium',
    subcategory: 'reflected-xss',
    cwe: ['CWE-79'],
  },
  {
    // res.send/write with string concatenation containing HTML
    regex: /res\.(?:send|write|end)\s*\(\s*(?:['"][^'"]*<[a-zA-Z]+[^>]*>[^'"]*['"]\s*\+\s*[^)]+|[^,)]+\s*\+\s*['"][^'"]*<[a-zA-Z]+[^>]*>[^'"]*['"])/i,
    message: 'HTML string concatenation sent directly in HTTP response – reflected XSS risk',
    severity: 'high',
    confidence: 'medium',
    subcategory: 'reflected-xss',
    cwe: ['CWE-79'],
  },
  {
    // Flask/Python HTML response return with string formatting %
    regex: /return\s+['"][^'"]*<[a-zA-Z]+[^>]*>[^'"]*['"]\s*%\s*[^;]+/i,
    message: 'Python string formatting with % used to return HTML response – reflected XSS risk',
    severity: 'high',
    confidence: 'medium',
    subcategory: 'reflected-xss',
    cwe: ['CWE-79'],
  },
  {
    // Flask/Python HTML response return with f-strings
    regex: /return\s+f['"][^'"]*<[a-zA-Z]+[^>]*>[^'"]*\{[^}]+\}[^'"]*['"]/i,
    message: 'Python f-string used to return HTML response – reflected XSS risk',
    severity: 'high',
    confidence: 'medium',
    subcategory: 'reflected-xss',
    cwe: ['CWE-79'],
  },
  {
    // Flask/Python HTML response return with .format()
    regex: /return\s+['"][^'"]*<[a-zA-Z]+[^>]*>[^'"]*['"]\.format\s*\(/i,
    message: 'Python .format() used to return HTML response – reflected XSS risk',
    severity: 'high',
    confidence: 'medium',
    subcategory: 'reflected-xss',
    cwe: ['CWE-79'],
  },
  {
    // Django mark_safe XSS on non-literals
    regex: /mark_safe\s*\(\s*(?!(?:['"`][^'"`]*['"`])\s*\))\S/i,
    message: 'mark_safe called with dynamic content or variable – reflected XSS risk',
    severity: 'high',
    confidence: 'medium',
    subcategory: 'reflected-xss',
    cwe: ['CWE-79'],
  },
];

// ─── Main Analyzer Function ────────────────────────────────────────────────

/**
 * Analyze source code for Cross-Site Scripting (XSS) vulnerabilities.
 */
export function analyzeXSS(context: ScanFileContext): Finding[] {
  const findings: Finding[] = [];
  const { content, filePath } = context;

  if (content.length < 10) return findings;

  for (const pattern of XSS_PATTERNS) {
    const matches = matchPattern(content, pattern.regex);
    for (const match of matches) {
      // Skip matches that appear in comments
      const trimmed = match.lineContent.trimStart();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('#') || trimmed.startsWith('/*')) {
        continue;
      }

      const snippet = extractSnippet(content, match.line);
      findings.push(
        createFinding({
          ruleId: 'SEC-XSS-001',
          scanner: 'security',
          severity: pattern.severity,
          confidence: pattern.confidence,
          category: 'xss',
          subcategory: pattern.subcategory,
          title: 'Cross-Site Scripting (XSS)',
          message: pattern.message,
          filePath,
          lineNumber: match.line,
          column: match.column,
          snippet,
          cwe: pattern.cwe,
          owasp: ['A03:2021'],
          fix: {
            description: 'Sanitize and escape all user input before rendering in HTML. Use context-aware encoding.',
            references: [
              'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
              'https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html',
            ],
          },
          tags: ['xss', 'owasp-top10'],
        }),
      );
    }
  }

  return findings;
}
