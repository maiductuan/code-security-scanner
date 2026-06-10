import { writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { resolve, relative } from 'node:path';
import { execSync } from 'node:child_process';

interface ExpectedVulnerability {
  id: string;
  language: string;
  file: string; // relative to examples/
  line: number;
  category: string; // 'injection', 'xss', 'secrets', 'auth', 'crypto', 'file-ops', 'api-security', 'cve'
  description: string;
}

// Ground Truth: All expected vulnerabilities in our benchmark files
const EXPECTED_VULNERABILITIES: ExpectedVulnerability[] = [
  // ─── Node.js Backend ──────────────────────────────────────────────────────
  {
    id: "node-secrets-db",
    language: "javascript",
    file: "node-backend/config/db.js",
    line: 6,
    category: "secrets",
    description: "Hardcoded database password in config"
  },
  {
    id: "node-auth-password",
    language: "javascript",
    file: "node-backend/controllers/authController.js",
    line: 7,
    category: "auth",
    description: "Direct password string comparison (missing hashing)"
  },
  {
    id: "node-auth-jwt",
    language: "javascript",
    file: "node-backend/controllers/authController.js",
    line: 9,
    category: "auth",
    description: "Weak JWT signing algorithm (none or weak secret)"
  },
  {
    id: "node-auth-cookie",
    language: "javascript",
    file: "node-backend/controllers/authController.js",
    line: 12,
    category: "auth",
    description: "Insecure cookie configuration (httpOnly false)"
  },
  {
    id: "node-sqli-user",
    language: "javascript",
    file: "node-backend/controllers/userController.js",
    line: 7,
    category: "injection",
    description: "SQL Injection via string concatenation"
  },
  {
    id: "node-xss-user",
    language: "javascript",
    file: "node-backend/controllers/userController.js",
    line: 10,
    category: 'xss',
    description: "Reflected XSS via raw innerHTML write"
  },
  {
    id: "node-cmdi-ping",
    language: "javascript",
    file: "node-backend/controllers/userController.js",
    line: 17,
    category: "injection",
    description: "Command Injection in subprocess execution"
  },
  {
    id: "node-crypto-hash",
    language: "javascript",
    file: "node-backend/utils/crypto.js",
    line: 5,
    category: "crypto",
    description: "Weak cryptographic hashing algorithm (MD5)"
  },
  {
    id: "node-crypto-rand",
    language: "javascript",
    file: "node-backend/utils/crypto.js",
    line: 10,
    category: "crypto",
    description: "Insecure random number generator (Math.random)"
  },
  {
    id: "node-cve-axios",
    language: "javascript",
    file: "node-backend/package.json",
    line: 10,
    category: "cve",
    description: "Vulnerable axios dependency (< 0.21.2)"
  },
  {
    id: "node-cve-jwt",
    language: "javascript",
    file: "node-backend/package.json",
    line: 9,
    category: "cve",
    description: "Vulnerable jsonwebtoken dependency"
  },

  // ─── Python Application ───────────────────────────────────────────────────
  {
    id: "py-sqli-user",
    language: "python",
    file: "python-app/app.py",
    line: 13,
    category: "injection",
    description: "SQL Injection via python string formatting"
  },
  {
    id: "py-xss-user",
    language: "python",
    file: "python-app/app.py",
    line: 16,
    category: 'xss',
    description: "XSS in Flask raw string return"
  },
  {
    id: "py-cmdi-ping",
    language: "python",
    file: "python-app/app.py",
    line: 22,
    category: "injection",
    description: "Command Injection in os.system call"
  },
  {
    id: "py-cve-flask",
    language: "python",
    file: "python-app/requirements.txt",
    line: 1,
    category: "cve",
    description: "Vulnerable Flask package version"
  },
  {
    id: "py-cve-requests",
    language: "python",
    file: "python-app/requirements.txt",
    line: 2,
    category: "cve",
    description: "Vulnerable requests package version"
  },

  // ─── Go Service ───────────────────────────────────────────────────────────
  {
    id: "go-secrets-aws",
    language: "go",
    file: "go-service/main.go",
    line: 11,
    category: "secrets",
    description: "Hardcoded AWS Access Key ID"
  },
  {
    id: "go-path-traversal",
    language: "go",
    file: "go-service/main.go",
    line: 18,
    category: "file-ops",
    description: "Path Traversal in ReadFile call"
  },
  {
    id: "go-cve-gin",
    language: "go",
    file: "go-service/go.mod",
    line: 6,
    category: "cve",
    description: "Vulnerable gin-gonic dependency version"
  },

  // ─── Java Application ─────────────────────────────────────────────────────
  {
    id: "java-sqli",
    language: "java",
    file: "java-app/App.java",
    line: 14,
    category: "injection",
    description: "SQL Injection in execute statement"
  },
  {
    id: "java-xxe",
    language: "java",
    file: "java-app/App.java",
    line: 20,
    category: "api-security",
    description: "XML External Entity (XXE) vulnerability"
  },
  {
    id: "java-cve-log4j",
    language: "java",
    file: "java-app/pom.xml",
    line: 10,
    category: "cve",
    description: "Vulnerable log4j-core dependency (Log4Shell)"
  },
  {
    id: "py-django-sqli",
    language: "python",
    file: "python-app/django_views.py",
    line: 9,
    category: "injection",
    description: "SQL Injection via format string in raw SQL execute"
  },
  {
    id: "py-django-xss",
    language: "python",
    file: "python-app/django_views.py",
    line: 13,
    category: 'xss',
    description: "Reflected XSS via mark_safe on unescaped input"
  },
  {
    id: "node-nest-sqli",
    language: "javascript",
    file: "node-backend/controllers/nestUserController.ts",
    line: 13,
    category: "injection",
    description: "SQL Injection in TypeORM raw query"
  },
  {
    id: "node-nest-ssrf",
    language: "javascript",
    file: "node-backend/controllers/nestUserController.ts",
    line: 19,
    category: "api-security",
    description: "SSRF in axios call with user URL"
  },
  {
    id: "php-laravel-sqli",
    language: "php",
    file: "php-app/app/Http/Controllers/UserController.php",
    line: 14,
    category: "injection",
    description: "SQL Injection in DB::select string concatenation"
  },
  {
    id: "php-laravel-xss",
    language: "php",
    file: "php-app/resources/views/user.blade.php",
    line: 3,
    category: 'xss',
    description: "Reflected XSS in Blade template"
  },
  {
    id: "php-cve-laravel",
    language: "php",
    file: "php-app/composer.json",
    line: 4,
    category: "cve",
    description: "Vulnerable laravel/framework dependency version"
  }
];

interface ScannedFinding {
  ruleId: string;
  scanner: string;
  category: string;
  severity: string;
  file: string;
  line: number;
  message: string;
}

interface EvaluationResult {
  expected: ExpectedVulnerability;
  detected: boolean;
  findingDetails?: ScannedFinding;
}

interface FalsePositiveResult {
  file: string;
  line: number;
  ruleId: string;
  category: string;
  message: string;
}

async function run() {
  console.log('Starting DeepScan Accuracy and Benchmark Evaluation...');

  const rawJsonPath = resolve(process.cwd(), 'evaluation-raw.json');
  const examplesDir = resolve(process.cwd(), 'examples');

  // 1. Run the scanner
  console.log('Running scan on examples directory...');
  try {
    execSync(`npx tsx src/bin/deepscan.ts scan "${examplesDir}" --format json --output "${rawJsonPath}"`, { stdio: 'inherit' });
  } catch (err) {
    // CLI exits with code 1 if findings are found, which is expected
  }

  if (!existsSync(rawJsonPath)) {
    console.error('Scan failed to output evaluation-raw.json');
    process.exit(1);
  }

  // 2. Parse findings
  const scanData = JSON.parse(readFileSync(rawJsonPath, 'utf-8'));
  const rawFindings = scanData.findings || [];

  const findings: ScannedFinding[] = rawFindings.map((f: any) => ({
    ruleId: f.ruleId,
    scanner: f.scanner,
    category: f.category,
    severity: f.severity,
    file: relative(examplesDir, f.location.file).replace(/\\/g, '/'),
    line: f.location.startLine,
    message: f.message
  }));

  console.log(`Scan completed. Found ${findings.length} total findings.`);

  // 3. Map TPs, FNs, and FPs
  const evaluatedResults: EvaluationResult[] = [];
  const falsePositives: FalsePositiveResult[] = [];
  const matchedFindingIndices = new Set<number>();

  // Helper matching function
  const findMatchingFindingIndex = (exp: ExpectedVulnerability): number => {
    return findings.findIndex((f, idx) => {
      if (matchedFindingIndices.has(idx)) return false;

      const fileMatch = f.file === exp.file;
      // For CVE scanner, the line number in package manifests doesn't need to match exactly
      const lineMatch = exp.category === 'cve' || Math.abs(f.line - exp.line) <= 5;
      const catMatch = 
        f.category === exp.category || 
        f.ruleId.includes(exp.category) ||
        (exp.category === 'secrets' && f.ruleId.includes('secret')) ||
        (exp.category === 'xss' && f.ruleId.includes('xss')) ||
        (exp.category === 'cve' && f.scanner === 'cve');

      return fileMatch && lineMatch && catMatch;
    });
  };

  // Evaluate Expected TPs
  for (const exp of EXPECTED_VULNERABILITIES) {
    const fIdx = findMatchingFindingIndex(exp);
    if (fIdx !== -1) {
      matchedFindingIndices.add(fIdx);
      evaluatedResults.push({
        expected: exp,
        detected: true,
        findingDetails: findings[fIdx]
      });
    } else {
      evaluatedResults.push({
        expected: exp,
        detected: false
      });
    }
  }

  // Identify False Positives (FPs)
  findings.forEach((f, idx) => {
    // Quality scanner alerts (style/complexity smells) are expected and are not considered security false positives
    if (f.scanner === 'quality') return;

    const isSafeFile = f.file.includes('safe') || f.file.includes('Safe');
    
    // Check if there is an expected vulnerability on this file and category (regardless of exact line)
    const hasExpectedVuln = EXPECTED_VULNERABILITIES.some(exp => {
      const fileMatch = exp.file === f.file;
      const catMatch = 
        f.category === exp.category || 
        f.ruleId.includes(exp.category) ||
        (exp.category === 'secrets' && f.ruleId.includes('secret')) ||
        (exp.category === 'xss' && f.ruleId.includes('xss')) ||
        (exp.category === 'cve' && f.scanner === 'cve');
      return fileMatch && catMatch;
    });

    // It is a False Positive if it occurs in a safe file, or is on a file without this expected vulnerability
    if (isSafeFile || !hasExpectedVuln) {
      falsePositives.push({
        file: f.file,
        line: f.line,
        ruleId: f.ruleId,
        category: f.category,
        message: f.message
      });
    }
  });

  // 4. Calculate Stats
  const totalExpected = EXPECTED_VULNERABILITIES.length;
  const tpCount = evaluatedResults.filter(r => r.detected).length;
  const fnCount = totalExpected - tpCount;
  const fpCount = falsePositives.length;

  const recall = totalExpected > 0 ? (tpCount / totalExpected) * 100 : 0;
  const precision = (tpCount + fpCount) > 0 ? (tpCount / (tpCount + fpCount)) * 100 : 0;
  const f1 = (precision + recall) > 0 ? (2 * precision * recall) / (precision + recall) : 0;

  // Language stats
  const languages = ['javascript', 'python', 'go', 'java', 'php'];
  const langStats: Record<string, { expected: number; tp: number; fn: number; fp: number; recall: number }> = {};

  languages.forEach(lang => {
    const expectedForLang = EXPECTED_VULNERABILITIES.filter(v => v.language === lang);
    const tpForLang = evaluatedResults.filter(r => r.expected.language === lang && r.detected).length;
    const fnForLang = expectedForLang.length - tpForLang;
    
    // FPs belong to a language if the filepath contains it
    const fpForLang = falsePositives.filter(fp => {
      if (lang === 'javascript') return fp.file.includes('node-backend');
      if (lang === 'python') return fp.file.includes('python-app');
      if (lang === 'go') return fp.file.includes('go-service');
      if (lang === 'java') return fp.file.includes('java-app');
      if (lang === 'php') return fp.file.includes('php-app');
      return false;
    }).length;

    langStats[lang] = {
      expected: expectedForLang.length,
      tp: tpForLang,
      fn: fnForLang,
      fp: fpForLang,
      recall: expectedForLang.length > 0 ? (tpForLang / expectedForLang.length) * 100 : 0
    };
  });

  // Print results
  let summaryText = '--- EVALUATION SUMMARY ---\n';
  summaryText += `Expected Vulnerabilities: ${totalExpected}\n`;
  summaryText += `Successfully Caught (TP): ${tpCount}\n`;
  summaryText += `Missed (FN):              ${fnCount}\n`;
  summaryText += `False Positives (FP):     ${fpCount}\n`;
  summaryText += `Recall (Detection Rate):  ${recall.toFixed(1)}%\n`;
  summaryText += `Precision:                ${precision.toFixed(1)}%\n`;
  summaryText += `F1 Score:                 ${f1.toFixed(1)}%\n`;

  if (fnCount > 0) {
    summaryText += '\n--- MISSED VULNERABILITIES (FN) ---\n';
    evaluatedResults.filter(r => !r.detected).forEach(r => {
      summaryText += `- [${r.expected.language.toUpperCase()}] ${r.expected.file}:${r.expected.line} - ${r.expected.description} (${r.expected.category})\n`;
    });
  }

  if (fpCount > 0) {
    summaryText += '\n--- FALSE POSITIVES (FP) ---\n';
    falsePositives.forEach(fp => {
      summaryText += `- [${fp.category.toUpperCase()}] ${fp.file}:${fp.line} - ${fp.message}\n`;
    });
  }

  writeFileSync(resolve(process.cwd(), 'evaluation-summary.txt'), summaryText, 'utf-8');

  console.log(summaryText);

  // 5. Generate HTML Report
  const reportPath = resolve(process.cwd(), 'evaluation-report.html');
  const html = generateHtmlReport(
    totalExpected, tpCount, fnCount, fpCount, recall, precision, f1,
    langStats, evaluatedResults, falsePositives
  );

  writeFileSync(reportPath, html, 'utf-8');
  console.log(`\nEvaluation report successfully generated: ${reportPath}`);

  // Cleanup
  rmSync(rawJsonPath, { force: true });
}

function generateHtmlReport(
  expected: number, tp: number, fn: number, fp: number, recall: number, precision: number, f1: number,
  langStats: any, results: EvaluationResult[], falsePositives: FalsePositiveResult[]
): string {
  const formatPercentage = (val: number) => val.toFixed(1) + '%';
  const getLanguageLabel = (lang: string) => {
    if (lang === 'javascript') return 'Node.js / JavaScript';
    if (lang === 'python') return 'Python';
    if (lang === 'go') return 'Go';
    if (lang === 'java') return 'Java';
    if (lang === 'php') return 'PHP';
    return lang;
  };

  const resultsRows = results.map(r => `
    <tr class="${r.detected ? 'row-detected' : 'row-missed'}">
      <td><span class="badge lang-${r.expected.language}">${getLanguageLabel(r.expected.language)}</span></td>
      <td><strong>${r.expected.category.toUpperCase()}</strong></td>
      <td class="file-path">${r.expected.file}:${r.expected.line}</td>
      <td>${r.expected.description}</td>
      <td>
        ${r.detected 
          ? `<span class="status status-tp">Caught (TP)</span>` 
          : `<span class="status status-fn">Missed (FN)</span>`}
      </td>
    </tr>
  `).join('');

  const fpRows = falsePositives.length === 0 
    ? `<tr><td colspan="4" class="text-center text-muted">No False Positives detected! Great precision.</td></tr>`
    : falsePositives.map(f => `
      <tr class="row-fp">
        <td><strong>${f.category.toUpperCase()}</strong></td>
        <td class="file-path">${f.file}:${f.line}</td>
        <td>${f.message}</td>
        <td><span class="status status-fp">False Alarm (FP)</span></td>
      </tr>
    `).join('');

  const langRows = Object.entries(langStats).map(([lang, stat]: any) => `
    <tr>
      <td><strong>${getLanguageLabel(lang)}</strong></td>
      <td class="text-center">${stat.expected}</td>
      <td class="text-center text-success"><strong>${stat.tp}</strong></td>
      <td class="text-center text-danger">${stat.fn}</td>
      <td class="text-center text-warning">${stat.fp}</td>
      <td class="text-right">
        <div class="progress-container">
          <span class="progress-label">${formatPercentage(stat.recall)}</span>
          <div class="progress-bar-bg">
            <div class="progress-bar" style="width: ${stat.recall}%"></div>
          </div>
        </div>
      </td>
    </tr>
  `).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DeepScan Accuracy & Benchmark Report</title>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&family=Plus+Jakarta+Sans:wght@300;400;600;700&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #090a0f;
      --panel-dark: rgba(17, 19, 31, 0.7);
      --border-color: rgba(255, 255, 255, 0.08);
      --text-main: #f3f4f6;
      --text-muted: #9ca3af;
      --primary: #6366f1;
      --primary-glow: rgba(99, 102, 241, 0.15);
      --success: #10b981;
      --danger: #ef4444;
      --warning: #f59e0b;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      background-color: var(--bg-dark);
      color: var(--text-main);
      font-family: 'Plus Jakarta Sans', sans-serif;
      padding: 3rem 2rem;
      line-height: 1.5;
    }

    .container {
      max-width: 1200px;
      margin: 0 auto;
    }

    header {
      margin-bottom: 3rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    h1 {
      font-family: 'Outfit', sans-serif;
      font-size: 2.2rem;
      font-weight: 700;
      letter-spacing: -0.02em;
      background: linear-gradient(135deg, #fff 30%, #a5b4fc 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      margin-bottom: 0.5rem;
    }

    header p {
      color: var(--text-muted);
      font-size: 1rem;
    }

    .badge-scan {
      background: var(--primary-glow);
      border: 1px solid var(--primary);
      color: #a5b4fc;
      padding: 0.5rem 1rem;
      border-radius: 50px;
      font-size: 0.85rem;
      font-weight: 600;
    }

    /* Cards Grid */
    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 1.5rem;
      margin-bottom: 3rem;
    }

    .card {
      background: var(--panel-dark);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      padding: 1.8rem;
      backdrop-filter: blur(10px);
      box-shadow: 0 4px 30px rgba(0, 0, 0, 0.2);
    }

    .card-title {
      font-size: 0.85rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      margin-bottom: 0.8rem;
    }

    .card-value {
      font-family: 'Outfit', sans-serif;
      font-size: 2.5rem;
      font-weight: 700;
      color: #fff;
    }

    .card-value.highlight-success {
      color: var(--success);
      text-shadow: 0 0 15px rgba(16, 185, 129, 0.2);
    }

    .card-value.highlight-warning {
      color: ${fp > 0 ? 'var(--warning)' : 'var(--success)'};
    }

    /* Table styles */
    .section-title {
      font-family: 'Outfit', sans-serif;
      font-size: 1.5rem;
      font-weight: 600;
      margin-bottom: 1.5rem;
      color: #fff;
    }

    .table-container {
      background: var(--panel-dark);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      overflow: hidden;
      margin-bottom: 3rem;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
    }

    th, td {
      padding: 1rem 1.5rem;
      border-bottom: 1px solid var(--border-color);
      font-size: 0.9rem;
    }

    th {
      background: rgba(255, 255, 255, 0.02);
      color: var(--text-muted);
      font-weight: 600;
      text-transform: uppercase;
      font-size: 0.75rem;
      letter-spacing: 0.05em;
    }

    tr:last-child td {
      border-bottom: none;
    }

    .text-center { text-align: center; }
    .text-right { text-align: right; }

    /* Badges & Statuses */
    .badge {
      padding: 0.25rem 0.6rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 600;
    }

    .lang-javascript { background: rgba(245, 158, 11, 0.15); color: #fbbf24; }
    .lang-python { background: rgba(59, 130, 246, 0.15); color: #60a5fa; }
    .lang-go { background: rgba(6, 182, 212, 0.15); color: #22d3ee; }
    .lang-java { background: rgba(239, 68, 68, 0.15); color: #f87171; }
    .lang-php { background: rgba(139, 92, 246, 0.15); color: #a78bfa; }

    .status {
      display: inline-flex;
      align-items: center;
      padding: 0.35rem 0.8rem;
      border-radius: 50px;
      font-size: 0.8rem;
      font-weight: 600;
    }

    .status-tp { background: rgba(16, 185, 129, 0.1); color: var(--success); border: 1px solid rgba(16, 185, 129, 0.2); }
    .status-fn { background: rgba(239, 68, 68, 0.1); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.2); }
    .status-fp { background: rgba(245, 158, 11, 0.1); color: var(--warning); border: 1px solid rgba(245, 158, 11, 0.2); }

    .file-path {
      font-family: 'JetBrains Mono', monospace;
      color: #a5b4fc;
      font-size: 0.85rem;
    }

    /* Progress bar */
    .progress-container {
      display: inline-flex;
      align-items: center;
      gap: 0.8rem;
      width: 100%;
      justify-content: flex-end;
    }

    .progress-label {
      font-family: 'Outfit', sans-serif;
      font-weight: 600;
      color: #fff;
      min-width: 45px;
    }

    .progress-bar-bg {
      width: 100px;
      height: 6px;
      background: rgba(255, 255, 255, 0.05);
      border-radius: 10px;
      overflow: hidden;
    }

    .progress-bar {
      height: 100%;
      background: linear-gradient(90deg, var(--primary) 0%, var(--success) 100%);
      border-radius: 10px;
    }

    /* Row classes */
    .row-detected { background: rgba(16, 185, 129, 0.01); }
    .row-missed { background: rgba(239, 68, 68, 0.01); }
    .row-fp { background: rgba(245, 158, 11, 0.01); }

    @media (max-width: 1024px) {
      .metrics-grid {
        grid-template-columns: repeat(2, 1fr);
      }
    }

    @media (max-width: 640px) {
      .metrics-grid {
        grid-template-columns: 1fr;
      }
      body {
        padding: 1.5rem 1rem;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>DeepScan Accuracy & Benchmark</h1>
        <p>Calculated F1-Score and scanner verification analysis report</p>
      </div>
      <div class="badge-scan">
        Monorepo Benchmark v1.0
      </div>
    </header>

    <!-- Metrics -->
    <div class="metrics-grid">
      <div class="card">
        <div class="card-title">Detection Rate (Recall)</div>
        <div class="card-value highlight-success">${formatPercentage(recall)}</div>
      </div>
      <div class="card">
        <div class="card-title">Precision Rate</div>
        <div class="card-value">${formatPercentage(precision)}</div>
      </div>
      <div class="card">
        <div class="card-title">False Positives (FP)</div>
        <div class="card-value highlight-warning">${fp}</div>
      </div>
      <div class="card">
        <div class="card-title">Total Bugs Expected</div>
        <div class="card-value">${expected}</div>
      </div>
    </div>

    <!-- Language Breakdown -->
    <h2 class="section-title">Breakdown by Language / Environment</h2>
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>Language</th>
            <th class="text-center">Expected Bugs</th>
            <th class="text-center">Caught (TP)</th>
            <th class="text-center">Missed (FN)</th>
            <th class="text-center">False Alarms (FP)</th>
            <th class="text-right" style="width: 200px;">Recall / Accuracy</th>
          </tr>
        </thead>
        <tbody>
          ${langRows}
        </tbody>
      </table>
    </div>

    <!-- Expected Vulnerabilities Detail -->
    <h2 class="section-title">Expected Vulnerabilities Ground Truth Analysis</h2>
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>Language</th>
            <th>Category</th>
            <th>Location</th>
            <th>Vulnerability Description</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          ${resultsRows}
        </tbody>
      </table>
    </div>

    <!-- False Positives Detail -->
    <h2 class="section-title">False Positive Registry (False Alarms)</h2>
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>Category</th>
            <th>Location</th>
            <th>Message</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          ${fpRows}
        </tbody>
      </table>
    </div>
  </div>
</body>
</html>
`;
}

run();
