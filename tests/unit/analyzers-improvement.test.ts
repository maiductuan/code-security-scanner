import { describe, it, expect } from 'vitest';
import { analyzeComplexity } from '../../src/scanners/quality/analyzers/complexity.js';
import { analyzeCodeSmells } from '../../src/scanners/quality/analyzers/code-smells.js';
import { analyzeSecrets } from '../../src/scanners/security/analyzers/secrets.js';
import { analyzeXSS } from '../../src/scanners/security/analyzers/xss.js';
import { analyzeInjection } from '../../src/scanners/security/analyzers/injection.js';
import { analyzeCrypto } from '../../src/scanners/security/analyzers/crypto.js';
import { analyzeFileOps } from '../../src/scanners/security/analyzers/file-ops.js';
import { analyzeAuth } from '../../src/scanners/security/analyzers/auth.js';
import { analyzeAPISec } from '../../src/scanners/security/analyzers/api-sec.js';
import { analyzeMetrics } from '../../src/scanners/quality/analyzers/metrics.js';
import { analyzeTaintFlow } from '../../src/core/taint-tracker.js';
import { parseDependencies } from '../../src/scanners/cve/parsers/package-parser.js';

describe('Improved Analyzers Verification Round 2', () => {
  describe('XSS Sanitizer Awareness', () => {
    it('should not flag innerHTML when input is sanitized by sanitizeHtml() in preceding lines', () => {
      const code = `
export function RichTextEditor({ content, value }) {
  useEffect(() => {
    const safeHtml = sanitizeHtml(content);
    if (editorRef.current.innerHTML !== safeHtml) {
      editorRef.current.innerHTML = safeHtml;
    }
  }, [value]);
}
`;
      const findings = analyzeXSS({
        content: code,
        filePath: 'src/components/RichTextEditor.tsx',
        language: 'typescript',
        rules: [],
      });
      expect(findings.length).toBe(0);
    });

    it('should not flag dangerouslySetInnerHTML when variable is produced by useMemo(() => buildHtmlAndToc(...))', () => {
      const code = `
import { buildHtmlAndToc } from '../utils/contentParser';
export function ArticleDetailPage({ post }) {
  const { htmlWithIds, headings } = useMemo(
    () => buildHtmlAndToc(post?.content || ''),
    [post?.content]
  );
  return <div dangerouslySetInnerHTML={{ __html: htmlWithIds }} />;
}
`;
      const findings = analyzeXSS({
        content: code,
        filePath: 'resources/js/pages/ArticleDetailPage.jsx',
        language: 'javascript',
        rules: [],
      });
      expect(findings.length).toBe(0);
    });

    it('should still flag unsanitized innerHTML assignments with user input', () => {
      const vulnerableCode = `
function renderUserBio(userInput) {
  document.getElementById('bio').innerHTML = userInput;
}
`;
      const findings = analyzeXSS({
        content: vulnerableCode,
        filePath: 'src/components/UserBio.tsx',
        language: 'typescript',
        rules: [],
      });
      expect(findings.length).toBeGreaterThan(0);
    });
  });

  describe('Laravel Raw SQL Injection Detection', () => {
    it('should detect SQL injection in Laravel orderByRaw with variable interpolation', () => {
      const phpCode = `<?php
namespace App\\Http\\Controllers\\Api\\V1;

class PostController {
    public function getTrending($quotedList) {
        $query = Post::query();
        $query->orderByRaw("CASE WHEN posts.id IN ($quotedList) THEN 1 ELSE 0 END ASC");
        return $query->get();
    }
}
`;
      const findings = analyzeInjection({
        content: phpCode,
        filePath: 'app/Http/Controllers/Api/V1/PostController.php',
        language: 'php',
        rules: [],
      });
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].ruleId).toBe('SEC-INJ-002');
    });

    it('should not flag parameterized Laravel raw queries', () => {
      const safeCode = `<?php
class SafeController {
    public function index($id) {
        return DB::select("SELECT * FROM users WHERE id = ?", [$id]);
    }
}
`;
      const findings = analyzeInjection({
        content: safeCode,
        filePath: 'app/Http/Controllers/SafeController.php',
        language: 'php',
        rules: [],
      });
      expect(findings.length).toBe(0);
    });
  });

  describe('Metrics Analyzer', () => {
    it('should not emit QUA-METRICS-001 info issues into findings list', () => {
      const code = `
function hello() {
  return 'world';
}
`;
      const findings = analyzeMetrics({
        content: code,
        filePath: 'src/index.ts',
        language: 'typescript',
        rules: [],
      });
      const metricFindings = findings.filter(f => f.ruleId === 'QUA-METRICS-001');
      expect(metricFindings.length).toBe(0);
    });
  });

  describe('Path Traversal Ellipsis Escape False Positive Prevention', () => {
    it('should not flag ellipsis followed by newline escape (...\\n) in string literals', () => {
      const seederCode = `<?php
$post = [
    'prompt_template' => "Scene 1 (00:00-00:15): Medium shot at modern white studio desk...\\nScene 2: Close-up shot...",
];
`;
      const findings = analyzeFileOps({
        content: seederCode,
        filePath: 'database/seeders/DatabaseSeeder.php',
        language: 'php',
        rules: [],
      });
      expect(findings.length).toBe(0);
    });
  });

  describe('Crypto Math.random() UI & Canvas Context Awareness', () => {
    it('should not flag Math.random() in Canvas particle animation', () => {
      const canvasCode = `
export function NeuralCanvas({ width, height }) {
  const node = {
    x: Math.random() * width,
    y: Math.random() * height,
    vx: (Math.random() - 0.5) * 0.48,
    pulsePhase: Math.random() * Math.PI * 2,
  };
  return node;
}
`;
      const findings = analyzeCrypto({
        content: canvasCode,
        filePath: 'resources/js/components/NeuralCanvas.jsx',
        language: 'javascript',
        rules: [],
      });
      expect(findings.length).toBe(0);
    });

    it('should still flag Math.random() when generating tokens or secrets', () => {
      const badCryptoCode = `
function generateResetToken() {
  const token = Math.random().toString(36).substring(2);
  return token;
}
`;
      const findings = analyzeCrypto({
        content: badCryptoCode,
        filePath: 'src/auth/token.ts',
        language: 'typescript',
        rules: [],
      });
      expect(findings.length).toBeGreaterThan(0);
    });
  });

  describe('Complexity Control-Flow Keyword Exclusion', () => {
    it('should not treat if() or foreach() statements as function declarations', () => {
      const phpCode = `<?php
class SyncController {
    public function handle($items) {
        if ($items && count($items) > 0) {
            foreach ($items as $item) {
                if ($item->a || $item->b || $item->c || $item->d || $item->e) {
                    if ($item->f && $item->g && $item->h && $item->i && $item->j) {
                        if ($item->k || $item->l || $item->m || $item->n || $item->o) {
                            echo $item->name;
                        }
                    }
                }
            }
        }
    }
}
`;
      const findings = analyzeComplexity({
        content: phpCode,
        filePath: 'app/Http/Controllers/SyncController.php',
        language: 'php',
        rules: [],
      });
      const bogusFuncFindings = findings.filter(
        f => f.message.includes("Function 'if'") || f.message.includes("Function 'foreach'")
      );
      expect(bogusFuncFindings.length).toBe(0);
    });
  });

  describe('Round 3 Real-World Corpus Improvements', () => {
    it('should detect hardcoded fallback secrets in process.env expressions and Google GOCSPX secrets', () => {
      const code = `
const ADMIN_SECRET = process.env.ADMIN_SECRET_KEY || 'bungbung_master_secret_2026';
const JWT_SECRET = process.env.JWT_SECRET || 'veil_jwt_secret_token_key_safe_2026';
const GOOGLE_SECRET = process.env.GOOGLE_CLIENT_SECRET || 'GOCSPX-1234567890abcdefghijklmnopqr';
`;
      const secretFindings = analyzeSecrets({
        content: code,
        filePath: 'src/config/security.ts',
        language: 'typescript',
        rules: [],
      });
      const authFindings = analyzeAuth({
        content: code,
        filePath: 'src/config/security.ts',
        language: 'typescript',
        rules: [],
      });
      expect(secretFindings.some(f => f.ruleId === 'SEC-SEC-001')).toBe(true);
      expect(secretFindings.some(f => f.ruleId === 'SEC-SEC-014')).toBe(true);
      expect(authFindings.some(f => f.ruleId === 'SEC-AUTH-004')).toBe(true);
    });

    it('should not flag character set lookup tables as high-entropy secrets', () => {
      const code = `
const chars = '0123456789ABCDEFGHJKLMNPQRSTUVWXYZ';
const base62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
`;
      const findings = analyzeSecrets({
        content: code,
        filePath: 'src/utils/id.ts',
        language: 'typescript',
        rules: [],
      });
      expect(findings.length).toBe(0);
    });

    it('should not flag app.disable("x-powered-by") in auth analyzer', () => {
      const code = `
import express from 'express';
const app = express();
app.disable('x-powered-by');
`;
      const findings = analyzeAuth({
        content: code,
        filePath: 'src/server.ts',
        language: 'typescript',
        rules: [],
      });
      expect(findings.length).toBe(0);
    });

    it('should not flag multi-line static or escapeHtml-sanitized innerHTML assignments', () => {
      const code = `
function renderEmpty(el, items) {
  el.innerHTML = \`
    <div class="empty-state">
      <p>No items available</p>
    </div>
  \`;
  el.innerHTML = items.map(v => \`
    <div class="card">
      <h3>\${escapeHtml(v.title)}</h3>
      <span>\${Number(v.count)}</span>
    </div>
  \`).join('');
}
`;
      const findings = analyzeXSS({
        content: code,
        filePath: 'src/ui/render.js',
        language: 'javascript',
        rules: [],
      });
      expect(findings.length).toBe(0);
    });

    it('should not flag RegExp.exec() or redisClient.eval() as command/code injection in taint tracker', () => {
      const code = `
function handleUpload(req) {
  const dataUrl = req.body.image;
  const match = /^data:image\\/png;base64,(.+)$/.exec(dataUrl);
  const res = redisClient.eval(luaScript, 1, dataUrl);
  return { match, res };
}
`;
      const taintResults = analyzeTaintFlow(code, 'src/upload.js', 'javascript', null);
      expect(taintResults.length).toBe(0);
    });

    it('should clean multi-range Composer/npm version constraints properly', () => {
      const composerJson = JSON.stringify({
        require: {
          'laravel/Sanctum': '10.24|^11.0|^12.0|^13.0',
        },
      });
      const deps = parseDependencies(composerJson, 'composer.json');
      expect(deps.length).toBe(1);
      expect(deps[0].version).toBe('13.0');
    });
  });
});
