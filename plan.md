# DeepScan - Open Source Security & Code Quality Scanner

## Tổng quan

**DeepScan** là một công cụ scan bảo mật và chất lượng code mã nguồn mở, kết hợp tính năng của SonarQube, Coverity, và CVE scanner vào một CLI tool duy nhất. Xây dựng bằng TypeScript/Node.js với kiến trúc plugin-based, hỗ trợ tất cả ngôn ngữ lập trình thông qua Tree-sitter.

### Điểm khác biệt (Unique Selling Points)
1. **Context-Aware Scanning** - Hiểu business logic context (auth, payment, API) để giảm false positive
2. **AI-Assisted Validation** - Tích hợp LLM để giải thích risk và validate findings  
3. **Cross-File Taint Analysis** - Theo dõi data flow xuyên nhiều file
4. **Semantic Pattern Matching** - So sánh cấu trúc code ở mức semantic thay vì chỉ syntax
5. **Unified Scanner** - Security + Quality + CVE trong một tool duy nhất

---

## User Review Required

> [!IMPORTANT]
> **Ngôn ngữ lập trình**: TypeScript/Node.js với Tree-sitter WASM bindings. Performance-critical paths sẽ dùng worker threads.

> [!WARNING] 
> **AI-Assisted Validation**: Tính năng này sẽ yêu cầu API key (OpenAI/Anthropic/local LLM). Cần quyết định: bắt buộc hay tùy chọn (optional, OFF by default)?

> [!IMPORTANT]
> **Scope ban đầu**: Dù target full language support, giai đoạn 1 sẽ tập trung hoàn thiện architecture + core engine + rules cho 5 ngôn ngữ phổ biến nhất (JavaScript/TypeScript, Python, Java, Go, C/C++). Các ngôn ngữ khác sẽ được thêm qua plugin system.

---

## Open Questions

> [!IMPORTANT]
> 1. **License**: MIT hay Apache 2.0? MIT phổ biến hơn, Apache 2.0 có patent protection.
> 2. **AI Provider**: Hỗ trợ OpenAI, Anthropic, hay Ollama (local)? Hay tất cả?
> 3. **Package name**: `@deepscan/cli` hay `deepscan-cli` trên npm?
> 4. **CVE Database**: Sử dụng NVD (National Vulnerability Database) hay OSV (Open Source Vulnerabilities by Google)?

---

## Kiến trúc tổng thể

```
┌─────────────────────────────────────────────────────────────────┐
│                        DeepScan CLI                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │
│  │  scan     │  │  init    │  │  report  │  │  rule-mgmt   │   │
│  │  command  │  │  config  │  │  convert │  │  list/add/rm │   │
│  └────┬─────┘  └──────────┘  └──────────┘  └──────────────┘   │
│       │                                                         │
│  ┌────▼──────────────────────────────────────────────────────┐  │
│  │              Pipeline Orchestrator                         │  │
│  │  ┌──────────┐  ┌───────────┐  ┌────────────────────────┐ │  │
│  │  │ File     │  │ Language  │  │ Parallel Execution     │ │  │
│  │  │ Discovery│→ │ Detection │→ │ (Worker Threads)       │ │  │
│  │  └──────────┘  └───────────┘  └────────────────────────┘ │  │
│  └────┬──────────────────────────────────────────────────────┘  │
│       │                                                         │
│  ┌────▼──────────────────────────────────────────────────────┐  │
│  │                  Scanner Engines                           │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │  │
│  │  │  Security    │  │  Quality     │  │  CVE/SCA     │    │  │
│  │  │  Scanner     │  │  Scanner     │  │  Scanner     │    │  │
│  │  │              │  │              │  │              │    │  │
│  │  │ • Injection  │  │ • Complexity │  │ • Dependency │    │  │
│  │  │ • XSS        │  │ • Duplicates │  │ • License    │    │  │
│  │  │ • Secrets    │  │ • CodeSmells │  │ • CVE Match  │    │  │
│  │  │ • Auth       │  │ • Standards  │  │ • SBOM       │    │  │
│  │  │ • Crypto     │  │ • Metrics    │  │              │    │  │
│  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘    │  │
│  └─────────┼─────────────────┼─────────────────┼────────────┘  │
│            │                 │                 │                │
│  ┌─────────▼─────────────────▼─────────────────▼────────────┐  │
│  │              Analysis Core                                │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │  │
│  │  │  Tree-sitter │  │  Taint       │  │  Context     │    │  │
│  │  │  Parser      │  │  Tracker     │  │  Analyzer    │    │  │
│  │  │  (WASM)      │  │  (DFA/CFA)   │  │  (Business)  │    │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘    │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │  │
│  │  │  Pattern     │  │  Semantic    │  │  AI          │    │  │
│  │  │  Matcher     │  │  Engine      │  │  Validator   │    │  │
│  │  │  (Queries)   │  │  (CPG)       │  │  (Optional)  │    │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘    │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              Rule Engine                                   │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │  │
│  │  │  Built-in    │  │  Custom      │  │  Rule        │    │  │
│  │  │  Rules       │  │  Rules       │  │  Validator   │    │  │
│  │  │  (YAML)      │  │  (YAML/JS)  │  │  & Loader    │    │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘    │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              Output / Reporter                             │  │
│  │  ┌────┐  ┌─────┐  ┌──────┐  ┌───────┐  ┌──────────┐    │  │
│  │  │JSON│  │ CSV │  │ HTML │  │ SARIF │  │ Console  │    │  │
│  │  └────┘  └─────┘  └──────┘  └───────┘  └──────────┘    │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Proposed Changes

### 1. Project Foundation

#### [NEW] [package.json](file:///d:/code/code-scan-security/package.json)
- Project metadata, dependencies, scripts
- CLI entry point configuration (`bin` field)
- Dependencies: `commander`, `tree-sitter`, `web-tree-sitter`, `chalk`, `glob`, `yaml`, `zod`, `consola`
- Dev dependencies: `typescript`, `tsup`, `vitest`, `tsx`

#### [NEW] [tsconfig.json](file:///d:/code/code-scan-security/tsconfig.json)
- TypeScript strict mode configuration
- ES2022 target, ESM modules
- Path aliases cho clean imports

#### [NEW] [.deepscan.yml](file:///d:/code/code-scan-security/.deepscan.yml)
- Example default configuration file
- Sử dụng để scan chính project DeepScan

---

### 2. CLI Layer (`src/cli/`)

#### [NEW] [src/cli/index.ts](file:///d:/code/code-scan-security/src/cli/index.ts)
- Entry point cho CLI application
- Commander.js setup với các commands: `scan`, `init`, `report`, `rules`
- Global options: `--config`, `--format`, `--output`, `--verbose`, `--quiet`

#### [NEW] [src/cli/commands/scan.ts](file:///d:/code/code-scan-security/src/cli/commands/scan.ts)
- Command chính: `deepscan scan [path]`
- Options:
  - `--scanners security,quality,cve` - chọn scanner engines
  - `--severity error,warning` - filter theo severity
  - `--include "**/*.ts"` - glob patterns cho files
  - `--exclude "node_modules/**"` - exclude patterns
  - `--deep` - enable deep analysis (taint + semantic)
  - `--ai` - enable AI validation
  - `--parallel <n>` - số worker threads
  - `--incremental` - chỉ scan changed files (git-based)

#### [NEW] [src/cli/commands/init.ts](file:///d:/code/code-scan-security/src/cli/commands/init.ts)
- `deepscan init` - tạo file `.deepscan.yml` mặc định
- Interactive mode hỏi user về project type, languages

#### [NEW] [src/cli/commands/rules.ts](file:///d:/code/code-scan-security/src/cli/commands/rules.ts)
- `deepscan rules list` - liệt kê tất cả rules
- `deepscan rules info <rule-id>` - chi tiết 1 rule
- `deepscan rules create` - scaffold custom rule

#### [NEW] [src/cli/commands/report.ts](file:///d:/code/code-scan-security/src/cli/commands/report.ts)
- `deepscan report convert --from json --to html`
- Convert giữa các format output

---

### 3. Configuration System (`src/config/`)

#### [NEW] [src/config/schema.ts](file:///d:/code/code-scan-security/src/config/schema.ts)
- Zod schemas cho configuration validation
- Type-safe config interfaces

```typescript
// Cấu trúc .deepscan.yml
interface DeepScanConfig {
  version: '1.0';
  scanners: {
    security: { enabled: boolean; severity: Severity[] };
    quality: { enabled: boolean; thresholds: QualityThresholds };
    cve: { enabled: boolean; sources: string[] };
  };
  rules: {
    include: string[];      // Rule IDs hoặc categories
    exclude: string[];
    custom: string[];       // Paths tới custom rule files
  };
  languages: string[];
  paths: {
    include: string[];
    exclude: string[];
  };
  output: {
    format: 'json' | 'csv' | 'html' | 'sarif' | 'console';
    file?: string;
  };
  ai?: {
    enabled: boolean;
    provider: 'openai' | 'anthropic' | 'ollama';
    model?: string;
    apiKey?: string;        // Hoặc env var
  };
  context?: {
    projectType: 'web' | 'api' | 'library' | 'mobile' | 'cli';
    frameworks: string[];   // express, react, spring, etc.
    sensitivePatterns: string[];  // Custom sensitive data patterns
  };
}
```

#### [NEW] [src/config/loader.ts](file:///d:/code/code-scan-security/src/config/loader.ts)
- Load config từ `.deepscan.yml`, `.deepscan.json`, `.deepscan.js`
- Merge config: default → project → CLI args
- Environment variable substitution

#### [NEW] [src/config/defaults.ts](file:///d:/code/code-scan-security/src/config/defaults.ts)
- Default configuration values
- Preset configs cho common project types

---

### 4. Analysis Core (`src/core/`)

#### [NEW] [src/core/parser.ts](file:///d:/code/code-scan-security/src/core/parser.ts)
- Tree-sitter WASM parser initialization
- Language-specific grammar loading (lazy)
- Parse file → CST (Concrete Syntax Tree)
- Caching parsed trees cho incremental analysis

#### [NEW] [src/core/ast-utils.ts](file:///d:/code/code-scan-security/src/core/ast-utils.ts)
- Utility functions cho tree traversal
- Node type queries, pattern matching helpers
- Source location mapping

#### [NEW] [src/core/taint-tracker.ts](file:///d:/code/code-scan-security/src/core/taint-tracker.ts)
**Cross-File Taint Analysis Engine**
- Build inter-procedural data flow graph
- Track tainted data từ sources (user input, network, env) tới sinks (SQL, exec, file write)
- Support cross-file tracking qua import/export analysis
- Configurable sources/sinks per language

```typescript
interface TaintConfig {
  sources: TaintSource[];   // { pattern: "req.body.*", type: "user_input" }
  sinks: TaintSink[];       // { pattern: "db.query($TAINTED)", type: "sql_injection" }
  sanitizers: Sanitizer[];  // { pattern: "escape($X)", cleanses: ["sql_injection"] }
  propagators: Propagator[];// { from: "$X.toString()", to: "return" }
}
```

#### [NEW] [src/core/context-analyzer.ts](file:///d:/code/code-scan-security/src/core/context-analyzer.ts)
**Context-Aware Analysis Engine** (Unique Feature)
- Phân tích business logic context:
  - Detect auth-related code (login, token, session)
  - Detect payment/financial code
  - Detect data handling patterns (PII, GDPR)
  - Detect API endpoints và access control
- Apply context-specific rules (ví dụ: auth code cần stricter checks)
- Reduce false positives bằng cách hiểu intent

```typescript
interface CodeContext {
  type: 'auth' | 'payment' | 'data-handling' | 'api' | 'crypto' | 'file-io' | 'general';
  confidence: number;      // 0-1
  indicators: string[];    // Tại sao classify như vậy
  relatedFiles: string[];  // Files liên quan trong cùng context
}
```

#### [NEW] [src/core/semantic-engine.ts](file:///d:/code/code-scan-security/src/core/semantic-engine.ts)
**Semantic Pattern Matching Engine** (Unique Feature)
- So sánh code patterns ở mức semantic thay vì chỉ syntax
- Normalize code trước khi so sánh (rename vars, simplify expressions)
- Detect semantic equivalence (ví dụ: `!a || !b` === `!(a && b)`)
- Build Code Property Graph (CPG) cho semantic analysis

#### [NEW] [src/core/ai-validator.ts](file:///d:/code/code-scan-security/src/core/ai-validator.ts)
**AI-Assisted Validation** (Optional Feature)
- Nhận finding từ scanners → gửi code context tới LLM
- LLM validate: true positive hay false positive?
- LLM explain: tại sao đây là risk? Cách fix?
- Support multiple providers: OpenAI, Anthropic, Ollama (local)
- Rate limiting và cost management
- Fallback khi không có AI: trả về raw findings

#### [NEW] [src/core/file-discovery.ts](file:///d:/code/code-scan-security/src/core/file-discovery.ts)
- Scan directory recursively
- Respect `.gitignore`, `.deepscanignore`
- Language detection by extension + content sniffing
- Dependency file detection (package.json, pom.xml, etc.)

#### [NEW] [src/core/pipeline.ts](file:///d:/code/code-scan-security/src/core/pipeline.ts)
- Orchestrate toàn bộ scanning pipeline
- Parallel execution with worker threads
- Progress reporting
- Error handling và graceful degradation

---

### 5. Scanner Engines (`src/scanners/`)

#### [NEW] [src/scanners/base-scanner.ts](file:///d:/code/code-scan-security/src/scanners/base-scanner.ts)
- Abstract base class cho tất cả scanners
- Common interface: `scan(file, tree, context) → Finding[]`
- Rule loading và filtering

---

#### 5a. Security Scanner (`src/scanners/security/`)

#### [NEW] [src/scanners/security/index.ts](file:///d:/code/code-scan-security/src/scanners/security/index.ts)
- Security scanner orchestrator
- Aggregates results từ các sub-analyzers

#### [NEW] [src/scanners/security/analyzers/injection.ts](file:///d:/code/code-scan-security/src/scanners/security/analyzers/injection.ts)
- SQL Injection detection (parameterized queries check)
- Command Injection (exec, spawn patterns)
- LDAP, XPath, NoSQL injection
- Template injection (SSTI)

#### [NEW] [src/scanners/security/analyzers/xss.ts](file:///d:/code/code-scan-security/src/scanners/security/analyzers/xss.ts)
- Cross-Site Scripting detection
- DOM-based XSS patterns
- Reflected XSS qua taint tracking
- Missing output encoding

#### [NEW] [src/scanners/security/analyzers/secrets.ts](file:///d:/code/code-scan-security/src/scanners/security/analyzers/secrets.ts)
- Hardcoded passwords, API keys, tokens
- High-entropy string detection
- Known secret patterns (AWS keys, GitHub tokens, etc.)
- .env file scanning

#### [NEW] [src/scanners/security/analyzers/auth.ts](file:///d:/code/code-scan-security/src/scanners/security/analyzers/auth.ts)
- Weak authentication patterns
- Missing authorization checks
- Insecure session management
- JWT misconfigurations

#### [NEW] [src/scanners/security/analyzers/crypto.ts](file:///d:/code/code-scan-security/src/scanners/security/analyzers/crypto.ts)
- Weak algorithms (MD5, SHA1, DES)
- Insecure random number generation
- Hardcoded encryption keys
- Missing TLS/SSL verification

#### [NEW] [src/scanners/security/analyzers/file-ops.ts](file:///d:/code/code-scan-security/src/scanners/security/analyzers/file-ops.ts)
- Path traversal vulnerabilities
- Unsafe file uploads
- Directory listing exposure
- Temporary file issues

---

#### 5b. Quality Scanner (`src/scanners/quality/`)

#### [NEW] [src/scanners/quality/index.ts](file:///d:/code/code-scan-security/src/scanners/quality/index.ts)
- Quality scanner orchestrator

#### [NEW] [src/scanners/quality/analyzers/complexity.ts](file:///d:/code/code-scan-security/src/scanners/quality/analyzers/complexity.ts)
- Cyclomatic complexity calculation
- Cognitive complexity (SonarQube style)
- Nesting depth analysis
- Function length warnings

#### [NEW] [src/scanners/quality/analyzers/duplication.ts](file:///d:/code/code-scan-security/src/scanners/quality/analyzers/duplication.ts)
- Code duplication detection
- Token-based comparison
- Configurable minimum block size
- Cross-file duplication

#### [NEW] [src/scanners/quality/analyzers/code-smells.ts](file:///d:/code/code-scan-security/src/scanners/quality/analyzers/code-smells.ts)
- Long methods/functions
- Large classes/files
- Dead code detection
- Unused imports/variables
- Magic numbers

#### [NEW] [src/scanners/quality/analyzers/naming.ts](file:///d:/code/code-scan-security/src/scanners/quality/analyzers/naming.ts)
- Naming convention checks
- Language-specific conventions (camelCase, snake_case)
- Meaningless variable names

#### [NEW] [src/scanners/quality/analyzers/metrics.ts](file:///d:/code/code-scan-security/src/scanners/quality/analyzers/metrics.ts)
- Lines of code (LOC/SLOC)
- Comment ratio
- Test coverage estimation
- Maintainability index

---

#### 5c. CVE/SCA Scanner (`src/scanners/cve/`)

#### [NEW] [src/scanners/cve/index.ts](file:///d:/code/code-scan-security/src/scanners/cve/index.ts)
- Software Composition Analysis orchestrator

#### [NEW] [src/scanners/cve/parsers/package-parser.ts](file:///d:/code/code-scan-security/src/scanners/cve/parsers/package-parser.ts)
- Parse dependency manifests:
  - `package.json` + `package-lock.json` (npm/yarn)
  - `requirements.txt` + `Pipfile.lock` (Python)
  - `pom.xml` + `build.gradle` (Java)
  - `go.mod` + `go.sum` (Go)
  - `Cargo.toml` + `Cargo.lock` (Rust)
  - `Gemfile.lock` (Ruby)
  - `composer.lock` (PHP)

#### [NEW] [src/scanners/cve/vulnerability-db.ts](file:///d:/code/code-scan-security/src/scanners/cve/vulnerability-db.ts)
- Fetch và cache CVE data từ OSV (Google) + NVD
- Local SQLite database cho offline scanning
- Periodic update mechanism
- Version range matching

#### [NEW] [src/scanners/cve/license-checker.ts](file:///d:/code/code-scan-security/src/scanners/cve/license-checker.ts)
- Detect dependency licenses
- License compatibility checking
- Policy enforcement (block certain licenses)

---

### 6. Rule System (`src/rules/`)

#### [NEW] [src/rules/rule-engine.ts](file:///d:/code/code-scan-security/src/rules/rule-engine.ts)
- Rule loading, validation, và execution
- Priority-based rule ordering
- Category filtering
- Custom rule plugin system

#### [NEW] [src/rules/rule-schema.ts](file:///d:/code/code-scan-security/src/rules/rule-schema.ts)
- Zod schema cho rule YAML format validation

```yaml
# Ví dụ Custom Rule Format (.deepscan-rules/my-rule.yml)
rules:
  - id: custom/no-eval
    name: "Prohibit eval() usage"
    description: "eval() is dangerous and should never be used in production code"
    category: security
    subcategory: injection
    severity: error
    confidence: high
    cwe: CWE-95
    languages: [javascript, typescript, python]
    
    # Tree-sitter pattern matching
    patterns:
      - pattern: "eval($CODE)"
        message: "eval() với input không tin cậy có thể dẫn tới Code Injection"
      - pattern: "new Function($CODE)"
        message: "new Function() tương đương eval()"
    
    # Semantic conditions (optional)
    conditions:
      - type: taint-check
        source: "user_input"
        sink: "$CODE"
      - type: context-check
        not-in: ["test", "development"]
    
    # Fix suggestion
    fix:
      description: "Sử dụng JSON.parse() hoặc parser an toàn thay vì eval()"
      replacement: "JSON.parse($CODE)"
    
    # Metadata
    tags: [owasp-top-10, injection, a03]
    references:
      - https://owasp.org/Top10/A03_2021-Injection/
      - https://cwe.mitre.org/data/definitions/95.html
```

#### [NEW] [src/rules/built-in/](file:///d:/code/code-scan-security/src/rules/built-in/)
- `security/` - 50+ built-in security rules
- `quality/` - 30+ built-in quality rules
- Organized by category (injection, xss, secrets, complexity, etc.)

#### [NEW] [src/rules/custom-loader.ts](file:///d:/code/code-scan-security/src/rules/custom-loader.ts)
- Load custom rules từ local files hoặc remote URLs
- Support YAML rules (declarative) và JS/TS rules (programmatic)
- Rule inheritance và override

---

### 7. Output / Reporter (`src/reporters/`)

#### [NEW] [src/reporters/base-reporter.ts](file:///d:/code/code-scan-security/src/reporters/base-reporter.ts)
- Abstract base class cho reporters
- Common finding format

#### [NEW] [src/reporters/json-reporter.ts](file:///d:/code/code-scan-security/src/reporters/json-reporter.ts)
- JSON output với full metadata
- Pretty-print option
- Streaming output cho large results

#### [NEW] [src/reporters/csv-reporter.ts](file:///d:/code/code-scan-security/src/reporters/csv-reporter.ts)
- CSV output cho Excel/spreadsheet analysis
- Configurable columns
- Proper escaping

#### [NEW] [src/reporters/html-reporter.ts](file:///d:/code/code-scan-security/src/reporters/html-reporter.ts)
- Beautiful, interactive HTML report
- Dashboard với charts (severity distribution, top issues)
- Filterable findings table
- Code snippet highlighting
- Export to PDF option
- Self-contained single HTML file (no external deps)

#### [NEW] [src/reporters/sarif-reporter.ts](file:///d:/code/code-scan-security/src/reporters/sarif-reporter.ts)
- SARIF 2.1.0 compliant output
- GitHub Code Scanning compatible
- CWE và OWASP taxonomy references

#### [NEW] [src/reporters/console-reporter.ts](file:///d:/code/code-scan-security/src/reporters/console-reporter.ts)
- Terminal-friendly colored output
- Summary statistics
- Progress indicators
- Verbose/quiet modes

---

### 8. Language Support (`src/languages/`)

#### [NEW] [src/languages/registry.ts](file:///d:/code/code-scan-security/src/languages/registry.ts)
- Language registry và auto-detection
- Extension → language mapping
- Grammar lazy-loading

#### [NEW] [src/languages/configs/](file:///d:/code/code-scan-security/src/languages/configs/)
Mỗi ngôn ngữ có 1 config file chứa:
- Tree-sitter grammar package name
- Language-specific taint sources/sinks
- Naming conventions
- Common frameworks patterns
- File extensions

Ngôn ngữ hỗ trợ ban đầu:
- `javascript.ts`, `typescript.ts`
- `python.ts`
- `java.ts`
- `go.ts`
- `c-cpp.ts`
- `csharp.ts`
- `php.ts`
- `ruby.ts`
- `rust.ts`
- `kotlin.ts`
- `swift.ts`

---

### 9. Types & Interfaces (`src/types/`)

#### [NEW] [src/types/finding.ts](file:///d:/code/code-scan-security/src/types/finding.ts)
```typescript
interface Finding {
  id: string;                     // Unique finding ID
  ruleId: string;                 // Rule that triggered this finding
  scanner: 'security' | 'quality' | 'cve';
  severity: 'critical' | 'error' | 'warning' | 'info';
  confidence: 'high' | 'medium' | 'low';
  category: string;               // injection, xss, complexity, etc.
  title: string;
  message: string;
  location: {
    file: string;
    startLine: number;
    startColumn: number;
    endLine: number;
    endColumn: number;
    snippet: string;              // Code context
  };
  context?: CodeContext;           // Business logic context
  taintFlow?: TaintFlowStep[];    // Data flow trace
  cwe?: string[];                  // CWE references
  owasp?: string[];                // OWASP Top 10 references
  fix?: {
    description: string;
    suggestion?: string;           // Code replacement
    references: string[];
  };
  aiValidation?: {
    isValid: boolean;
    explanation: string;
    confidence: number;
    fixSuggestion?: string;
  };
  metadata: {
    fingerprint: string;           // Cho dedup across scans
    firstSeen?: string;
    tags: string[];
  };
}
```

---

### 10. Project Structure tổng thể

```
d:/code/code-scan-security/
├── bin/
│   └── deepscan.ts                 # CLI entry point
├── src/
│   ├── cli/
│   │   ├── index.ts                # CLI setup
│   │   └── commands/
│   │       ├── scan.ts
│   │       ├── init.ts
│   │       ├── rules.ts
│   │       └── report.ts
│   ├── config/
│   │   ├── schema.ts
│   │   ├── loader.ts
│   │   └── defaults.ts
│   ├── core/
│   │   ├── parser.ts               # Tree-sitter parser
│   │   ├── ast-utils.ts
│   │   ├── taint-tracker.ts        # Cross-file taint analysis
│   │   ├── context-analyzer.ts     # Context-aware scanning
│   │   ├── semantic-engine.ts      # Semantic pattern matching
│   │   ├── ai-validator.ts         # AI-assisted validation
│   │   ├── file-discovery.ts
│   │   └── pipeline.ts             # Orchestrator
│   ├── scanners/
│   │   ├── base-scanner.ts
│   │   ├── security/
│   │   │   ├── index.ts
│   │   │   └── analyzers/
│   │   │       ├── injection.ts
│   │   │       ├── xss.ts
│   │   │       ├── secrets.ts
│   │   │       ├── auth.ts
│   │   │       ├── crypto.ts
│   │   │       └── file-ops.ts
│   │   ├── quality/
│   │   │   ├── index.ts
│   │   │   └── analyzers/
│   │   │       ├── complexity.ts
│   │   │       ├── duplication.ts
│   │   │       ├── code-smells.ts
│   │   │       ├── naming.ts
│   │   │       └── metrics.ts
│   │   └── cve/
│   │       ├── index.ts
│   │       ├── parsers/
│   │       │   └── package-parser.ts
│   │       ├── vulnerability-db.ts
│   │       └── license-checker.ts
│   ├── rules/
│   │   ├── rule-engine.ts
│   │   ├── rule-schema.ts
│   │   ├── custom-loader.ts
│   │   └── built-in/
│   │       ├── security/
│   │       │   ├── injection.yml
│   │       │   ├── xss.yml
│   │       │   ├── secrets.yml
│   │       │   ├── auth.yml
│   │       │   ├── crypto.yml
│   │       │   └── file-ops.yml
│   │       └── quality/
│   │           ├── complexity.yml
│   │           ├── duplication.yml
│   │           ├── code-smells.yml
│   │           └── naming.yml
│   ├── reporters/
│   │   ├── base-reporter.ts
│   │   ├── json-reporter.ts
│   │   ├── csv-reporter.ts
│   │   ├── html-reporter.ts
│   │   ├── sarif-reporter.ts
│   │   ├── console-reporter.ts
│   │   └── templates/
│   │       └── html-report/        # HTML report template & assets
│   ├── languages/
│   │   ├── registry.ts
│   │   └── configs/
│   │       ├── javascript.ts
│   │       ├── python.ts
│   │       ├── java.ts
│   │       ├── go.ts
│   │       └── ...
│   └── types/
│       ├── finding.ts
│       ├── config.ts
│       ├── rule.ts
│       └── scanner.ts
├── rules/                          # External custom rules directory
│   └── examples/
│       ├── custom-api-security.yml
│       └── custom-naming.yml
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/                   # Test code samples
├── docs/
│   ├── getting-started.md
│   ├── configuration.md
│   ├── writing-rules.md
│   └── api-reference.md
├── .deepscan.yml                   # Self-scan configuration
├── package.json
├── tsconfig.json
├── tsup.config.ts
├── vitest.config.ts
├── LICENSE
└── README.md
```

---

## Verification Plan

### Automated Tests
```bash
# Unit tests cho từng module
npm run test

# Integration tests - scan test fixtures
npm run test:integration

# Scan chính project DeepScan (self-test)
npx deepscan scan ./src --format json

# Type checking
npm run typecheck

# Lint
npm run lint
```

### Manual Verification
1. **CLI Test**: Chạy `deepscan scan` trên các sample projects
2. **Output Test**: Verify JSON, CSV, HTML, SARIF outputs đều valid
3. **Rule Test**: Tạo custom rule và verify nó hoạt động
4. **Config Test**: Test various `.deepscan.yml` configurations
5. **Cross-language Test**: Scan projects đa ngôn ngữ
6. **Performance Test**: Scan large codebase (>10k files) đo thời gian

### Test Fixtures
- Tạo sample code với known vulnerabilities cho mỗi ngôn ngữ
- Verify detection rate (true positive, false positive, false negative)
- Benchmark với Semgrep và ESLint trên cùng test fixtures

---

## Phát triển theo phases

### Phase 1: Foundation (Tuần 1-2)
- Project setup, TypeScript config, CLI framework
- Config system, file discovery, Tree-sitter parser
- Base scanner, rule engine, console reporter
- 10 security rules cơ bản cho JavaScript

### Phase 2: Core Scanners (Tuần 3-4)  
- Security scanner với đầy đủ analyzers
- Quality scanner với complexity và code smells
- JSON, CSV, HTML reporters
- 50+ built-in rules cho 5 ngôn ngữ chính

### Phase 3: Advanced Features (Tuần 5-6)
- Taint tracker (cross-file)
- Context-aware analyzer
- Semantic pattern matching engine
- CVE/SCA scanner
- SARIF reporter

### Phase 4: AI & Polish (Tuần 7-8)
- AI validator integration
- Incremental scanning
- Performance optimization (worker threads)
- HTML report dashboard
- Documentation
- npm publish

---

## Sử dụng (Usage Preview)

```bash
# Install
npm install -g deepscan-cli

# Initialize config
deepscan init

# Basic scan
deepscan scan ./src

# Full scan với all options
deepscan scan ./src \
  --scanners security,quality,cve \
  --format html \
  --output report.html \
  --deep \
  --severity critical,error \
  --parallel 4

# Scan với AI validation
deepscan scan ./src --ai --ai-provider openai

# Custom rules
deepscan scan ./src --rules ./my-rules/

# Incremental scan (only changed files)
deepscan scan ./src --incremental

# List all rules
deepscan rules list --category security

# Convert report format
deepscan report convert scan-results.json --to csv --output results.csv
```

```yaml
# .deepscan.yml
version: "1.0"

scanners:
  security:
    enabled: true
    severity: [critical, error, warning]
  quality:
    enabled: true
    thresholds:
      maxComplexity: 15
      maxFileLength: 500
      maxFunctionLength: 50
  cve:
    enabled: true
    failOnSeverity: critical

rules:
  exclude:
    - quality/naming-convention
  custom:
    - ./my-rules/*.yml

paths:
  exclude:
    - node_modules/**
    - dist/**
    - "**/*.test.ts"

output:
  format: json
  file: deepscan-results.json
```
