# DeepScan Administrator Guide

This guide is intended for administrators managing rule deployments, system-wide configurations, and automated ruleset updates for DeepScan.

---

## 📋 Rule Management

DeepScan uses a flexible, YAML-based rule architecture. Rules can be either **built-in** or **custom**.

### 1. Built-in Rules
Built-in rules are stored under the `rules/built-in/` directory, grouped by language (e.g. `semgrep-javascript.yml`, `semgrep-python.yml`).

#### Updating Built-in Rules
To update the built-in ruleset to the latest version of the official Semgrep rules repository:
1. Open a terminal in the root of the project source code.
2. Run the update command:
   ```bash
   npm run rules:update
   ```
This command automatically:
- Downloads the latest ZIP file of the Semgrep rules repository (`develop` branch).
- Unpacks it using OS-native tools (`Expand-Archive` on Windows, `unzip` on macOS/Linux).
- Automatically parses and filters the rules, mapping severities, CWEs, and OWASP categories.
- Groups and writes them to language-specific files (e.g. `rules/built-in/semgrep-typescript.yml`).
- Deduplicates rule IDs inside each language.
- Cleans up all temporary files.

> [!NOTE]
> Updating built-in rules requires a network connection to `github.com`.

---

## ⚙️ System Configuration

Administrators can enforce scan behavior using a global or project-specific `.deepscan.yml` file.

### Customizing Scanner Behavior
Place a `.deepscan.yml` file in the root of scanning targets. Below is a production configuration template:

```yaml
version: "1.0"

scanners:
  security:
    enabled: true
    severity: [critical, high, medium] # Ignore low-level rules in production
  quality:
    enabled: true
    thresholds:
      maxComplexity: 15
      maxFileLength: 500
  cve:
    enabled: true
    sources: [osv]
    failOnSeverity: high # Fail CI if CVE severity is high or higher

rules:
  # Enforce only security rules or exclude specific rules
  exclude:
    - quality/console-log
  # Point to custom admin rules directories
  custom:
    - /var/deepscan/custom-rules/*.yml

paths:
  exclude:
    - node_modules/**
    - dist/**
    - tests/**
```

---

## 🚀 Deployment & Rule Distribution

DeepScan resolves built-in rules relative to its execution directory:
- When package is globally installed via `npm install -g deepscan-cli`, built-in rules are stored inside the npm package's `rules/` folder.
- If you deploy deepscan across a server or CI runner:
  - Copy the `rules/` directory alongside the built files.
  - Or specify custom rule directories using the `--rules` flag or the `.deepscan.yml` config file.

---

## 💻 CLI Option Reference (Admin & CI/CD focus)

DeepScan CLI provides specific optimization flags to customize scans, select scanner subsets, and control exit behaviors. These are crucial for configuring automated jobs in CI/CD pipelines (GitHub Actions, GitLab CI, Jenkins).

### 1. Engine Subset Selection

By default, DeepScan executes **all** scanner engines (SAST Security, Code Quality, and CVE/SCA). If your pipeline only cares about a specific check, use the subset flags:

- `--security`: Run **only** the static application security testing (SAST) and secrets scan engines.
- `--quality`: Run **only** the code metrics, complexity, and duplicate code analyzer engines.
- `--cve`: Run **only** the dependency manifest parser and Google OSV vulnerability database search engines.

#### Combining Subsets
You can combine subsets by passing multiple flags or using the `-s` / `--scanners` option:
```bash
# Run security and CVE scans only (skip quality code smells)
deepscan scan ./src --security --cve

# Equivalent syntax using the --scanners option
deepscan scan ./src --scanners security,cve
```

> [!TIP]
> Executing only the required scanner subset reduces pipeline execution times, avoids database calls (for CVE), and keeps log outputs clean.

### 2. Exit Status and Pipeline Failures

For automation integration, controlling when the CLI exits with a non-zero code is essential:

- **Exit Code 1**: Returned when findings are found that match your severity thresholds.
- **Exit Code 0**: Returned when no findings are found, or when errors/findings do not meet threshold limits.

You can configure thresholds in `.deepscan.yml` under `failOnSeverity` (for CVE) or global CLI options:
```bash
# Fail only if critical or high level security bugs are found
deepscan scan ./src --severity critical,high
```

### 3. JIT Compilation vs Built Bundle Execution in CI

When running DeepScan in automated environments:
- **Production Execution (Recommended)**: Build the package first and invoke the compiled JS. This avoids the TS compilation overhead.
  ```bash
  npm run build
  node dist/bin/deepscan.js scan ./src --security
  ```
- **Development / JIT Execution**: If debugging or testing changes to custom rules/analyzers:
  ```bash
  # Note the double dash -- separator for passing arguments through npm
  npm run dev -- scan ./src --security
  ```
