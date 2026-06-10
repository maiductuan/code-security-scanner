import { z } from 'zod';

/** Zod schema for validating DeepScan configuration files */

const SeveritySchema = z.enum(['critical', 'high', 'medium', 'low']);
const OutputFormatSchema = z.enum(['json', 'csv', 'html', 'sarif', 'console']);

const SecurityScannerSchema = z.object({
  enabled: z.boolean().default(true),
  severity: z.array(SeveritySchema).default(['critical', 'high', 'medium', 'low']),
}).default({});

const QualityThresholdsSchema = z.object({
  maxComplexity: z.number().min(1).default(15),
  maxCognitiveComplexity: z.number().min(1).default(20),
  maxFileLength: z.number().min(10).default(500),
  maxFunctionLength: z.number().min(5).default(50),
  maxNestingDepth: z.number().min(1).default(4),
  minCommentRatio: z.number().min(0).max(1).default(0.1),
}).default({});

const QualityScannerSchema = z.object({
  enabled: z.boolean().default(true),
  thresholds: QualityThresholdsSchema,
}).default({});

const CVEScannerSchema = z.object({
  enabled: z.boolean().default(true),
  sources: z.array(z.string()).default(['osv']),
  failOnSeverity: SeveritySchema.optional(),
}).default({});

const ScannersSchema = z.object({
  security: SecurityScannerSchema,
  quality: QualityScannerSchema,
  cve: CVEScannerSchema,
}).default({});

const RulesSchema = z.object({
  include: z.array(z.string()).default(['*']),
  exclude: z.array(z.string()).default([]),
  custom: z.array(z.string()).default([]),
}).default({});

const PathsSchema = z.object({
  include: z.array(z.string()).default(['**/*']),
  exclude: z.array(z.string()).default([
    'node_modules/**', 'dist/**', 'build/**', '.git/**',
  ]),
}).default({});

const OutputSchema = z.object({
  format: OutputFormatSchema.default('console'),
  file: z.string().optional(),
  verbose: z.boolean().default(false),
  colors: z.boolean().default(true),
}).default({});

const AISchema = z.object({
  enabled: z.boolean().default(false),
  provider: z.enum(['openai', 'anthropic', 'ollama']).default('openai'),
  model: z.string().optional(),
  apiKey: z.string().optional(),
  baseUrl: z.string().optional(),
  maxFindings: z.number().min(1).default(20),
  temperature: z.number().min(0).max(2).default(0.1),
}).default({});

const ContextSchema = z.object({
  projectType: z.enum(['web', 'api', 'library', 'mobile', 'cli', 'auto']).default('auto'),
  frameworks: z.array(z.string()).default([]),
  sensitivePatterns: z.array(z.string()).default([]),
}).default({});

/** Main configuration schema */
export const DeepScanConfigSchema = z.object({
  version: z.string().default('1.0'),
  scanners: ScannersSchema,
  rules: RulesSchema,
  languages: z.array(z.string()).default(['auto']),
  paths: PathsSchema,
  output: OutputSchema,
  ai: AISchema,
  context: ContextSchema,
  parallel: z.number().min(1).max(32).default(4),
  incremental: z.boolean().default(false),
  deep: z.boolean().default(false),
});

/** Rule YAML schema validation */
const RulePatternSchema = z.object({
  pattern: z.string().optional(),
  message: z.string().optional(),
  regex: z.string().optional(),
  regexFlags: z.string().optional(),
}).refine(data => data.pattern || data.regex, {
  message: 'Either pattern or regex must be provided',
});

const RuleConditionSchema = z.object({
  type: z.enum(['taint-check', 'context-check', 'scope-check', 'ast-check']),
  source: z.string().optional(),
  sink: z.string().optional(),
  in: z.array(z.string()).optional(),
  notIn: z.array(z.string()).optional(),
  scope: z.string().optional(),
});

const RuleFixSchema = z.object({
  description: z.string(),
  replacement: z.string().optional(),
});

export const RuleSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  description: z.string(),
  category: z.string(),
  subcategory: z.string().optional(),
  severity: SeveritySchema,
  confidence: z.enum(['high', 'medium', 'low']),
  cwe: z.array(z.string()).optional(),
  owasp: z.array(z.string()).optional(),
  languages: z.array(z.string()),
  patterns: z.array(RulePatternSchema),
  conditions: z.array(RuleConditionSchema).optional(),
  fix: RuleFixSchema.optional(),
  tags: z.array(z.string()).optional(),
  references: z.array(z.string()).optional(),
  enabled: z.boolean().default(true),
});

export const RuleFileSchema = z.object({
  rules: z.array(RuleSchema),
});

export type ValidatedConfig = z.infer<typeof DeepScanConfigSchema>;
export type ValidatedRule = z.infer<typeof RuleSchema>;
