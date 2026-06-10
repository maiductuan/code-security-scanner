export { ScanPipeline, generateFingerprint } from './pipeline.js';
export { discoverFiles, readFileContent } from './file-discovery.js';
export { analyzeContext, getContextAdjustments } from './context-analyzer.js';
export { analyzeTaintFlow } from './taint-tracker.js';
export { normalizeCode, calculateSemanticSimilarity, detectSemanticEquivalence } from './semantic-engine.js';
export { AIValidator } from './ai-validator.js';
