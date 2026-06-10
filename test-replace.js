import { HtmlReporter } from './src/reporters/html-reporter.js';
import fs from 'fs';

// Mock a scan result containing </script> in a snippet
const mockResult = {
  version: '1.0.0',
  tool: { name: 'DeepScan', version: '1.0.0' },
  target: 'D:/test',
  config: '1.0',
  summary: {
    totalFindings: 1,
    bySeverity: { critical: 0, high: 1, medium: 0, low: 0 },
    byScanner: { security: 1, quality: 0, cve: 0 },
    byCategory: { security: 1 },
    filesScanned: 1,
    filesWithFindings: 1,
    scanDuration: 100,
    timestamp: new Date().toISOString()
  },
  findings: [
    {
      id: 'test-1',
      ruleId: 'test-rule',
      scanner: 'security',
      severity: 'high',
      confidence: 'high',
      category: 'security',
      title: 'Test XSS',
      message: 'Some XSS with script tag',
      location: {
        file: 'D:/test/index.html',
        startLine: 10,
        startColumn: 1,
        endLine: 10,
        endColumn: 20,
        snippet: '<script>alert(1)</script>'
      },
      metadata: {
        fingerprint: 'hash123',
        tags: []
      }
    }
  ]
};

const reporter = new HtmlReporter();
reporter.generate(mockResult).then(html => {
  console.log('HTML generated. Length:', html.length);
  const containsScript = html.includes('</script>');
  console.log('Contains literal </script>:', containsScript);
  
  // Find where FINDINGS is defined
  const lines = html.split('\n');
  const findingsLine = lines.find(l => l.includes('const FINDINGS ='));
  console.log('FINDINGS line:', findingsLine);
}).catch(err => {
  console.error(err);
});
