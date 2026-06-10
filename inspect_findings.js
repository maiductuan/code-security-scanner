import fs from 'fs';

const filePath = 'd:/code/code-scan-security/report.html';
const content = fs.readFileSync(filePath, 'utf8');

const startMarker = 'const FINDINGS = ';
const startIndex = content.indexOf(startMarker);
if (startIndex === -1) {
  console.log('FINDINGS not found');
} else {
  const jsonStart = startIndex + startMarker.length;
  const summaryMarker = 'const SUMMARY = ';
  const summaryIndex = content.indexOf(summaryMarker);
  
  if (summaryIndex === -1) {
    console.log('SUMMARY not found');
  } else {
    const jsonText = content.substring(jsonStart, summaryIndex).trim().replace(/;$/, '');
    try {
      const findings = JSON.parse(jsonText);
      console.log(`--- Total findings: ${findings.length} ---`);
      findings.forEach((f, index) => {
        console.log(`\nFinding ${index + 1}:`);
        console.log(` - ID: ${f.id}`);
        console.log(` - File: ${f.file}:${f.line}`);
        console.log(` - Severity: ${f.severity}`);
        console.log(` - Category: ${f.category}`);
        console.log(` - Rule: ${f.ruleId} (${f.title})`);
        console.log(` - Message: ${f.message}`);
        console.log(` - Snippet:`);
        console.log(f.snippet);
      });
    } catch (e) {
      console.error('Failed to parse JSON:', e);
    }
  }
}
