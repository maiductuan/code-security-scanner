import fs from 'fs';

try {
  const content = fs.readFileSync('report.html', 'utf-8');
  const query = 'sanitize file paths. Use path.resolve()';
  const idx = content.indexOf(query);
  
  if (idx !== -1) {
    console.log('Found query at index:', idx);
    // Print 300 characters before and 300 characters after
    const start = Math.max(0, idx - 300);
    const end = Math.min(content.length, idx + 300);
    console.log('--- CONTEXT ---');
    console.log(content.substring(start, end));
    console.log('--- END CONTEXT ---');
  } else {
    console.log('Query not found in report.html');
  }
} catch (e) {
  console.error(e);
}
