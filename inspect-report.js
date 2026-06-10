import fs from 'fs';

try {
  const content = fs.readFileSync('report.html', 'utf-8');
  console.log('report.html read successfully. Length:', content.length);
  
  // Find the <script> block
  const scriptStart = content.indexOf('<script>');
  const scriptEnd = content.indexOf('</script>', scriptStart + 8);
  
  console.log('Script block start index:', scriptStart);
  console.log('Script block end index:', scriptEnd);
  
  if (scriptStart !== -1 && scriptEnd !== -1) {
    const scriptContent = content.substring(scriptStart, scriptEnd + 9);
    console.log('Script content length:', scriptContent.length);
    
    // Check if there are any other </script> tags inside this script block
    // (excluding the very end one)
    const innerContent = content.substring(scriptStart + 8, scriptEnd);
    
    // Search for case-insensitive </script
    const match = innerContent.match(/<\/script/gi);
    if (match) {
      console.log('Found matches of </script inside the script block:', match.length);
      // Let's print around the first match
      const matchIdx = innerContent.search(/<\/script/i);
      console.log('Match context:', innerContent.substring(Math.max(0, matchIdx - 100), Math.min(innerContent.length, matchIdx + 100)));
    } else {
      console.log('No matches of </script found inside the script block. The HTML parser did not break on </script>.');
    }
  }
} catch (e) {
  console.error(e);
}
