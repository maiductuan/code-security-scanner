import { readFileSync } from 'fs';
import { resolve } from 'path';
import { ASTParser } from '../src/core/ast-parser.js';
import { analyzeTaintFlow } from '../src/core/taint-tracker.js';
import { getLanguageConfig } from '../src/languages/registry.js';

async function test() {
  const content = readFileSync(resolve(process.cwd(), 'tests/scratch-taint.js'), 'utf-8');
  const parser = new ASTParser();
  await parser.initialize();
  const tree = await parser.parse(content, 'javascript');
  console.log(tree.rootNode.toString());
  
  const results = analyzeTaintFlow(content, 'scratch-taint.js', 'javascript', tree);
  console.log(JSON.stringify(results, null, 2));
}

test().catch(console.error);
