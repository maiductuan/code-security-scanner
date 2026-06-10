#!/usr/bin/env node
import { createRequire } from 'node:module';
import { createCLI } from '../cli/index.js';

// Run the CLI
const cli = createCLI();
cli.parse(process.argv);
