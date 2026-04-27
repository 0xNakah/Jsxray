#!/usr/bin/env node
/**
 * ast_extract — JS Parameter Extraction Engine  v5.3
 *
 * Reads raw JS source from stdin, writes JSON to stdout:
 *   {
 *     params:    [{ value, confidence, source }],
 *     endpoints: string[],
 *     error:     string | null,
 *     meta:      { queryAliases, urlParamAliases, payloadAliases, babelFallback }
 *   }
 *
 * Usage:
 *   cat bundle.js | node core/index.js
 *
 * Dependencies:  acorn  acorn-walk
 * Optional:      @babel/parser   (TypeScript / JSX / error-recovery)
 */

'use strict';

const { extract } = require('./extract');

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data',  chunk => { input += chunk; });
process.stdin.on('end',   ()    => {
  process.stdout.write(JSON.stringify(extract(input), null, 2));
});
