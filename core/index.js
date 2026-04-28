#!/usr/bin/env node
/**
 * ast_extract — JS Parameter Extraction Engine  v5.3
 *
 * Reads raw JS source from stdin, writes JSON to stdout:
 *
 *     params:    [{ value, source }],
 *     endpoints: [string, …],
 *     error:     null | 'parse_failed',
 *     meta:      { queryAliases, urlParamAliases, payloadAliases, babelFallback }
 */

const { extract } = require('./extract');

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => { input += chunk; });
process.stdin.on('end', () => {
  const result = extract(input);
  process.stdout.write(JSON.stringify(result));
});
