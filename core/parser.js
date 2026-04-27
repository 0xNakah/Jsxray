'use strict';

const acorn = require('acorn');

let babel = null;
try { babel = require('@babel/parser'); } catch (_) {}

/**
 * Parse JS source into an AST.
 *
 * Strategy:
 *   1. acorn — try module then script (handles most bundled JS)
 *   2. @babel/parser — fallback for TypeScript, JSX, decorators, and
 *      heavily minified code that acorn cannot recover from
 *
 * Returns an AST node or null on total failure.
 */
function tryParse(code) {
  for (const sourceType of ['module', 'script']) {
    try {
      return acorn.parse(code, { ecmaVersion: 2022, sourceType });
    } catch (_) {}
  }

  if (babel) {
    try {
      return babel.parse(code, {
        sourceType: 'unambiguous',
        plugins: ['typescript', 'jsx', 'decorators-legacy'],
        errorRecovery: true,
      });
    } catch (_) {}
  }

  return null;
}

module.exports = { tryParse, hasBabel: () => babel !== null };
